"""Claude AI engine — uses the local Claude CLI (Claude Code subscription) instead of the paid API.

The CLI is invoked in one-shot "print" mode (``claude -p``) with the prompt piped via stdin.
This way the existing Claude Code subscription handles auth/billing and no ANTHROPIC_API_KEY
is required.
"""

from __future__ import annotations

import os
import json
import shutil
import subprocess
from typing import Any


# Cached path to the resolved `claude` executable so we don't re-run shutil.which on every call.
_CLAUDE_BIN: str | None = None


def _get_claude_bin() -> str:
    """Locate the Claude Code CLI executable.

    Resolution order:
      1. ``CLAUDE_CLI_PATH`` environment variable (explicit override).
      2. ``claude`` on PATH (handles claude / claude.cmd / claude.exe via PATHEXT).
    """
    global _CLAUDE_BIN
    if _CLAUDE_BIN is not None:
        return _CLAUDE_BIN

    override = os.environ.get("CLAUDE_CLI_PATH")
    if override:
        if not os.path.exists(override):
            raise RuntimeError(
                f"CLAUDE_CLI_PATH is set to '{override}' but that file does not exist."
            )
        _CLAUDE_BIN = override
        return _CLAUDE_BIN

    found = shutil.which("claude")
    if not found:
        raise RuntimeError(
            "Claude CLI not found on PATH.\n"
            "Install Claude Code from https://docs.claude.com/en/docs/claude-code and make "
            "sure `claude` is on your PATH, or set the CLAUDE_CLI_PATH environment variable "
            "to the full path of the executable."
        )
    _CLAUDE_BIN = found
    return _CLAUDE_BIN


def _chat(system: str, user: str, model: str, max_tokens: int) -> str:
    """Send a prompt to Claude via the local CLI and return the text response.

    ``max_tokens`` is accepted for signature compatibility but is not enforced by the CLI;
    the underlying subscription model decides response length.
    """
    claude_bin = _get_claude_bin()

    # Combine system + user into a single stdin payload. We pipe via stdin to dodge
    # Windows command-line length limits (~8 KB) — scanner output can easily exceed that.
    combined = f"{system}\n\n---\n\n{user}"

    cmd: list[str] = [claude_bin, "-p", "--output-format", "text"]
    if model:
        cmd.extend(["--model", model])

    try:
        proc = subprocess.run(
            cmd,
            input=combined,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Failed to launch Claude CLI ({claude_bin}): {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Claude CLI call timed out after 10 minutes.") from exc

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise RuntimeError(
            f"Claude CLI failed (exit {proc.returncode}).\n"
            f"Command: {' '.join(cmd)}\n"
            f"Stderr: {stderr or '<empty>'}"
        )

    output = (proc.stdout or "").strip()
    if not output:
        raise RuntimeError("Claude CLI returned an empty response.")
    return output


def _strip_json_fences(text: str) -> str:
    """Best-effort cleanup if the model wraps its JSON in ``` fences."""
    text = text.strip()
    if text.startswith("```"):
        # Drop the opening fence (and any language tag) plus the trailing fence.
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
    return text.strip()


def analyze_scanner_findings(scanner_name: str, raw_findings: dict, cfg: dict) -> dict:
    """Ask Claude to interpret raw scanner output and produce structured findings."""
    model = cfg.get("model", "claude-sonnet-4-6")
    max_tokens = cfg.get("max_tokens", 8096)

    system = (
        "You are an expert cybersecurity analyst performing a security audit of a Windows home computer. "
        "You receive raw data from a security scanner and must produce a structured JSON analysis. "
        "Be precise, factual, and focus on actionable security findings. "
        "Respond ONLY with valid JSON — no markdown fences, no explanation outside the JSON."
    )

    user = f"""Scanner: {scanner_name}
Raw data:
{json.dumps(raw_findings, indent=2, default=str)}

Produce a JSON object with this exact schema:
{{
  "summary": "<1-2 sentence overview of security posture for this area>",
  "score": <integer 0-100 where 100 is perfect security>,
  "findings": [
    {{
      "id": "<SCANNER_ABBREV-NNN>",
      "title": "<short title>",
      "severity": "<critical|high|medium|low|info>",
      "description": "<what the issue is and why it matters>",
      "recommendation": "<specific actionable fix>",
      "evidence": "<key data point from the raw scan>"
    }}
  ]
}}

Rules:
- Only report genuine security concerns. Skip purely informational items unless truly notable.
- severity=critical: immediate exploitation risk; high: significant risk; medium: moderate risk; low: minor hardening; info: no risk but notable.
- Keep descriptions concise (1-3 sentences each).
- Prefix finding IDs with the scanner abbreviation (e.g. NET-001, SYS-001).
"""

    text = _chat(system, user, model, max_tokens)
    return json.loads(_strip_json_fences(text))


def generate_executive_summary(all_analyses: list[dict], system_info: dict, cfg: dict) -> dict:
    """Generate a holistic executive summary across all scanner results."""
    model = cfg.get("model", "claude-sonnet-4-6")
    max_tokens = cfg.get("max_tokens", 8096)

    system = (
        "You are a senior cybersecurity consultant writing an executive security report for a home computer owner. "
        "Write in clear, jargon-free language. The owner is tech-literate but not a security expert. "
        "Respond ONLY with valid JSON."
    )

    combined = {a["scanner"]: a.get("analysis", {}) for a in all_analyses}
    scores = [a.get("analysis", {}).get("score", 50) for a in all_analyses if "analysis" in a]
    overall = round(sum(scores) / len(scores)) if scores else 0

    user = f"""System: {json.dumps(system_info, indent=2, default=str)}

Per-scanner analyses:
{json.dumps(combined, indent=2, default=str)}

Overall computed score: {overall}/100

Produce a JSON object:
{{
  "overall_score": {overall},
  "grade": "<A|B|C|D|F>",
  "headline": "<one sentence overall verdict>",
  "top_risks": ["<risk 1>", "<risk 2>", "<risk 3>"],
  "quick_wins": ["<easy fix 1>", "<easy fix 2>", "<easy fix 3>"],
  "summary_paragraphs": ["<paragraph 1>", "<paragraph 2>"],
  "priority_actions": [
    {{"action": "<what to do>", "effort": "<low|medium|high>", "impact": "<low|medium|high>"}}
  ]
}}
"""

    text = _chat(system, user, model, max_tokens)
    return json.loads(_strip_json_fences(text))


def analyze_all(scan_results: dict, system_info: dict, cfg: dict) -> tuple[dict, dict]:
    """Run per-scanner analysis AND executive summary in a single CLI call.

    Returns (analyses, executive). When a scanner output contains a
    ``kev_findings`` array (produced by the cve-matcher-backed KEV engine),
    the prompt tells the model to treat that as authoritative and ignore
    the legacy ``cve_matches`` view for the same scanner.
    """
    model = cfg.get("model", "claude-sonnet-4-6")
    max_tokens = cfg.get("max_tokens", 8096)

    ok_scanners: dict = {}
    failed_scanners: list[str] = []
    for name, raw in scan_results.items():
        if isinstance(raw, dict) and raw.get("status") == "error":
            failed_scanners.append(name)
        else:
            ok_scanners[name] = raw

    scanner_keys = list(ok_scanners.keys())
    has_kev_findings = isinstance(ok_scanners.get("software"), dict) and \
                       "kev_findings" in ok_scanners["software"]

    system_prompt = (
        "You are an expert cybersecurity analyst auditing a Windows home computer. "
        "You will receive raw output from several scanners at once and must produce, "
        "in a single JSON object, both (a) a per-scanner analysis for each scanner "
        "and (b) a holistic executive summary across all of them. "
        "Be precise, factual, and focus on actionable security findings. "
        "Respond ONLY with valid JSON. No markdown fences, no commentary outside the JSON."
    )

    schema_block = (
        '{\n'
        '  "analyses": {\n'
        '    "<scanner_name>": {\n'
        '      "summary": "<1-2 sentence overview of security posture for this area>",\n'
        '      "score": <integer 0-100 where 100 is perfect security>,\n'
        '      "findings": [\n'
        '        {\n'
        '          "id": "<SCANNER_ABBREV-NNN>",\n'
        '          "title": "<short title>",\n'
        '          "severity": "<critical|high|medium|low|info>",\n'
        '          "description": "<what the issue is and why it matters>",\n'
        '          "recommendation": "<specific actionable fix>",\n'
        '          "evidence": "<key data point from the raw scan>"\n'
        '        }\n'
        '      ]\n'
        '    }\n'
        '  },\n'
        '  "executive": {\n'
        '    "overall_score": <integer 0-100>,\n'
        '    "grade": "<A|B|C|D|F>",\n'
        '    "headline": "<one sentence overall verdict>",\n'
        '    "top_risks": ["<risk 1>", "<risk 2>", "<risk 3>"],\n'
        '    "quick_wins": ["<easy fix 1>", "<easy fix 2>", "<easy fix 3>"],\n'
        '    "summary_paragraphs": ["<paragraph 1>", "<paragraph 2>"],\n'
        '    "priority_actions": [\n'
        '      {"action": "<what to do>", "effort": "<low|medium|high>", "impact": "<low|medium|high>"}\n'
        '    ]\n'
        '  }\n'
        '}'
    )

    rules = [
        f"- The \"analyses\" object MUST contain exactly these keys: {json.dumps(scanner_keys)}",
        "- Only report genuine security concerns. Skip purely informational items unless truly notable.",
        "- severity=critical: immediate exploitation risk; high: significant risk; medium: moderate risk; low: minor hardening; info: no risk but notable.",
        "- Keep descriptions concise (1-3 sentences each).",
        "- Prefix finding IDs with the scanner abbreviation (e.g. NET-001, SYS-001, USR-001).",
        "- The executive summary should be written for a tech-literate but non-expert home computer owner.",
    ]

    if has_kev_findings:
        rules.extend([
            "",
            "Software scanner extra guidance (the 'software' output includes a 'kev_findings' array):",
            "- 'kev_findings' is the AUTHORITATIVE pre-classified view (KEV catalog cross-referenced with NVD CPE version ranges). Use it INSTEAD of 'cve_matches' for that scanner; 'cve_matches' is a legacy compatibility view and overlaps with kev_findings.",
            "- For each kev_findings entry:",
            "    verdict == 'vulnerable' -> create a finding. severity = critical if ransomware_linked else high.",
            "    verdict == 'unknown'    -> create a finding only if notable. severity = medium.",
            "    verdict == 'patched'    -> do NOT create a finding (user's version is outside the affected range).",
            "- In 'description', cite cve_id, kev_name, and whether ransomware_linked.",
            "- In 'recommendation', reference verdict_detail's range and tell the user the minimum version to upgrade to (the upper bound of the affected range).",
            "- If kev_summary is present, surface ransomware_vulnerable_count in the software scanner summary.",
        ])

    user_prompt = (
        f"System info:\n{json.dumps(system_info, indent=2, default=str)}\n\n"
        f"Scanners that failed and should be skipped: {json.dumps(failed_scanners)}\n\n"
        f"Raw scanner outputs (analyze every key in this object):\n"
        f"{json.dumps(ok_scanners, indent=2, default=str)}\n\n"
        f"Produce a single JSON object with this exact top-level schema:\n{schema_block}\n\n"
        f"Rules:\n" + "\n".join(rules) + "\n"
    )

    text = _chat(system_prompt, user_prompt, model, max_tokens)
    payload = json.loads(_strip_json_fences(text))

    analyses: dict = payload.get("analyses", {}) or {}
    executive: dict = payload.get("executive", {}) or {}

    # Defensive override: keep overall_score internally consistent.
    scores = [a.get("score", 50) for a in analyses.values() if isinstance(a, dict)]
    if scores:
        executive["overall_score"] = round(sum(scores) / len(scores))

    return analyses, executive
