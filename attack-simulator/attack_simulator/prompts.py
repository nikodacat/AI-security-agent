"""Claude prompts for the attack-simulator.

`SYSTEM_PROMPT` frames Claude as an adversarial narrator writing an advisory
attack-path for a CONFIRMED CVE verdict. Prompt-adapter fidelity to
Deng et al. 2023 (PentestGPT) — three-stage decomposition (recon →
discovery → exploitation) — with an explicit prohibition on concrete
attacker-tool invocations, since v2's product surface is defender advisory,
not offensive tooling.

`build_narrative_prompt()` constructs the per-verdict user turn from the
analyzer's verdict record.

`scan_for_tool_invocations()` is a defense-in-depth post-generation check
that flags narratives which sneak in specific tool commands despite the
prompt. It does NOT rewrite the narrative — the operator sees both the
narrative and the warning.
"""

from __future__ import annotations

import json
import re
from typing import Any


SYSTEM_PROMPT = """\
You are an advisory adversarial narrator for a gray-box security-assessment
report. Given ONE CONFIRMED CVE verdict from a defender's vulnerability
scanner, describe the shape of a plausible attack against the target host —
what an external attacker would do at each stage — so that the defender
reading the report understands why the verdict matters and where the
attacker's leverage comes from.

You write for defenders, not attackers. Your narratives are read by the
operator triaging the scanner's output; they must be actionable ("this is
where the exposure lives, this is how it would be reached") without being
weaponizable ("here is the command to run").

Your output has THREE labeled sections, in this order:

  ### Recon
  What an external attacker on the same network segment would observe first:
  which ports/banners are exposed, what fingerprinting information the
  service leaks, what the attacker learns from a low-noise sweep. Reference
  the verdict's network_state or probe evidence when it is present.

  ### Discovery
  How the attacker narrows recon into the specific vulnerable component: the
  fingerprint step that pins down the vulnerable version, the configuration
  detail that unlocks the exploit path (missing auth, exposed endpoint,
  writable directory, permissive CORS, etc.). Ground this in the verdict's
  package_version / probe_output / evidence fields.

  ### Exploitation
  The class of attack the CVE enables and what the attacker's next move
  would be at the vulnerability-class level (e.g. "authentication bypass
  followed by arbitrary Lua execution in the Redis process context"). Name
  the attacker's OBJECTIVE and the CATEGORY of technique. Do NOT provide
  specific commands, payloads, exploit code, or tool invocations.

HARD PROHIBITIONS (do not violate — the narrative is rejected if you do):

  1. No specific attacker-tool invocations. Never write commands like
     `nmap -sV`, `sqlmap -u`, `msfconsole`, `use exploit/...`,
     `curl -X POST ... -d '<payload>'`, `hydra -l ...`, `metasploit`
     module names, `python -c "..."` exploit one-liners, `nc -e /bin/sh`,
     or any shell/PowerShell command intended to run against the target.
  2. No exploit code or payload strings. Never include shellcode,
     ROP chains, SQL-injection payloads, XSS payloads, JNDI lookup strings,
     format-string exploit fragments, path-traversal sequences with
     concrete filenames, or any string that would function as a live payload
     if copied verbatim.
  3. No CVE PoC URLs, exploit-DB IDs (`EDB-*`), Metasploit module paths,
     or references to public exploit code repositories.
  4. No step-by-step operational instructions (e.g. "1. run X, 2. run Y,
     3. then Z"). Narrate the ATTACKER's understanding at each stage, not a
     recipe.

If the verdict's evidence is thin or self-contradictory, say so in the
narrative rather than inventing detail. It is fine — and preferable — for a
narrative to say "the exact exploitation path depends on the caller's usage
of the vulnerable library" if that is what the evidence supports.

Style:
- ~150-250 words total across the three sections.
- Present tense, third-person ("the attacker ...").
- No preamble ("Here is a narrative:") and no closing summary.
- Return the three sections and nothing else.
"""


_MAX_EVIDENCE_LEN = 4000
_MAX_PROBE_OUTPUT_LEN = 2000


def build_narrative_prompt(verdict: dict[str, Any]) -> str:
    """Construct the per-verdict user turn.

    The prompt gives the model the whole CONFIRMED verdict as JSON, then
    asks for the three-section narrative. Long fields are truncated to
    keep the prompt within reasonable bounds — the model still gets more
    context than it needs for a good narrative.
    """
    cve_id = verdict.get("cve_id", "CVE-UNKNOWN")
    verdict_label = verdict.get("verdict", "CONFIRMED")
    reason = verdict.get("reason", "")
    evidence = verdict.get("evidence", {}) or {}
    probe_command = verdict.get("probe_command", "")
    probe_output = _truncate(verdict.get("probe_output", ""), _MAX_PROBE_OUTPUT_LEN)

    evidence_json = _render_json(evidence, limit=_MAX_EVIDENCE_LEN)

    parts: list[str] = []
    parts.append(f"CONFIRMED verdict for {cve_id}.")
    parts.append("")
    parts.append(f"Analyzer verdict: {verdict_label}")
    parts.append("")
    parts.append("Reason:")
    parts.append(reason.strip() or "(no reason recorded)")
    parts.append("")
    parts.append("Evidence:")
    parts.append(evidence_json)
    parts.append("")
    if probe_command:
        parts.append(f"Probe executed: `{probe_command}`")
        if probe_output:
            parts.append("Probe output:")
            parts.append("```")
            parts.append(probe_output)
            parts.append("```")
        parts.append("")
    parts.append(
        "Write the three-section attack narrative described in the system "
        "prompt, respecting all hard prohibitions. Return only the "
        "narrative — no preamble, no summary."
    )
    return "\n".join(parts)


# Case-insensitive regex patterns for the post-generation guardrail sweep.
# Each pattern targets a shape of attacker-tool invocation the SYSTEM_PROMPT
# forbids. Matches produce a WARNING appended to the narrative, not a
# rejection — the operator sees both the model's output and the flag.
_TOOL_INVOCATION_PATTERNS = [
    (re.compile(r"\bnmap\s+-[a-zA-Z]"), "nmap invocation"),
    (re.compile(r"\bsqlmap\b"), "sqlmap invocation"),
    (re.compile(r"\bmsfconsole\b|\buse\s+exploit/"), "metasploit invocation"),
    (re.compile(r"\bhydra\s+-[a-zA-Z]"), "hydra invocation"),
    (re.compile(r"\bnc\s+-[a-zA-Z]*e\b"), "netcat reverse-shell (-e)"),
    (re.compile(r"\bcurl\s+-X\s+(POST|PUT|DELETE)\b", re.IGNORECASE), "curl payload command"),
    (re.compile(r"\bwget\s+http[s]?://[^\s]*(?:sh|exe|py)\b", re.IGNORECASE), "wget payload"),
    (re.compile(r"EDB-\d+"), "exploit-DB id"),
    (re.compile(r"\bexploit-db\.com\b", re.IGNORECASE), "exploit-db.com link"),
    (re.compile(r"\b/etc/passwd\b|\b/etc/shadow\b"), "sensitive file path"),
    (re.compile(r"\${jndi:", re.IGNORECASE), "JNDI lookup payload"),
    (re.compile(r"[A-Za-z]:\\\\Windows\\\\System32"), "Windows system path"),
]


def scan_for_tool_invocations(narrative: str) -> list[str]:
    """Return a list of guardrail-hit labels found in the narrative.

    Empty list = clean. Non-empty = the SYSTEM_PROMPT's prohibitions
    weren't fully followed and the operator should audit. Callers may
    append the labels as a footer to the narrative rather than dropping
    the narrative entirely — the analyzer verdict already justifies the
    finding; the narrative is context.
    """
    hits: list[str] = []
    seen: set[str] = set()
    for pattern, label in _TOOL_INVOCATION_PATTERNS:
        if pattern.search(narrative) and label not in seen:
            hits.append(label)
            seen.add(label)
    return hits


def _render_json(obj: Any, limit: int | None = None) -> str:
    text = json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    if limit is not None:
        text = _truncate(text, limit)
    return text


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, original length {len(text)} chars]"
