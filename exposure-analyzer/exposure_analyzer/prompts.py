"""Claude prompts for the exposure-analyzer.

`SYSTEM_PROMPT` frames Claude's role as a gray-box impact analyst.
`build_verdict_prompt()` constructs a per-candidate user turn from the CVE
metadata + host state + optional probe output.

The prompt design is informed by PentestGPT (Deng et al., 2023) -- see
`../docs/DESIGN.md` section 3 for the citation.
"""

from __future__ import annotations

import json
from typing import Any


SYSTEM_PROMPT = """\
You are a gray-box security-assessment advisor. For each CVE candidate the
operator gives you, decide whether it is currently exploitable on THIS host
given the evidence provided, and produce a structured verdict.

You have five verdict values available:
  CONFIRMED            - vulnerable version + service running + reachable + config does not mitigate
  MITIGATED_BY_CONFIG  - vulnerable version installed, but a config setting blocks the attack
  MITIGATED_BY_EXPOSURE - vulnerable version + running, but not reachable (loopback / firewalled)
  NOT_RUNNING          - vulnerable version installed but the service is stopped
  NO_EVIDENCE          - insufficient data to decide; recommend human review

Rules:
- Cite the specific evidence you used (config key names, port bindings, probe
  output substrings). Do not speculate beyond what the operator gave you.
- Never propose exploitation. You are a defender, not an attacker.
- If evidence is contradictory, return NO_EVIDENCE and describe the conflict.

Response format:
Return ONLY a single JSON object, no prose before or after, matching this shape:
{
  "verdict": "<one of the five values above>",
  "reason": "<one-paragraph explanation, <= 400 chars>",
  "evidence": {"<field>": "<value>", ...}
}
"""


# Cap host_state serialization so a huge scanner output can't blow the prompt.
_HOST_STATE_CHAR_LIMIT = 8000
# Cap probe_output too -- probes should be small but be defensive.
_PROBE_OUTPUT_CHAR_LIMIT = 4000


def build_verdict_prompt(
    candidate: dict[str, Any],
    host_state: dict[str, Any],
    probe_command: str = "",
    probe_output: str = "",
) -> str:
    """Construct the per-candidate user turn.

    Args:
        candidate:      one entry from cve-matcher's `kev_findings` array.
        host_state:     the full host-scanner output for the target.
        probe_command:  the command that was executed (empty if none).
        probe_output:   captured stdout/stderr of the probe (empty if none).

    Returns:
        A prompt string ready to be sent as the user turn.
    """
    parts: list[str] = []

    cve_id = candidate.get("cve_id", "CVE-UNKNOWN")
    parts.append(f"Candidate: {cve_id}")
    parts.append("")
    parts.append("CVE metadata:")
    parts.append(_render_json(_candidate_summary(candidate)))
    parts.append("")

    parts.append("Relevant host state (from host-scanner):")
    parts.append(_render_json(host_state, limit=_HOST_STATE_CHAR_LIMIT))
    parts.append("")

    if probe_command:
        parts.append(f"Probe executed: `{probe_command}`")
        if probe_output:
            truncated = _truncate(probe_output, _PROBE_OUTPUT_CHAR_LIMIT)
            parts.append("Probe output:")
            parts.append("```")
            parts.append(truncated)
            parts.append("```")
        else:
            parts.append("Probe output: (empty)")
        parts.append("")
    else:
        parts.append("Probe executed: (none)")
        parts.append("")

    parts.append(
        "Decide the verdict for this CVE on this host. Respond with the JSON "
        "object described in the system prompt."
    )
    return "\n".join(parts)


def _candidate_summary(candidate: dict[str, Any]) -> dict[str, Any]:
    """Pull the fields the analyzer actually reasons over."""
    keep = (
        "cve_id",
        "kev_name",
        "kev_vendor",
        "kev_product",
        "kev_description",
        "cwes",
        "package_name",
        "package_version",
        "verdict",
        "verdict_detail",
        "ransomware_linked",
    )
    return {k: candidate[k] for k in keep if k in candidate}


def _render_json(obj: Any, limit: int | None = None) -> str:
    text = json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    if limit is not None:
        text = _truncate(text, limit)
    return text


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, original length {len(text)} chars]"
