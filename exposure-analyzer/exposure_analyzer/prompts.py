"""Claude prompts for the exposure-analyzer.

`SYSTEM_PROMPT` frames Claude's role as a gray-box impact analyst.
`build_verdict_prompt()` (STUB) constructs a per-candidate user turn from
the CVE metadata + host state + optional probe output.

Chunk D drafts the real templates. This scaffold holds the shape and
docstrings so callers can wire the interface in advance.

The prompt design is informed by PentestGPT (Deng et al., 2023) — see
`../docs/DESIGN.md` §3 for the citation.
"""

from __future__ import annotations

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
"""


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
        probe_output:   captured stdout of the probe (empty if none).

    Returns:
        A prompt string ready to be sent as the user turn.

    Raises:
        NotImplementedError: chunk D fills this in.
    """
    raise NotImplementedError("build_verdict_prompt is implemented in chunk D")
