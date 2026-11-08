"""Verdict data model — shared by every other module.

A `Verdict` is what the analyzer produces per candidate CVE. It's the
canonical serialization unit that flows from `ExposureAgent.analyze()`
through `report.py` and into the final HTML report.

Kept dependency-free (stdlib only) so both cve-matcher's callers and
host-scanner's report generator can import it without pulling in the
full agent runtime.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class VerdictType(str, Enum):
    """The five verdict values the analyzer can emit per CVE candidate.

    Subclassing `str` lets these serialize cleanly as JSON strings without
    a custom encoder, and lets callers compare against literals directly.
    """

    CONFIRMED = "CONFIRMED"
    MITIGATED_BY_CONFIG = "MITIGATED_BY_CONFIG"
    MITIGATED_BY_EXPOSURE = "MITIGATED_BY_EXPOSURE"
    NOT_RUNNING = "NOT_RUNNING"
    NO_EVIDENCE = "NO_EVIDENCE"


@dataclass
class Verdict:
    """Per-candidate impact-analysis result.

    Fields:
      cve_id               : CVE identifier from the candidate.
      verdict              : one of `VerdictType`.
      reason               : one-paragraph human-readable explanation.
      evidence             : structured dict citing the specific facts used
                             (e.g. sshd_config keys, listening addresses, probe output).
      probe_command        : the command actually executed (or "" if none).
      probe_output         : captured stdout of the probe (or "" if none).
      timestamp            : ISO-8601 UTC timestamp of verdict generation.
      proposed_probe       : v2-7. When the analyzer has no KNOWN_PROBES entry
                             and an LLM proposer is wired up, this holds the
                             validated {binary, args, rationale, expected_signals}
                             dict the model proposed. The proposal is NOT executed
                             in v2-7 (execution + HITL is v2-8) — it's recorded
                             so a human reviewer can see what the analyzer wanted
                             to run. None when no proposal was made or one was made
                             but failed validation (see `probe_proposal_error`).
      probe_proposal_error : v2-7. Human-readable reason a proposal failed
                             validation or the proposer call itself errored. Empty
                             string when no proposal was attempted or the proposal
                             succeeded.
    """

    cve_id: str
    verdict: VerdictType
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)
    probe_command: str = ""
    probe_output: str = ""
    timestamp: str = ""
    proposed_probe: dict[str, Any] | None = None
    probe_proposal_error: str = ""
    # v3-5: where the candidate's package came from, copied from the candidate so
    # fix-publisher can tell apt-managed software from source-built / library
    # installs without asking the model. Empty on verdicts written before v3-5.
    package_name: str = ""
    package_version: str = ""
    installed_version: str = ""   # full apt version when known (banner candidates)
    package_source: str = ""
    candidate_source: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        # Coerce string verdict to enum for consistent downstream comparison.
        if isinstance(self.verdict, str):
            self.verdict = VerdictType(self.verdict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Verdict":
        """Construct from a JSON-loaded dict (round-trip inverse of `to_dict`)."""
        return cls(
            cve_id=d["cve_id"],
            verdict=VerdictType(d["verdict"]),
            reason=d["reason"],
            evidence=d.get("evidence", {}),
            probe_command=d.get("probe_command", ""),
            probe_output=d.get("probe_output", ""),
            timestamp=d.get("timestamp", ""),
            proposed_probe=d.get("proposed_probe"),
            probe_proposal_error=d.get("probe_proposal_error", ""),
            package_name=d.get("package_name", ""),
            package_version=d.get("package_version", ""),
            installed_version=d.get("installed_version", ""),
            package_source=d.get("package_source", ""),
            candidate_source=d.get("candidate_source", ""),
        )


def dump_verdicts(verdicts: list[Verdict], path: Path) -> None:
    """Write a list of verdicts to a JSON file."""
    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "verdicts": [v.to_dict() for v in verdicts],
    }
    Path(path).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def load_verdicts(path: Path) -> list[Verdict]:
    """Load a list of verdicts from a JSON file previously written by `dump_verdicts`."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return [Verdict.from_dict(v) for v in raw.get("verdicts", [])]
