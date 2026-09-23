"""Human-in-the-loop gate for LLM-proposed probes + learned_probes.jsonl.

v2-8. When a proposal from proposal.py comes back valid, we ask the
operator whether to run it. Approved probes are executed AND appended to
a git-tracked append-only JSONL sidecar keyed by sha256 of the argv, so
future runs (or a later --auto-approve-known) can skip the prompt for
the same argv.

**Trust boundary:** proposal.parse_proposal() is the security floor —
shell wrappers, shell metacharacters, and illegal binaries are refused
BEFORE they reach this layer. The HITL is UX on top of that, not a
security gate. NEVER call any function here on a raw model response; it
must have been through parse_proposal() first.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from .proposal import ProposedProbe


# ---- Identity --------------------------------------------------------------

_ARGV_DELIMITER = "\x00"  # null byte — validator forbids this char in args,
                          # so no collision between ["foo","bar"] and ["foobar"].


def argv_hash(binary: str, args: tuple[str, ...] | list[str]) -> str:
    """Deterministic SHA-256 of (binary, args) tuple. Returns 'sha256:<hex>'.

    Uses null-byte delimiter (which parse_proposal already forbids in
    binary/args) so ["foo","bar"] and ["foobar"] hash differently.
    """
    payload = binary + _ARGV_DELIMITER + _ARGV_DELIMITER.join(args)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


# ---- JSONL persistence -----------------------------------------------------

# Default path is package-local so v2-8 owns its own sidecar. Override with
# --learned-probes-path on the CLI.
DEFAULT_LEARNED_PROBES_PATH = Path("exposure-analyzer") / "learned_probes.jsonl"


@dataclass(frozen=True)
class LearnedProbeRecord:
    """One row in learned_probes.jsonl.

    Field order matches the JSONL schema. Do NOT reorder or rename;
    downstream eval tooling may parse these.
    """
    argv_hash: str
    binary: str
    args: tuple[str, ...]
    rationale: str
    expected_signals: tuple[str, ...]
    first_seen_cve: str
    approved_at: str
    approved_by: str  # "operator" for interactive; "auto-approve-all-unsafe" for that flag

    def to_json_line(self) -> str:
        # One record per line; no trailing newline (caller adds "\n").
        # Sorted keys for stable diffs in git.
        d = {
            "argv_hash": self.argv_hash,
            "binary": self.binary,
            "args": list(self.args),
            "rationale": self.rationale,
            "expected_signals": list(self.expected_signals),
            "first_seen_cve": self.first_seen_cve,
            "approved_at": self.approved_at,
            "approved_by": self.approved_by,
        }
        return json.dumps(d, ensure_ascii=False, sort_keys=True)

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "LearnedProbeRecord":
        return cls(
            argv_hash=d["argv_hash"],
            binary=d["binary"],
            args=tuple(d.get("args", [])),
            rationale=d.get("rationale", ""),
            expected_signals=tuple(d.get("expected_signals", [])),
            first_seen_cve=d.get("first_seen_cve", ""),
            approved_at=d.get("approved_at", ""),
            approved_by=d.get("approved_by", ""),
        )


def load_learned_probes(path: Path) -> dict[str, LearnedProbeRecord]:
    """Load JSONL sidecar into dict keyed by argv_hash. Missing file → empty dict.

    Malformed lines are skipped with a warning to stderr — a corrupt row
    should not abort the whole run.
    """
    path = Path(path)
    if not path.exists():
        return {}
    out: dict[str, LearnedProbeRecord] = {}
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError as e:
            print(
                f"warning: learned_probes.jsonl line {i}: skipping malformed JSON ({e})",
                file=sys.stderr,
            )
            continue
        if not isinstance(d, dict) or "argv_hash" not in d:
            print(
                f"warning: learned_probes.jsonl line {i}: skipping row without argv_hash",
                file=sys.stderr,
            )
            continue
        rec = LearnedProbeRecord.from_json(d)
        out[rec.argv_hash] = rec
    return out


def append_learned_probe(path: Path, record: LearnedProbeRecord) -> None:
    """Append a single record to the JSONL file. Creates parent dirs as needed.

    Idempotency is the CALLER's responsibility — check argv_hash against
    load_learned_probes() first. This function always appends.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(record.to_json_line() + "\n")


# ---- Approval gate ---------------------------------------------------------

class Decision(str, Enum):
    """Result of asking the gate about one proposal.

    APPROVE     : execute this probe now
    DENY        : do not execute this probe; leave as v2-7 data
    SKIP_ALL    : deny this AND all subsequent proposals this run (operator
                  said "stop asking me" via 's'/'skip-all')
    """
    APPROVE = "APPROVE"
    DENY = "DENY"
    SKIP_ALL = "SKIP_ALL"


@dataclass
class ApprovalGate:
    """Combines auto-approve flags + HITL prompt into one decision.

    Instantiate once per analyzer run and reuse across candidates so
    'skip-all' state persists across the batch.

    Fields:
      learned         : output of load_learned_probes() — hashes that
                        auto-approve when --auto-approve-known is set.
      auto_approve_known    : --auto-approve-known flag.
      auto_approve_all_unsafe : --auto-approve-all-unsafe flag (BYPASSES
                        the gate entirely; awkward name is deliberate so
                        eval scripts don't reach for it by muscle memory).
      interactive     : True if stdin is a TTY; False (default when
                        non-interactive) means prompts default-deny
                        instead of hanging.
    """
    learned: dict[str, LearnedProbeRecord] = field(default_factory=dict)
    auto_approve_known: bool = False
    auto_approve_all_unsafe: bool = False
    interactive: bool = True
    _skip_remainder: bool = False

    def decide(self, proposal: ProposedProbe, cve_id: str) -> tuple[Decision, str]:
        """Decide whether to run this proposal.

        The order matters: skip-all beats everything (operator already said
        stop), then auto-approve-all-unsafe (explicit bypass), then
        auto-approve-known (matches a JSONL entry), then HITL (or
        default-deny when non-interactive).

        Returns:
            (Decision, approved_by) tuple. approved_by is an empty string
            when Decision != APPROVE.
        """
        if self._skip_remainder:
            return Decision.DENY, ""

        # Empty-binary sentinel = "no useful probe" — don't approve, don't ask.
        if proposal.binary == "":
            return Decision.DENY, ""

        if self.auto_approve_all_unsafe:
            return Decision.APPROVE, "auto-approve-all-unsafe"

        h = argv_hash(proposal.binary, proposal.args)
        if self.auto_approve_known and h in self.learned:
            return Decision.APPROVE, "auto-approve-known"

        if not self.interactive:
            # Non-TTY: never prompt (would hang forever); default deny.
            return Decision.DENY, ""

        decision = self._prompt(proposal, cve_id)
        if decision == Decision.APPROVE:
            return decision, "operator"
        return decision, ""

    def _prompt(self, proposal: ProposedProbe, cve_id: str) -> Decision:
        argv_display = " ".join([proposal.binary, *proposal.args])
        print(f"\n[HITL] Proposed probe for {cve_id}:", file=sys.stderr)
        print(f"       argv:      {argv_display}", file=sys.stderr)
        print(f"       rationale: {proposal.rationale}", file=sys.stderr)
        if proposal.expected_signals:
            print(f"       signals:   {', '.join(proposal.expected_signals)}", file=sys.stderr)
        while True:
            try:
                ans = input("       run? [y/N/skip-all] ").strip().lower()
            except EOFError:
                # stdin closed mid-run — deny + stop asking.
                self._skip_remainder = True
                return Decision.DENY
            if ans in ("", "n", "no"):
                return Decision.DENY
            if ans in ("y", "yes"):
                return Decision.APPROVE
            if ans in ("s", "skip", "skip-all"):
                self._skip_remainder = True
                return Decision.DENY
            print("       (answer y, n, or skip-all)", file=sys.stderr)


def stdin_is_tty() -> bool:
    """Best-effort TTY check for defaulting interactive."""
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


# ---- Approved-probe execution helper --------------------------------------

def build_probe_argv(proposal: ProposedProbe, target_container: str | None) -> list[str]:
    """Build the argv list to actually exec for an approved proposal.

    When target_container is set, wraps with `docker exec <container>` —
    mirrors docker_exec_probe_runner's behavior for hardcoded probes.
    """
    argv = [proposal.binary, *proposal.args]
    if target_container:
        return ["docker", "exec", target_container, *argv]
    return argv


def make_learned_record(
    proposal: ProposedProbe,
    cve_id: str,
    approved_by: str,
) -> LearnedProbeRecord:
    """Construct a LearnedProbeRecord from an approved proposal for JSONL append."""
    return LearnedProbeRecord(
        argv_hash=argv_hash(proposal.binary, proposal.args),
        binary=proposal.binary,
        args=proposal.args,
        rationale=proposal.rationale,
        expected_signals=proposal.expected_signals,
        first_seen_cve=cve_id,
        approved_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        approved_by=approved_by,
    )
