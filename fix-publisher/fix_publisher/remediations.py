"""Data model for remediation drafts.

`Remediation` is the per-CONFIRMED-verdict output record. `dump_remediations`
writes a JSON sidecar; `load_remediations` reads it back; `render_markdown`
produces a human-readable companion document (used by the CLI's --markdown
flag and, later, by v2-11 report integration).

Design constraints:
- Frozen dataclass so records are hashable + comparable.
- Empty-string defaults for optional fields keep JSON round-trip stable.
- Field order: identity → structured fix subfields → context → metadata.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Remediation:
    """One remediation draft for one CONFIRMED verdict.

    Attributes:
        cve_id: the CVE identifier being remediated.
        target: the host / container the analyzer verdict was for.
        apt_command: pinned apt install block (validator requires version pin).
        config_diff: unified diff of the config change, or
            "no config change needed".
        service_restart: systemctl restart directive, or "no restart needed".
        explanation: one or two sentences on why this fixes the CVE.
        source_verdict_reason: copy of the verdict's `reason` field.
        generated_at: ISO 8601 UTC timestamp of generation.
        model: identifier of the backend (e.g. "sonnet", "fake", "claude-sonnet").
    """

    cve_id: str
    target: str
    apt_command: str
    config_diff: str
    service_restart: str
    explanation: str
    source_verdict_reason: str = ""
    generated_at: str = ""
    model: str = ""

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "target": self.target,
            "apt_command": self.apt_command,
            "config_diff": self.config_diff,
            "service_restart": self.service_restart,
            "explanation": self.explanation,
            "source_verdict_reason": self.source_verdict_reason,
            "generated_at": self.generated_at,
            "model": self.model,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Remediation":
        return cls(
            cve_id=data.get("cve_id", ""),
            target=data.get("target", ""),
            apt_command=data.get("apt_command", ""),
            config_diff=data.get("config_diff", ""),
            service_restart=data.get("service_restart", ""),
            explanation=data.get("explanation", ""),
            source_verdict_reason=data.get("source_verdict_reason", ""),
            generated_at=data.get("generated_at", ""),
            model=data.get("model", ""),
        )


SCHEMA_VERSION = "fix-publisher/v1"


def dump_remediations(
    rems: list[Remediation],
    path: str | Path,
    *,
    generated_at: str = "",
) -> None:
    """Write remediations as a JSON sidecar.

    Shape mirrors exposure-analyzer's verdicts.json:
        {"schema_version": ..., "generated_at": ..., "remediations": [...]}
    """
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "remediations": [r.to_dict() for r in rems],
    }
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_remediations(path: str | Path) -> list[Remediation]:
    """Read a remediations JSON sidecar. Tolerates bare-list format."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "remediations" in data:
        entries = data["remediations"]
    elif isinstance(data, list):
        entries = data
    else:
        raise ValueError(f"Unrecognized remediations JSON shape at {path}")
    return [Remediation.from_dict(e) for e in entries]


_NO_CONFIG = "no config change needed"
_NO_RESTART = "no restart needed"


def render_markdown(
    rems: list[Remediation],
    *,
    generated_at: str = "",
) -> str:
    """Render remediations as a single readable Markdown document.

    Top of the document names the scope + generation metadata; each
    remediation gets a level-2 heading with CVE + target, a small metadata
    line, the analyzer verdict as a blockquote, then four labeled
    subsections (Package update, Config change, Service restart, Why this
    works). Subsections that would just repeat "no change needed" collapse
    to a single italic line so the reader can scan quickly.
    """
    lines: list[str] = []
    lines.append("# Remediation drafts")
    lines.append("")
    n_count = len(rems)
    lines.append(
        f"Advisory scope: {n_count} remediation(s) from CONFIRMED verdicts. "
        "Draft commands — review against your fleet's pins before applying."
    )
    if generated_at:
        lines.append("")
        lines.append(f"_Generated: {generated_at}_")
    lines.append("")
    lines.append("---")
    lines.append("")

    if not rems:
        lines.append("_(no CONFIRMED verdicts — nothing to remediate)_")
        lines.append("")
        return "\n".join(lines)

    for r in rems:
        heading = f"## {r.cve_id}"
        if r.target:
            heading += f" — target: `{r.target}`"
        lines.append(heading)
        lines.append("")
        meta_bits: list[str] = []
        if r.generated_at:
            meta_bits.append(r.generated_at)
        if r.model:
            meta_bits.append(f"model: {r.model}")
        if meta_bits:
            lines.append("_" + " · ".join(meta_bits) + "_")
            lines.append("")
        if r.source_verdict_reason:
            lines.append("**Analyzer verdict:**")
            lines.append("")
            for verdict_line in r.source_verdict_reason.strip().splitlines():
                lines.append(f"> {verdict_line}")
            lines.append("")

        lines.append("### Package update")
        lines.append("")
        lines.append("```bash")
        lines.append(r.apt_command.strip() or "# (no apt command generated)")
        lines.append("```")
        lines.append("")

        lines.append("### Config change")
        lines.append("")
        cfg = r.config_diff.strip()
        if not cfg or cfg.lower() == _NO_CONFIG:
            lines.append(f"_{_NO_CONFIG}._")
        else:
            lines.append("```diff")
            lines.append(cfg)
            lines.append("```")
        lines.append("")

        lines.append("### Service restart")
        lines.append("")
        restart = r.service_restart.strip()
        if not restart or restart.lower() == _NO_RESTART:
            lines.append(f"_{_NO_RESTART}._")
        else:
            lines.append("```bash")
            lines.append(restart)
            lines.append("```")
        lines.append("")

        lines.append("### Why this works")
        lines.append("")
        lines.append(r.explanation.strip() or "_(no explanation provided)_")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)
