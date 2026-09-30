"""Data model for attack narratives.

`Narrative` is the per-CONFIRMED-verdict output record. `dump_narratives`
writes a JSON sidecar; `load_narratives` reads it back; `render_markdown`
produces a human-readable companion document (used by the CLI's --markdown
flag and, later, by v2-11 report integration).

Design constraints:
- Frozen dataclass so records are hashable and comparable.
- Empty-string defaults for optional fields keep JSON round-trip stable
  (no missing-vs-null ambiguity).
- Field order is deliberately identity → context → content → metadata, so
  the JSON reads top-to-bottom for a human skimming it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Narrative:
    """One attack-path narrative for one CONFIRMED verdict.

    Attributes:
        cve_id:  the CVE identifier this narrative describes.
        target:  the host / container the analyzer verdict was for.
        narrative:  the attack-path text (recon → discovery → exploitation).
        source_verdict_reason:  a copy of the verdict's `reason` field, so
            the narrative can be read on its own without opening verdicts.json.
        generated_at:  ISO 8601 UTC timestamp of narrative generation.
        model:  identifier of the backend that produced the narrative
            (e.g. "sonnet", "fake", "claude-sonnet-5").
    """

    cve_id: str
    target: str
    narrative: str
    source_verdict_reason: str = ""
    generated_at: str = ""
    model: str = ""

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "target": self.target,
            "narrative": self.narrative,
            "source_verdict_reason": self.source_verdict_reason,
            "generated_at": self.generated_at,
            "model": self.model,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Narrative":
        return cls(
            cve_id=data.get("cve_id", ""),
            target=data.get("target", ""),
            narrative=data.get("narrative", ""),
            source_verdict_reason=data.get("source_verdict_reason", ""),
            generated_at=data.get("generated_at", ""),
            model=data.get("model", ""),
        )


SCHEMA_VERSION = "attack-simulator/v1"


def dump_narratives(
    narratives: list[Narrative],
    path: str | Path,
    *,
    generated_at: str = "",
) -> None:
    """Write narratives as a JSON sidecar.

    Shape mirrors exposure-analyzer's verdicts.json:
        {"schema_version": ..., "generated_at": ..., "narratives": [...]}
    """
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "narratives": [n.to_dict() for n in narratives],
    }
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_narratives(path: str | Path) -> list[Narrative]:
    """Read a narratives JSON sidecar."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "narratives" in data:
        entries = data["narratives"]
    elif isinstance(data, list):
        # Tolerate bare-list format for hand-authored fixtures.
        entries = data
    else:
        raise ValueError(f"Unrecognized narratives JSON shape at {path}")
    return [Narrative.from_dict(e) for e in entries]


def render_markdown(
    narratives: list[Narrative],
    *,
    generated_at: str = "",
) -> str:
    """Render narratives as a single readable Markdown document.

    Used for the CLI's --markdown output and (later) v2-11 report integration.
    Top of the document names the scope + generation metadata; each narrative
    gets a level-2 heading with CVE + target, a small metadata line, the
    verdict reason as a blockquote, and the narrative body.
    """
    lines: list[str] = []
    lines.append("# Attack narratives")
    lines.append("")
    n_count = len(narratives)
    scope_line = (
        f"Advisory scope: {n_count} narrative(s) from CONFIRMED verdicts. "
        "No exploit code, no attacker-tool invocations."
    )
    lines.append(scope_line)
    if generated_at:
        lines.append("")
        lines.append(f"_Generated: {generated_at}_")
    lines.append("")
    lines.append("---")
    lines.append("")

    if not narratives:
        lines.append("_(no CONFIRMED verdicts — nothing to narrate)_")
        lines.append("")
        return "\n".join(lines)

    for n in narratives:
        heading = f"## {n.cve_id}"
        if n.target:
            heading += f" — target: `{n.target}`"
        lines.append(heading)
        lines.append("")
        meta_bits: list[str] = []
        if n.generated_at:
            meta_bits.append(n.generated_at)
        if n.model:
            meta_bits.append(f"model: {n.model}")
        if meta_bits:
            lines.append("_" + " · ".join(meta_bits) + "_")
            lines.append("")
        if n.source_verdict_reason:
            lines.append("**Analyzer verdict:**")
            lines.append("")
            for verdict_line in n.source_verdict_reason.strip().splitlines():
                lines.append(f"> {verdict_line}")
            lines.append("")
        lines.append(n.narrative.strip())
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)
