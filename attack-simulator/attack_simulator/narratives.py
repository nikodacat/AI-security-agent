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

import html
import json
import re
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


# ------------------------------------------------------------------ #
# HTML rendering (for v2-11 report integration)                      #
# ------------------------------------------------------------------ #

SECTION_MARKER = "<!-- exposure-analyzer:attack-narratives -->"


def render_html_section(
    narratives: list[Narrative],
    *,
    generated_at: str = "",
) -> str:
    """Render narratives as an HTML `<section>` fragment.

    Uses the host-scanner report's existing CSS classes (`card`, `muted`)
    for visual consistency; every model-produced text field is
    `html.escape`d so hostile narrator output cannot inject markup.
    Wrapped in `SECTION_MARKER` / `SECTION_MARKER + " end"` sentinels so
    exposure-analyzer's report.py can re-inject idempotently on re-runs.
    """
    parts: list[str] = []
    parts.append(SECTION_MARKER)
    parts.append('  <div class="card">')
    parts.append("    <h2>Attack Narratives</h2>")
    scope = (
        f'{len(narratives)} narrative(s) from CONFIRMED verdicts. '
        "No exploit code, no attacker-tool invocations."
    )
    meta_bits = [scope]
    if generated_at:
        meta_bits.append(f"Generated {html.escape(generated_at)}")
    parts.append(
        '    <p class="muted" style="margin-bottom:0.75rem;">'
        + " · ".join(meta_bits)
        + "</p>"
    )

    if not narratives:
        parts.append(
            '    <p class="muted" style="text-align:center;">'
            "(no CONFIRMED verdicts — nothing to narrate)</p>"
        )
    else:
        for n in narratives:
            parts.append(_render_narrative_block(n))

    parts.append("  </div>")
    parts.append(f"{SECTION_MARKER} end")
    return "\n".join(parts)


def _render_narrative_block(n: Narrative) -> str:
    heading = f"{html.escape(n.cve_id)}"
    if n.target:
        heading += f' <span class="muted">— target: <code>{html.escape(n.target)}</code></span>'

    meta_bits: list[str] = []
    if n.generated_at:
        meta_bits.append(html.escape(n.generated_at))
    if n.model:
        meta_bits.append(f"model: {html.escape(n.model)}")
    meta_html = ""
    if meta_bits:
        meta_html = (
            '<div class="muted" style="font-size:0.85em;margin-top:-0.35rem;'
            'margin-bottom:0.35rem;">'
            + " · ".join(meta_bits)
            + "</div>"
        )

    verdict_html = ""
    if n.source_verdict_reason:
        verdict_html = (
            '<blockquote style="margin:0.5rem 0;padding:0.5rem 0.75rem;'
            'border-left:3px solid #64748b;background:#f8fafc;'
            'font-size:0.9em;color:#334155;">'
            f'<strong>Analyzer verdict:</strong> {html.escape(n.source_verdict_reason)}'
            "</blockquote>"
        )

    body_html = _narrative_body_to_html(n.narrative)

    return (
        '    <div style="margin:1rem 0;padding:0.75rem 1rem;'
        'border:1px solid #e2e8f0;border-radius:6px;">\n'
        f"      <h3 style=\"margin-top:0;\">{heading}</h3>\n"
        f"      {meta_html}\n"
        f"      {verdict_html}\n"
        f"      {body_html}\n"
        "    </div>"
    )


_H3_RE = re.compile(r"^###\s+(.+?)\s*$")


def _narrative_body_to_html(body: str) -> str:
    """Convert the narrative body (Markdown-lite with ### headings) to HTML.

    The narrative body from Claude follows the SYSTEM_PROMPT's contract:
    `### Recon` / `### Discovery` / `### Exploitation` headings, each
    followed by a paragraph. We convert `###` → `<h4>` and blank-line-
    separated paragraphs → `<p>`. Everything is html.escape'd first.
    """
    lines = body.strip().splitlines()
    parts: list[str] = []
    para_buf: list[str] = []

    def flush_para() -> None:
        if para_buf:
            text = " ".join(para_buf).strip()
            if text:
                parts.append(f"<p>{html.escape(text)}</p>")
            para_buf.clear()

    for line in lines:
        m = _H3_RE.match(line)
        if m:
            flush_para()
            parts.append(f'<h4 style="margin-bottom:0.25rem;">{html.escape(m.group(1))}</h4>')
        elif line.strip() == "":
            flush_para()
        else:
            para_buf.append(line.strip())
    flush_para()

    return "\n      ".join(parts) if parts else "<p><em>(empty narrative)</em></p>"
