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

import html
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


# ------------------------------------------------------------------ #
# HTML rendering (for v2-11 report integration)                      #
# ------------------------------------------------------------------ #

SECTION_MARKER = "<!-- exposure-analyzer:remediations -->"


def render_html_section(
    rems: list[Remediation],
    *,
    generated_at: str = "",
) -> str:
    """Render remediations as an HTML `<section>` fragment.

    Same shape as attack_simulator.narratives.render_html_section — uses
    the host-scanner report's existing CSS classes (`card`, `muted`),
    html.escapes every model field, and wraps in
    SECTION_MARKER / SECTION_MARKER + " end" sentinels for idempotent
    re-injection by exposure-analyzer's report.py.
    """
    parts: list[str] = []
    parts.append(SECTION_MARKER)
    parts.append('  <div class="card">')
    parts.append("    <h2>Remediation Drafts</h2>")
    scope = (
        f'{len(rems)} remediation(s) from CONFIRMED verdicts. '
        "Draft commands — review against your fleet's pins before applying."
    )
    meta_bits = [scope]
    if generated_at:
        meta_bits.append(f"Generated {html.escape(generated_at)}")
    parts.append(
        '    <p class="muted" style="margin-bottom:0.75rem;">'
        + " · ".join(meta_bits)
        + "</p>"
    )

    if not rems:
        parts.append(
            '    <p class="muted" style="text-align:center;">'
            "(no CONFIRMED verdicts — nothing to remediate)</p>"
        )
    else:
        for r in rems:
            parts.append(_render_remediation_block(r))

    parts.append("  </div>")
    parts.append(f"{SECTION_MARKER} end")
    return "\n".join(parts)


def _render_remediation_block(r: Remediation) -> str:
    heading = f"{html.escape(r.cve_id)}"
    if r.target:
        heading += f' <span class="muted">— target: <code>{html.escape(r.target)}</code></span>'

    meta_bits: list[str] = []
    if r.generated_at:
        meta_bits.append(html.escape(r.generated_at))
    if r.model:
        meta_bits.append(f"model: {html.escape(r.model)}")
    meta_html = ""
    if meta_bits:
        meta_html = (
            '<div class="muted" style="font-size:0.85em;margin-top:-0.35rem;'
            'margin-bottom:0.35rem;">'
            + " · ".join(meta_bits)
            + "</div>"
        )

    verdict_html = ""
    if r.source_verdict_reason:
        verdict_html = (
            '<blockquote style="margin:0.5rem 0;padding:0.5rem 0.75rem;'
            'border-left:3px solid #64748b;background:#f8fafc;'
            'font-size:0.9em;color:#334155;">'
            f'<strong>Analyzer verdict:</strong> {html.escape(r.source_verdict_reason)}'
            "</blockquote>"
        )

    # Package update — always shown, even if empty apt_command (escape hatch).
    apt = r.apt_command.strip()
    if apt:
        pkg_html = _code_block(apt, lang="bash")
    else:
        pkg_html = (
            '<p class="muted" style="font-style:italic;">'
            "(no apt command — see explanation below)</p>"
        )

    # Config change — sentinel collapses to italic line.
    cfg = r.config_diff.strip()
    if not cfg or cfg.lower() == _NO_CONFIG:
        cfg_html = f'<p class="muted" style="font-style:italic;">{html.escape(_NO_CONFIG)}.</p>'
    else:
        cfg_html = _code_block(cfg, lang="diff")

    # Service restart — sentinel collapses to italic line.
    restart = r.service_restart.strip()
    if not restart or restart.lower() == _NO_RESTART:
        restart_html = f'<p class="muted" style="font-style:italic;">{html.escape(_NO_RESTART)}.</p>'
    else:
        restart_html = _code_block(restart, lang="bash")

    explanation_html = (
        f"<p>{html.escape(r.explanation.strip()) or '<em>(no explanation provided)</em>'}</p>"
    )

    return (
        '    <div style="margin:1rem 0;padding:0.75rem 1rem;'
        'border:1px solid #e2e8f0;border-radius:6px;">\n'
        f"      <h3 style=\"margin-top:0;\">{heading}</h3>\n"
        f"      {meta_html}\n"
        f"      {verdict_html}\n"
        '      <h4 style="margin-bottom:0.25rem;">Package update</h4>\n'
        f"      {pkg_html}\n"
        '      <h4 style="margin-bottom:0.25rem;">Config change</h4>\n'
        f"      {cfg_html}\n"
        '      <h4 style="margin-bottom:0.25rem;">Service restart</h4>\n'
        f"      {restart_html}\n"
        '      <h4 style="margin-bottom:0.25rem;">Why this works</h4>\n'
        f"      {explanation_html}\n"
        "    </div>"
    )


def _code_block(text: str, *, lang: str = "") -> str:
    """Render a text blob as an html-escaped <pre><code> block."""
    return (
        f'<pre style="background:#0f172a;color:#e2e8f0;padding:0.6rem 0.8rem;'
        f'border-radius:4px;overflow-x:auto;font-size:0.85em;">'
        f'<code class="language-{html.escape(lang)}">{html.escape(text)}</code>'
        "</pre>"
    )
