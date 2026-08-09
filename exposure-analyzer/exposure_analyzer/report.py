"""Report integration — append verdict blocks to host-scanner's HTML report.

This module is the ONLY point of contact between the analyzer and the
host-scanner report generator. Keeping the seam narrow means both can
evolve independently.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from .verdicts import Verdict, VerdictType


# Verdict-value → CSS badge color (reuses host-scanner's severity palette
# where the mapping is intuitive; falls back to `info` blue otherwise).
_VERDICT_BADGE_CLASS = {
    VerdictType.CONFIRMED: "sev-critical",
    VerdictType.MITIGATED_BY_CONFIG: "sev-low",
    VerdictType.MITIGATED_BY_EXPOSURE: "sev-low",
    VerdictType.NOT_RUNNING: "sev-info",
    VerdictType.NO_EVIDENCE: "sev-medium",
}

_SECTION_MARKER = "<!-- exposure-analyzer:verdicts -->"


def append_verdicts_to_report(
    verdicts: list[Verdict],
    html_report_path: Path,
) -> None:
    """Insert (or replace) a verdicts section in a host-scanner HTML report.

    Reads the file, removes any previously-inserted verdicts block (marked by
    `_SECTION_MARKER`), inserts a fresh one before the closing `</body>` tag,
    and writes the file back atomically.

    Raises:
        FileNotFoundError: if the report file does not exist yet.
    """
    path = Path(html_report_path)
    if not path.exists():
        raise FileNotFoundError(
            f"host-scanner report not found at {path}. "
            "Run host-scanner first, then re-invoke exposure-analyzer."
        )

    original = path.read_text(encoding="utf-8")
    stripped = _strip_existing_section(original)
    section = _render_verdicts_section(verdicts)

    if "</body>" in stripped:
        updated = stripped.replace("</body>", section + "\n</body>", 1)
    else:
        # Report has no </body> — append at end so we still emit something usable.
        updated = stripped + "\n" + section + "\n"

    path.write_text(updated, encoding="utf-8")


def render_verdicts_summary(verdicts: list[Verdict]) -> str:
    """One-line-per-verdict text summary — used by the CLI for stdout."""
    if not verdicts:
        return "(no verdicts)"
    lines = []
    for v in verdicts:
        lines.append(f"{v.verdict.value:22s}  {v.cve_id}  {v.reason[:60]}")
    return "\n".join(lines)


def _strip_existing_section(doc: str) -> str:
    """Remove a previously-inserted verdicts block, if present."""
    start = doc.find(_SECTION_MARKER)
    if start == -1:
        return doc
    end_marker = _SECTION_MARKER + " end"
    end = doc.find(end_marker, start)
    if end == -1:
        return doc
    return doc[:start] + doc[end + len(end_marker):]


def _render_verdicts_section(verdicts: list[Verdict]) -> str:
    """Build the HTML fragment to inject."""
    counts = _count_by_verdict(verdicts)
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")

    pills = []
    for vt, css in _VERDICT_BADGE_CLASS.items():
        n = counts.get(vt.value, 0)
        if n:
            pills.append(
                f'<div class="sev-pill {css}">{n} {html.escape(vt.value)}</div>'
            )
    pills_html = "\n      ".join(pills) if pills else '<span class="muted">no verdicts</span>'

    rows = []
    if not verdicts:
        rows.append(
            '<tr><td colspan="4" class="muted" style="text-align:center;">'
            'No verdicts produced.</td></tr>'
        )
    else:
        for v in verdicts:
            rows.append(_render_row(v))
    rows_html = "\n        ".join(rows)

    return f"""{_SECTION_MARKER}
  <div class="card">
    <h2>Exposure Verdicts</h2>
    <p class="muted" style="margin-bottom:0.75rem;">
      Gray-box impact analysis for CVE candidates. Generated {html.escape(generated)}
      by exposure-analyzer.
    </p>
    <div class="sev-counts">
      {pills_html}
    </div>
    <table>
      <thead>
        <tr>
          <th>Verdict</th><th>CVE</th><th>Reason</th><th>Evidence</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>
{_SECTION_MARKER} end"""


def _render_row(v: Verdict) -> str:
    css = _VERDICT_BADGE_CLASS.get(v.verdict, "sev-info")
    evidence_html = _render_evidence(v)
    return (
        "<tr>"
        f'<td><span class="badge {css}">{html.escape(v.verdict.value)}</span></td>'
        f'<td style="white-space:nowrap; font-family:monospace; font-size:0.8rem;">'
        f'{html.escape(v.cve_id)}</td>'
        f'<td class="muted">{html.escape(v.reason)}</td>'
        f"<td>{evidence_html}</td>"
        "</tr>"
    )


def _render_evidence(v: Verdict) -> str:
    parts: list[str] = []
    if v.evidence:
        pretty = html.escape(json.dumps(v.evidence, indent=2, ensure_ascii=False))
        parts.append(
            f'<pre style="margin:0; font-size:0.75rem; color:#cbd5e1; '
            f'white-space:pre-wrap;">{pretty}</pre>'
        )
    if v.probe_command:
        parts.append(
            f'<div class="muted" style="font-family:monospace; font-size:0.75rem; '
            f'margin-top:0.35rem;">$ {html.escape(v.probe_command)}</div>'
        )
    if not parts:
        return '<span class="muted">—</span>'
    return "".join(parts)


def _count_by_verdict(verdicts: list[Verdict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for v in verdicts:
        counts[v.verdict.value] = counts.get(v.verdict.value, 0) + 1
    return counts
