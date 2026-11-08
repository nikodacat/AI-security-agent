"""Report integration — append verdict blocks to host-scanner's HTML report.

This module is the ONLY point of contact between the analyzer and the
host-scanner report generator. Keeping the seam narrow means both can
evolve independently.

v2-11 extends this with two optional sibling-fed sections: attack
narratives (from `attack-simulator`) and remediation drafts (from
`fix-publisher`). Those sibling packages are imported lazily and only
when the caller provides their JSON paths — the v1 report code path is
unchanged, and running the analyzer without the siblings installed still
works.
"""

from __future__ import annotations

import html
import json
import sys
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
_ATTACK_MARKER = "<!-- exposure-analyzer:attack-narratives -->"
_REMEDIATION_MARKER = "<!-- exposure-analyzer:remediations -->"
_SECURITY_CHECKS_MARKER = "<!-- exposure-analyzer:security-checks -->"

# Sibling package roots (siblings of exposure-analyzer/ under the repo root).
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent  # exposure_analyzer/ → exposure-analyzer/ → repo/
_ATTACK_SIMULATOR_ROOT = _REPO_ROOT / "attack-simulator"
_FIX_PUBLISHER_ROOT = _REPO_ROOT / "fix-publisher"


def append_verdicts_to_report(
    verdicts: list[Verdict],
    html_report_path: Path,
    *,
    attack_narratives_path: Path | None = None,
    remediations_path: Path | None = None,
    scan: dict | None = None,
) -> None:
    """Insert (or replace) analyzer + optional attack + remediation sections.

    Reads the report file, strips any previously-inserted verdicts /
    attack / remediation blocks (each with its own marker), inserts fresh
    ones before the closing `</body>` tag, and writes the file back.

    `scan` (the host scan JSON) adds a "Security checks" section: the posture and leak
    findings with a fixed fix hint each (no AI involved).

    `attack_narratives_path` / `remediations_path` are optional. When
    provided, this function lazily imports the sibling packages
    (attack-simulator / fix-publisher) — adding their roots to sys.path
    if needed — loads the JSON, and renders each section via the
    sibling's own `render_html_section`. When omitted, the v1 code path
    runs unchanged.

    Raises:
        FileNotFoundError: if the base report file doesn't exist yet.
    """
    path = Path(html_report_path)
    if not path.exists():
        raise FileNotFoundError(
            f"host-scanner report not found at {path}. "
            "Run host-scanner first, then re-invoke exposure-analyzer."
        )

    attack_section = _load_attack_section(attack_narratives_path)
    remediation_section = _load_remediation_section(remediations_path)
    checks_section = _load_security_checks_section(scan)

    original = path.read_text(encoding="utf-8")
    stripped = _strip_all_sections(original)
    verdicts_section = _render_verdicts_section(verdicts)

    insert = verdicts_section
    if attack_section:
        insert += "\n" + attack_section
    if remediation_section:
        insert += "\n" + remediation_section
    if checks_section:
        insert += "\n" + checks_section

    if "</body>" in stripped:
        updated = stripped.replace("</body>", insert + "\n</body>", 1)
    else:
        updated = stripped + "\n" + insert + "\n"

    path.write_text(updated, encoding="utf-8")


def _ensure_sibling_on_path(sibling_root: Path) -> None:
    """Add a sibling package root to sys.path if not already present."""
    p = str(sibling_root)
    if sibling_root.exists() and p not in sys.path:
        sys.path.insert(0, p)


def _load_attack_section(path: Path | None) -> str:
    """Load attack narratives from disk and render as HTML. Empty if no path."""
    if path is None:
        return ""
    _ensure_sibling_on_path(_ATTACK_SIMULATOR_ROOT)
    try:
        from attack_simulator import load_narratives, render_html_section  # type: ignore
    except ImportError as e:  # pragma: no cover -- lazy import path
        raise RuntimeError(
            f"--attack-narratives given but attack-simulator package not importable. "
            f"Expected at {_ATTACK_SIMULATOR_ROOT}. "
            f"Original error: {e}"
        ) from e

    narratives = load_narratives(path)
    # Peek generated_at from the JSON payload for the scope line.
    generated_at = _peek_generated_at(path)
    return render_html_section(narratives, generated_at=generated_at)


def _load_remediation_section(path: Path | None) -> str:
    """Load remediations from disk and render as HTML. Empty if no path."""
    if path is None:
        return ""
    _ensure_sibling_on_path(_FIX_PUBLISHER_ROOT)
    try:
        from fix_publisher import load_remediations, render_html_section  # type: ignore
    except ImportError as e:  # pragma: no cover -- lazy import path
        raise RuntimeError(
            f"--remediations given but fix-publisher package not importable. "
            f"Expected at {_FIX_PUBLISHER_ROOT}. "
            f"Original error: {e}"
        ) from e

    rems = load_remediations(path)
    generated_at = _peek_generated_at(path)
    return render_html_section(rems, generated_at=generated_at)


def _load_security_checks_section(scan: dict | None) -> str:
    """Render the posture + leak findings of `scan` as HTML. Empty if no scan given."""
    if scan is None:
        return ""
    _ensure_sibling_on_path(_FIX_PUBLISHER_ROOT)
    try:
        from fix_publisher.hardening import collect_findings, render_html_section  # type: ignore
    except ImportError as e:  # pragma: no cover -- lazy import path
        raise RuntimeError(
            f"scan given but fix-publisher package not importable. "
            f"Expected at {_FIX_PUBLISHER_ROOT}. Original error: {e}"
        ) from e
    return render_html_section(collect_findings(scan))


def _peek_generated_at(path: Path) -> str:
    """Best-effort extraction of `generated_at` from a sibling JSON payload."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return str(data.get("generated_at", ""))
    except Exception:  # pragma: no cover -- defensive
        return ""
    return ""


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
    return _strip_marked_block(doc, _SECTION_MARKER)


def _strip_all_sections(doc: str) -> str:
    """Strip verdicts, attack, and remediation blocks from prior runs.

    Applied in that order so each strip pass sees a stable document. All
    three markers use the same "start / start + ' end'" convention.
    """
    for marker in (_SECTION_MARKER, _ATTACK_MARKER, _REMEDIATION_MARKER, _SECURITY_CHECKS_MARKER):
        doc = _strip_marked_block(doc, marker)
    return doc


def _strip_marked_block(doc: str, marker: str) -> str:
    start = doc.find(marker)
    if start == -1:
        return doc
    end_marker = marker.replace("-->", "end -->")
    end = doc.find(end_marker, start)
    if end == -1:
        return doc
    tail = doc[end + len(end_marker):]
    if tail.startswith("\n"):  # the newline the insert added after the block
        tail = tail[1:]
    return doc[:start] + tail


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
{_SECTION_MARKER.replace("-->", "end -->")}"""


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
    # v2-7/v2-8: surface LLM-proposed probes. When probe_command is set the
    # proposal was approved (HITL or auto-approve) and executed; the argv is
    # already shown above via probe_command, so we only add a small "(LLM-
    # proposed, operator-approved)" attribution line. When probe_command is
    # empty the proposal was not executed — show the argv with a "not executed"
    # label so a reviewer sees what the analyzer would have wanted to run.
    if v.proposed_probe:
        pp = v.proposed_probe
        argv_display = " ".join(
            [str(pp.get("binary", ""))] + [str(a) for a in pp.get("args", [])]
        ).strip()
        if v.probe_command:
            parts.append(
                f'<div class="muted" style="font-size:0.7rem; margin-top:0.15rem; '
                f'color:#94a3b8;">↑ LLM-proposed probe, operator-approved</div>'
            )
        else:
            parts.append(
                f'<div class="muted" style="font-family:monospace; font-size:0.75rem; '
                f'margin-top:0.35rem; color:#fbbf24;">'
                f'proposed (not executed): {html.escape(argv_display) or "—"}'
                f'</div>'
            )
    if v.probe_proposal_error:
        parts.append(
            f'<div class="muted" style="font-size:0.75rem; margin-top:0.35rem; '
            f'color:#f87171;">proposal rejected: {html.escape(v.probe_proposal_error)}</div>'
        )
    if not parts:
        return '<span class="muted">—</span>'
    return "".join(parts)


def _count_by_verdict(verdicts: list[Verdict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for v in verdicts:
        counts[v.verdict.value] = counts.get(v.verdict.value, 0) + 1
    return counts
