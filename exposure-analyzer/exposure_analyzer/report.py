"""Report integration — append verdict blocks to host-scanner's HTML report.

This module is the ONLY point of contact between the analyzer and the
host-scanner report generator. Keeping the seam narrow means both can
evolve independently.

Chunk C implements the real appender. This scaffold defines the signature.
"""

from __future__ import annotations

from pathlib import Path

from .verdicts import Verdict


def append_verdicts_to_report(
    verdicts: list[Verdict],
    html_report_path: Path,
) -> None:
    """Insert a verdicts section into an existing host-scanner HTML report.

    Args:
        verdicts:         list produced by `ExposureAgent.analyze_batch`.
        html_report_path: path to a report already produced by host-scanner.
                          This function reads it, inserts a verdicts block
                          before the closing `</body>` tag, and writes back.

    Raises:
        FileNotFoundError: if the report file does not exist yet.
        NotImplementedError: chunk C implements the real template.
    """
    if not Path(html_report_path).exists():
        raise FileNotFoundError(
            f"host-scanner report not found at {html_report_path}. "
            "Run host-scanner first, then re-invoke exposure-analyzer."
        )
    raise NotImplementedError(
        "append_verdicts_to_report is implemented in chunk C "
        "(see ../docs/ROADMAP.md)."
    )


def render_verdicts_summary(verdicts: list[Verdict]) -> str:
    """One-line-per-verdict text summary — used by the CLI for stdout.

    Not a full HTML render; that's `append_verdicts_to_report`'s job.

    Returns:
        A multi-line string like::

            CONFIRMED           CVE-2023-38408  OpenSSH pubkey vuln
            MITIGATED_BY_CONFIG CVE-2024-XXXX   ...

    Safe to call in the scaffold: uses only Verdict fields, no external deps.
    """
    if not verdicts:
        return "(no verdicts)"
    lines = []
    for v in verdicts:
        lines.append(f"{v.verdict.value:22s}  {v.cve_id}  {v.reason[:60]}")
    return "\n".join(lines)
