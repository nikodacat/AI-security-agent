"""Report builder — renders HTML and optionally PDF from scan results."""

import json
import os
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = Path(__file__).parent.parent / "frontend" / "templates"


def _severity_order(s: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 5)


def build_report_data(scan_results: dict, analyses: dict, executive: dict) -> dict:
    """Assemble all data into a single context dict for the template."""
    all_findings = []
    for scanner_name, analysis in analyses.items():
        for f in analysis.get("findings", []):
            f["scanner"] = scanner_name
            all_findings.append(f)

    all_findings.sort(key=lambda x: _severity_order(x.get("severity", "info")))

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    scanner_summaries = []
    for name, analysis in analyses.items():
        raw = scan_results.get(name, {})
        scanner_summaries.append({
            "name": name,
            "score": analysis.get("score", 0),
            "summary": analysis.get("summary", ""),
            "status": raw.get("status", "completed"),
            "duration": raw.get("scan_duration_s", 0),
            "finding_count": len(analysis.get("findings", [])),
        })

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "executive": executive,
        "scanner_summaries": scanner_summaries,
        "all_findings": all_findings,
        "severity_counts": severity_counts,
        "overall_score": executive.get("overall_score", 0),
        "grade": executive.get("grade", "?"),
    }


def render_html(report_data: dict, output_path: str) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template("report.html")
    html = template.render(**report_data)
    Path(output_path).write_text(html, encoding="utf-8")
    return output_path


def render_pdf(html_path: str, pdf_path: str) -> str:
    try:
        from weasyprint import HTML
        HTML(filename=html_path).write_pdf(pdf_path)
        return pdf_path
    except Exception:
        # WeasyPrint requires native GTK/Pango libs not available on all Windows setups.
        # The HTML report can be printed to PDF via the browser instead.
        return None


def save_json(report_data: dict, output_path: str) -> str:
    Path(output_path).write_text(
        json.dumps(report_data, indent=2, default=str), encoding="utf-8"
    )
    return output_path
