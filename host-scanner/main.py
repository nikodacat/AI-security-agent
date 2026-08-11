"""HomeSecAI - CLI entry point."""

import json
import os
import platform
import socket
import sys
from datetime import datetime
from pathlib import Path

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


_DEFAULT_CONFIG = Path(__file__).resolve().parent / "config.yaml"


def load_config(path: str | Path | None = None) -> dict:
    """Load host-scanner config.

    Defaults to the config.yaml living alongside this file, so the scanner
    works no matter where the caller cd'd from (previously required cwd to
    be host-scanner/ — see docs/VERIFICATION.md).
    """
    p = Path(path) if path is not None else _DEFAULT_CONFIG
    with open(p, "r") as f:
        return yaml.safe_load(f)


def collect_system_info() -> dict:
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "scan_time": datetime.now().isoformat(),
    }


def run_scan(cfg: dict) -> dict:
    from core.scanner import run_all_cli
    console.print(Panel("[bold cyan]HomeSecAI - Security Scanner[/bold cyan]\nStarting all modules...", expand=False))
    return run_all_cli(cfg)


def analyze_with_claude(scan_results: dict, system_info: dict, cfg: dict) -> tuple[dict, dict]:
    from core.claude_engine import analyze_all

    claude_cfg = cfg.get("claude", {})

    # Show which scanners are queued for analysis.
    ok_names = [n for n, d in scan_results.items() if not (isinstance(d, dict) and d.get("status") == "error")]
    skipped = [n for n in scan_results if n not in ok_names]

    console.print("\n[bold yellow]Analyzing findings with Claude (batched, single call)...[/bold yellow]")
    for n in ok_names:
        console.print(f"  Queued [cyan]{n}[/cyan]")
    for n in skipped:
        console.print(f"  [red]Skipping {n} (scan error)[/red]")

    try:
        analyses, executive = analyze_all(scan_results, system_info, claude_cfg)
    except Exception as e:
        console.print(f"\n[red]Claude analysis failed: {e}[/red]")
        return {}, {}

    # Report per-scanner outcomes.
    for name in ok_names:
        a = analyses.get(name)
        if a is None:
            console.print(f"  [yellow]No analysis returned for {name}[/yellow]")
            continue
        score = a.get("score", "?")
        finding_count = len(a.get("findings", []) or [])
        console.print(f"  [cyan]{name}[/cyan] -> score={score}/100  findings={finding_count}")

    return analyses, executive


def print_summary(executive: dict):
    grade = executive.get("grade", "?")
    score = executive.get("overall_score", 0)
    color = "green" if score >= 75 else ("yellow" if score >= 50 else "red")

    console.print()
    console.print(Panel(
        f"[bold {color}]Security Grade: {grade}  ({score}/100)[/bold {color}]\n\n"
        f"{executive.get('headline', '')}\n\n"
        "[bold]Top Risks:[/bold]\n" +
        "\n".join(f"  - {r}" for r in executive.get("top_risks", [])) +
        "\n\n[bold]Quick Wins:[/bold]\n" +
        "\n".join(f"  - {q}" for q in executive.get("quick_wins", [])),
        title="Executive Summary",
        expand=False,
    ))


def save_outputs(scan_results: dict, analyses: dict, executive: dict, cfg: dict):
    from core.report import build_report_data, render_html, render_pdf, save_json

    out_dir = Path(cfg.get("report", {}).get("output_dir", "reports"))
    out_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Save raw JSON
    raw_path = out_dir / f"raw_{ts}.json"
    save_json({"scan_results": scan_results, "analyses": analyses, "executive": executive}, str(raw_path))
    console.print(f"\n  Raw JSON: [dim]{raw_path}[/dim]")

    # Build report data
    report_data = build_report_data(scan_results, analyses, executive)

    # HTML report
    html_path = out_dir / f"report_{ts}.html"
    render_html(report_data, str(html_path))
    console.print(f"  HTML report: [bold green]{html_path}[/bold green]")

    # PDF (optional)
    formats = cfg.get("report", {}).get("formats", ["html"])
    if "pdf" in formats:
        pdf_path = out_dir / f"report_{ts}.pdf"
        result = render_pdf(str(html_path), str(pdf_path))
        if result:
            console.print(f"  PDF report: [bold green]{pdf_path}[/bold green]")
        else:
            console.print("  [yellow]PDF skipped - weasyprint not available[/yellow]")

    return str(html_path)


def main():
    cfg = load_config()
    system_info = collect_system_info()

    scan_results = run_scan(cfg)
    analyses, executive = analyze_with_claude(scan_results, system_info, cfg)

    # Save first — so the report is always written even if display fails.
    html_path = save_outputs(scan_results, analyses, executive, cfg)

    try:
        print_summary(executive)
    except UnicodeEncodeError:
        console.print("\n[yellow]Summary display skipped (terminal encoding issue). See HTML report.[/yellow]")

    console.print(f"\n[bold green]Done![/bold green] Open report: [link=file://{Path(html_path).resolve()}]{html_path}[/link]\n")


if __name__ == "__main__":
    main()
