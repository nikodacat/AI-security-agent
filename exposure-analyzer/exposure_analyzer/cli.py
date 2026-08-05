"""CLI entry point for `python -m exposure_analyzer`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="exposure-analyzer",
        description=(
            "Gray-box impact analysis for CVE candidates. Consumes "
            "cve-matcher output + host-scanner state, emits per-CVE verdicts."
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = p.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser(
        "analyze",
        help="Run analysis on a set of candidate CVEs.",
    )
    p_analyze.add_argument(
        "--candidates",
        type=Path,
        required=True,
        help="Path to cve-matcher output JSON (kev_findings array).",
    )
    p_analyze.add_argument(
        "--host-state",
        type=Path,
        required=True,
        help="Path to host-scanner output JSON (full scan result).",
    )
    p_analyze.add_argument(
        "--output",
        type=Path,
        default=Path("reports") / "verdicts.json",
        help="Where to write the verdicts JSON. Default: reports/verdicts.json",
    )
    p_analyze.add_argument(
        "--batch",
        action="store_true",
        help="Non-interactive: auto-answer probe prompts. Default is interactive.",
    )

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "analyze":
        # Placeholder — chunk D wires the real ExposureAgent invocation here.
        print(f"exposure-analyzer {__version__} (scaffold)")
        print(f"  candidates : {args.candidates}")
        print(f"  host-state : {args.host_state}")
        print(f"  output     : {args.output}")
        print(f"  mode       : {'batch' if args.batch else 'interactive'}")
        print()
        print("NOT YET IMPLEMENTED — this is the scaffold from chunk B.")
        print("Real analysis lives in chunks D-F (see docs/ROADMAP.md).")
        return 0

    print(f"unknown command: {args.command}", file=sys.stderr)
    return 2
