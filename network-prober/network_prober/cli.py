"""CLI entry point for ``python -m network_prober``.

    python -m network_prober scan \\
        --target eval-web-vuln \\
        --target eval-db-exposed \\
        --target eval-cms-plugin \\
        --output /prober-output/network_state.json

Emits a JSON file conforming to ``docs/schemas/network_state.schema.json``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="network-prober",
        description=(
            "External-scan phase. Runs nmap+banner-grab against each target and emits "
            "a network_state.json conforming to docs/schemas/network_state.schema.json."
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = p.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan target(s) and emit network_state.json")
    p_scan.add_argument(
        "--target",
        type=str,
        action="append",
        required=True,
        dest="targets",
        help="hostname or IP to scan; repeat for multiple targets",
    )
    p_scan.add_argument(
        "--output",
        type=Path,
        required=True,
        help="path to write network_state.json",
    )
    p_scan.add_argument(
        "--top-ports",
        type=int,
        default=100,
        help="number of top-ranked TCP ports to scan (nmap --top-ports). Ignored when --ports is set.",
    )
    p_scan.add_argument(
        "--ports",
        type=str,
        default=None,
        help=(
            "explicit port list/range to scan (nmap -p syntax, e.g. '80,443,6379,8000-8100'). "
            "Overrides --top-ports. Real-world targets often have services on ports outside nmap's "
            "top-N ranking (e.g. Redis on 6379 is not in top-1000) -- use --ports when you know "
            "what to look for."
        ),
    )
    p_scan.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="per-target nmap timeout in seconds",
    )
    p_scan.add_argument(
        "--schema",
        type=str,
        default="docs/schemas/network_state.schema.json",
        help=(
            "path to network_state schema for output validation; "
            "set to empty string to skip validation"
        ),
    )

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help(sys.stderr)
        return 2

    # Deferred imports so `python -m network_prober --help` works without
    # python-nmap installed on the caller's machine.
    from .emitter import emit_network_state
    from .prober import ProberDependencyError, scan_targets

    try:
        scan_results = scan_targets(
            args.targets,
            top_ports=args.top_ports,
            timeout=args.timeout,
            ports=args.ports,
        )
    except ProberDependencyError as e:
        sys.stderr.write(f"network-prober: {e}\n")
        return 3

    schema_path = args.schema if args.schema else None
    try:
        observations = emit_network_state(
            scan_results,
            output_path=args.output,
            schema_path=schema_path,
        )
    except Exception as e:
        # jsonschema.ValidationError, PermissionError, etc. Surface then bail.
        sys.stderr.write(f"network-prober: emit failed: {type(e).__name__}: {e}\n")
        return 4

    reachable = sum(1 for o in observations if o["reachable"])
    sys.stderr.write(
        f"network-prober: wrote {len(observations)} observations "
        f"({reachable} reachable) to {args.output}\n"
    )
    for target, data in scan_results.items():
        if data.get("error"):
            sys.stderr.write(f"  warning: {target}: {data['error']}\n")
    return 0
