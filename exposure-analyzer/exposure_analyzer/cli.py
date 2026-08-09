"""CLI entry point for `python -m exposure_analyzer`.

Two engines are available:

  --engine=fake    (default when no probe SDK is desired) uses cve-matcher's
                   own verdict as a stand-in and runs no probes. Cheap and
                   deterministic; used by chunk C plumbing tests.
  --engine=claude  wires ExposureAgent through claude-agent-sdk. Runs the
                   registered probe for each CVE, sends output + candidate +
                   host state to Claude, and parses the returned verdict.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .agent import (
    AgentConfig,
    ExposureAgent,
    build_claude_verdict_fn,
    docker_exec_probe_runner,
)
from .report import append_verdicts_to_report, render_verdicts_summary
from .verdicts import Verdict, VerdictType, dump_verdicts


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

    p_analyze = sub.add_parser("analyze", help="Run analysis on a set of candidate CVEs.")
    p_analyze.add_argument("--candidates", type=Path, required=True,
                           help="Path to cve-matcher output JSON (kev_findings array).")
    p_analyze.add_argument("--host-state", type=Path, required=False, default=None,
                           help="Path to host-scanner output JSON. Empty dict if omitted.")
    p_analyze.add_argument("--output", type=Path, default=Path("reports") / "verdicts.json",
                           help="Where to write the verdicts JSON. Default: reports/verdicts.json")
    p_analyze.add_argument("--report", type=Path, default=None,
                           help="Optional existing host-scanner HTML report to append verdicts to.")
    p_analyze.add_argument("--engine", choices=("fake", "claude"), default="fake",
                           help="Verdict engine. fake=cve-matcher passthrough (default); "
                                "claude=ExposureAgent via claude-agent-sdk.")
    p_analyze.add_argument("--no-probes", action="store_true",
                           help="Skip probe execution (claude engine only). "
                                "Useful when host-state is imported from another machine.")
    p_analyze.add_argument("--target-container", default=None,
                           help="Run probes inside a docker container via `docker exec` "
                                "instead of on the local machine. Use for eval-lab runs "
                                "(e.g. --target-container=eval-web-vuln).")
    p_analyze.add_argument("--batch", action="store_true",
                           help="Non-interactive: auto-answer probe prompts. Default is interactive.")

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        return _cmd_analyze(args)
    print(f"unknown command: {args.command}", file=sys.stderr)
    return 2


def _cmd_analyze(args: argparse.Namespace) -> int:
    candidates_path: Path = args.candidates
    if not candidates_path.exists():
        print(f"error: candidates file not found: {candidates_path}", file=sys.stderr)
        return 1

    payload = json.loads(candidates_path.read_text(encoding="utf-8"))
    kev_findings = payload.get("kev_findings", [])

    host_state: dict[str, Any] = {}
    if args.host_state is not None:
        if not args.host_state.exists():
            print(f"error: host-state file not found: {args.host_state}", file=sys.stderr)
            return 1
        host_state = json.loads(args.host_state.read_text(encoding="utf-8"))

    if args.engine == "fake":
        verdicts = [_fake_verdict(f) for f in kev_findings]
        engine_label = "fake (cve-matcher passthrough, no AI)"
    else:
        try:
            verdict_fn = build_claude_verdict_fn()
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        agent_cfg = AgentConfig(interactive=not args.batch, run_probes=not args.no_probes)
        probe_runner = None
        if args.target_container:
            probe_runner = docker_exec_probe_runner(args.target_container, agent_cfg)
        agent = ExposureAgent(
            verdict_fn=verdict_fn,
            config=agent_cfg,
            probe_runner=probe_runner,
        )
        try:
            verdicts = asyncio.run(agent.analyze_batch(kev_findings, host_state))
        except Exception as e:
            print(f"error: analyzer failed: {type(e).__name__}: {e}", file=sys.stderr)
            return 1
        engine_label = "claude (via claude-agent-sdk)"

    output_path: Path = args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    dump_verdicts(verdicts, output_path)

    print(f"exposure-analyzer {__version__} -- engine: {engine_label}")
    print(f"  wrote {len(verdicts)} verdict(s) to {output_path}")
    print()
    print(render_verdicts_summary(verdicts))

    if args.report is not None:
        append_verdicts_to_report(verdicts, args.report)
        print()
        print(f"  appended Verdicts section to {args.report}")

    return 0


def _fake_verdict(finding: dict) -> Verdict:
    """Deterministic verdict derived from cve-matcher's own output. No AI, no probes."""
    cve_id = finding.get("cve_id", "CVE-UNKNOWN")
    matcher_verdict = finding.get("verdict", "")
    detail = finding.get("verdict_detail", "")

    if matcher_verdict == "vulnerable":
        vt = VerdictType.CONFIRMED
        reason = (
            f"cve-matcher flagged this as vulnerable ({detail}). "
            "No exposure probes have been executed (fake engine)."
        )
    else:
        vt = VerdictType.NO_EVIDENCE
        reason = f"No probe evidence gathered (matcher verdict: {matcher_verdict or 'unknown'})."

    return Verdict(
        cve_id=cve_id,
        verdict=vt,
        reason=reason,
        evidence={
            "kev_name": finding.get("kev_name", ""),
            "package": f"{finding.get('package_name', '')} {finding.get('package_version', '')}".strip(),
            "matcher_verdict": matcher_verdict,
            "matcher_detail": detail,
        },
    )
