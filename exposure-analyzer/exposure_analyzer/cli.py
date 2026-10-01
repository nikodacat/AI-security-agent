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

from . import __version__, hitl
from .agent import (
    AgentConfig,
    ExposureAgent,
    build_claude_verdict_fn,
    docker_exec_probe_runner,
)
from .proposal import build_claude_proposer_fn
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
    p_analyze.add_argument("--attack-narratives", type=Path, default=None,
                           help="Optional path to attack_narratives.json from attack-simulator (v2-9). "
                                "When set together with --report, adds an Attack Narratives section.")
    p_analyze.add_argument("--remediations", type=Path, default=None,
                           help="Optional path to remediations.json from fix-publisher (v2-10). "
                                "When set together with --report, adds a Remediation Drafts section.")
    p_analyze.add_argument("--engine", choices=("fake", "claude"), default="fake",
                           help="Verdict engine. fake=cve-matcher passthrough (default); "
                                "claude=ExposureAgent via claude-agent-sdk.")
    p_analyze.add_argument("--no-probes", action="store_true",
                           help="Skip probe execution (claude engine only). "
                                "Useful when host-state is imported from another machine.")
    p_analyze.add_argument("--propose-probes", action="store_true", default=False,
                           help="Ask LLM to propose a non-destructive probe when no "
                                "known probe exists for a CVE (claude engine only).")
    p_analyze.add_argument("--target-container", default=None,
                           help="Run probes inside a docker container via `docker exec` "
                                "instead of on the local machine. Use for eval-lab runs "
                                "(e.g. --target-container=eval-web-vuln).")
    p_analyze.add_argument("--network-state", type=Path, default=None,
                           help="v2 external-attacker input: path to a network_state.json "
                                "produced by network-prober. Schema-validated on load. "
                                "Omit to run in v1 mode (no external leg) — this is what "
                                "the v2 delta baseline uses.")
    p_analyze.add_argument("--network-state-schema", type=Path,
                           default=Path("docs/schemas/network_state.schema.json"),
                           help="Schema used to validate --network-state input. Override "
                                "when running from a directory where the default relative "
                                "path doesn't resolve.")
    p_analyze.add_argument("--auto-approve-known", action="store_true", default=False,
                           help="Auto-approves proposals whose argv_hash matches a "
                                "learned_probes.jsonl entry.")
    p_analyze.add_argument("--auto-approve-all-unsafe", action="store_true", default=False,
                           help="Bypasses HITL entirely.")
    p_analyze.add_argument("--learned-probes-path", type=Path,
                           default=hitl.DEFAULT_LEARNED_PROBES_PATH,
                           help="Override the sidecar location. "
                                f"Default: {hitl.DEFAULT_LEARNED_PROBES_PATH}")
    p_analyze.add_argument("--no-learn", action="store_true", default=False,
                           help="Don't append newly-approved probes to the JSONL.")
    # --batch removed in chunk F (2026-08-10): was a no-op wired to
    # AgentConfig.interactive, which the analyzer never actually consumed.
    # See ROADMAP.md chunk F for the design decision.

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

    network_state: list[dict[str, Any]] | None = None
    if args.network_state is not None:
        rc = _load_network_state(args)
        if isinstance(rc, int):
            return rc
        network_state = rc

    if args.engine == "fake":
        verdicts = [_fake_verdict(f) for f in kev_findings]
        engine_label = "fake (cve-matcher passthrough, no AI)"
    else:
        try:
            verdict_fn = build_claude_verdict_fn()
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        agent_cfg = AgentConfig(run_probes=not args.no_probes)
        probe_runner = None
        if args.target_container:
            probe_runner = docker_exec_probe_runner(args.target_container, agent_cfg)
        probe_proposer = None
        approval_gate = None
        learned_probes_path = None
        if args.propose_probes:
            try:
                probe_proposer = build_claude_proposer_fn()
            except RuntimeError as e:
                print(f"error: {e}", file=sys.stderr)
                return 1
            learned = hitl.load_learned_probes(args.learned_probes_path)
            approval_gate = hitl.ApprovalGate(
                learned=learned,
                auto_approve_known=args.auto_approve_known,
                auto_approve_all_unsafe=args.auto_approve_all_unsafe,
                interactive=hitl.stdin_is_tty(),
            )
            learned_probes_path = None if args.no_learn else args.learned_probes_path
        agent = ExposureAgent(
            verdict_fn=verdict_fn,
            config=agent_cfg,
            probe_runner=probe_runner,
            probe_proposer=probe_proposer,
            approval_gate=approval_gate,
            learned_probes_path=learned_probes_path,
            target_container=args.target_container,
        )
        try:
            verdicts = asyncio.run(
                agent.analyze_batch(kev_findings, host_state, network_state=network_state)
            )
        except Exception as e:
            print(f"error: analyzer failed: {type(e).__name__}: {e}", file=sys.stderr)
            return 1
        engine_label = "claude (via claude-agent-sdk)"
        if args.propose_probes:
            engine_label += " + probe-proposer"
            if args.auto_approve_all_unsafe:
                engine_label += " + AUTO-APPROVE-ALL-UNSAFE"
            elif args.auto_approve_known:
                engine_label += f" + auto-approve-known({len(learned)})"
            elif hitl.stdin_is_tty():
                engine_label += " + HITL(interactive)"
            else:
                engine_label += " + HITL(non-TTY default-deny)"
        if network_state is not None:
            engine_label += f" + network_state ({len(network_state)} obs)"

    output_path: Path = args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    dump_verdicts(verdicts, output_path)

    print(f"exposure-analyzer {__version__} -- engine: {engine_label}")
    print(f"  wrote {len(verdicts)} verdict(s) to {output_path}")
    print()
    print(render_verdicts_summary(verdicts))

    if args.report is not None:
        append_verdicts_to_report(
            verdicts,
            args.report,
            attack_narratives_path=args.attack_narratives,
            remediations_path=args.remediations,
        )
        print()
        appended = ["Verdicts"]
        if args.attack_narratives is not None:
            appended.append("Attack Narratives")
        if args.remediations is not None:
            appended.append("Remediation Drafts")
        print(f"  appended {' + '.join(appended)} section(s) to {args.report}")

    return 0


def _load_network_state(args: argparse.Namespace) -> list[dict[str, Any]] | int:
    """Read and schema-validate ``--network-state`` input.

    Returns the observations list on success, or a CLI exit code on failure.
    Validation is best-effort: if the schema file is missing (e.g. the user
    is running from a directory where the default relative path doesn't
    resolve) we still load the JSON but log a warning — better to run
    unvalidated than to hard-fail when the operator has valid data.
    """
    ns_path: Path = args.network_state
    if not ns_path.exists():
        print(f"error: network-state file not found: {ns_path}", file=sys.stderr)
        return 1
    try:
        observations = json.loads(ns_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"error: network-state is not valid JSON: {e}", file=sys.stderr)
        return 1
    if not isinstance(observations, list):
        print(
            "error: network-state must be a JSON array of PortObservation records; "
            f"got {type(observations).__name__}",
            file=sys.stderr,
        )
        return 1

    schema_path: Path = args.network_state_schema
    if schema_path.exists():
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            print(
                "warning: jsonschema not installed; skipping network-state validation. "
                "Install with `pip install jsonschema` for stricter loading.",
                file=sys.stderr,
            )
        else:
            try:
                schema = json.loads(schema_path.read_text(encoding="utf-8"))
                Draft202012Validator(schema).validate(observations)
            except Exception as e:
                print(
                    f"error: network-state failed schema validation: "
                    f"{type(e).__name__}: {e}",
                    file=sys.stderr,
                )
                return 1
    else:
        print(
            f"warning: schema not found at {schema_path}; loading network-state "
            "without validation. Pass --network-state-schema to override the path.",
            file=sys.stderr,
        )

    return observations


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
