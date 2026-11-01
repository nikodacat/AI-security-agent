"""End-to-end evaluation driver: scan -> match -> analyze against one target.

Chains the pipeline stages so a single command produces the full verdicts
JSON + optional HTML report for a given eval-lab container:

  v1 stages (always on):
    1. `docker exec <container> python3 /opt/host-scanner/scan_target.py`
       -> raw host-scanner scan JSON
    2. Adapt scan.software.installed_apps -> cve-matcher inventory;
       run `cve_matcher.matcher.match(inventory, kev_catalog)`
       -> KEV findings (with optional NVD version-check)
    3. Adapt findings -> exposure-analyzer kev_findings shape;
       run `ExposureAgent.analyze_batch()` with `docker_exec_probe_runner`
       -> per-CVE verdicts JSON

  v2 stages (opt-in via flags, off by default so v1 tests keep working):
    P. --prober-target <target>  network-prober scan via eval-attacker;
                                 writes network_state.json + threads it into
                                 the analyzer as --network-state.
    S. --attack-simulator        attack_simulator narrate over verdicts.json;
                                 emits attack_narratives.{json,md}.
    F. --fix-publisher           fix_publisher publish over verdicts.json;
                                 emits remediations.{json,md}.
    R. --report <path>           analyzer --report -- attach Verdicts +
                                 (if attack + fix ran) Attack Narratives +
                                 Remediation Drafts sections in place.
    Shortcut: --v2  enables --prober-target=<container>, --attack-simulator,
              --fix-publisher, and creates a minimal report.html if --report
              is not given.

Usage:

    # v1-style: python eval-lab/run_full_scan.py --container eval-web-vuln --engine claude
    # v2-style: python eval-lab/run_full_scan.py --container eval-db-exposed --engine claude --v2

Emits under --out-dir (default eval-lab/reports/<container>/):
  - scan.json                  raw scan_target output
  - candidates.json            cve-matcher findings, kev_findings shape
  - host_state.json            trimmed scan for analyzer prompt
  - verdicts.json              analyzer output
  v2 only:
  - network_state.json         network-prober output (via eval-attacker)
  - attack_narratives.{json,md}  attack-simulator output
  - remediations.{json,md}     fix-publisher output
  - report.html                stitched HTML report (Verdicts + Attack + Fix)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(REPO_ROOT / "cve-matcher"))
sys.path.insert(0, str(REPO_ROOT / "exposure-analyzer"))

# v2 sibling packages — sys.path added so subprocess python invocations we spawn
# inherit PYTHONPATH via -m <module>. These packages are optional; if the paths
# don't exist the v2 flags emit a clean error.
_ATTACK_SIMULATOR_ROOT = REPO_ROOT / "attack-simulator"
_FIX_PUBLISHER_ROOT = REPO_ROOT / "fix-publisher"
_NETWORK_PROBER_ROOT = REPO_ROOT / "network-prober"
_NETWORK_SCHEMA_PATH = REPO_ROOT / "docs" / "schemas" / "network_state.schema.json"


_MINIMAL_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{container} — security assessment</title>
<style>
:root{{--bg:#0f172a;--surface:#1e293b;--surface2:#263044;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#38bdf8;}}
body{{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;max-width:1080px;margin:2rem auto;padding:0 1.5rem;color:var(--text);background:var(--bg);line-height:1.5;}}
h1{{margin:0 0 0.25rem;color:var(--text);}}h2{{margin-top:0;color:var(--accent);}}
h3{{margin-bottom:0.25rem;color:var(--text);}}h4{{margin-bottom:0.25rem;color:var(--muted);}}
.muted{{color:var(--muted);}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.25rem 1.5rem;margin:1rem 0;}}
.sev-counts{{display:flex;gap:0.5rem;flex-wrap:wrap;margin:0.5rem 0 1rem;}}
.sev-pill{{padding:0.25rem 0.6rem;border-radius:999px;font-size:0.85em;font-weight:600;}}
.sev-critical{{background:#dc2626;color:#fff;}}.sev-medium{{background:#ca8a04;color:#fff;}}
.sev-low{{background:#16a34a;color:#fff;}}.sev-info{{background:#2563eb;color:#fff;}}
.badge{{padding:0.15rem 0.5rem;border-radius:4px;font-size:0.85em;font-weight:600;}}
table{{border-collapse:collapse;width:100%;}}th,td{{text-align:left;padding:0.5rem 0.6rem;vertical-align:top;border-bottom:1px solid var(--border);}}
th{{background:var(--surface2);color:var(--muted);font-size:0.9em;}}
code{{background:var(--surface2);color:var(--text);padding:0.1rem 0.3rem;border-radius:3px;font-size:0.9em;}}
pre{{background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:0.5rem 0.8rem;overflow-x:auto;}}
</style></head><body>
<h1>{container} — security assessment</h1>
<p class="muted">Gray-box scan report generated by the AI-security-agent pipeline (v2).</p>
</body></html>
"""


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    from exposure_analyzer import settings as settings_mod
    from exposure_analyzer.ordering import order_for_budget
    try:
        cfg = settings_mod.load(args.settings, overrides={
            "engine": args.engine, "min_cvss": args.nvd_min_cvss, "per_product": args.per_product,
            "max_per_source": args.nvd_max_candidates, "max_calls": args.max_calls,
            "max_cost_usd": args.max_cost_usd,
            "use_banner": True if args.banner_candidates else None,
            "use_nvd": True if args.nvd_discovery else None,
            "use_osv": True if args.osv_discovery else None,
            "run_probes": False if args.no_probes else None,
            "prioritize": False if args.no_prioritize else None})
    except settings_mod.SettingsError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if cfg.engine == "openai":
        print("error: run_full_scan supports the fake and claude engines; use compare_arms for openai",
              file=sys.stderr)
        return 2
    args.engine = cfg.engine
    args.banner_candidates, args.nvd_discovery, args.osv_discovery = cfg.use_banner, cfg.use_nvd, cfg.use_osv

    # --v2 shortcut: turn on all three v2 stages + create a report if not given.
    if args.v2:
        if args.prober_target is None:
            args.prober_target = args.container
        args.attack_simulator = True
        args.fix_publisher = True
        if args.report is None:
            args.report = (args.out_dir or (HERE / "reports" / args.container)) / "report.html"

    out_dir: Path = args.out_dir or (HERE / "reports" / args.container)
    out_dir.mkdir(parents=True, exist_ok=True)

    scan_path = out_dir / "scan.json"
    candidates_path = out_dir / "candidates.json"
    host_state_path = out_dir / "host_state.json"
    verdicts_path = out_dir / "verdicts.json"
    network_state_path: Path | None = None
    attack_json_path: Path | None = None
    attack_md_path: Path | None = None
    remediations_json_path: Path | None = None
    remediations_md_path: Path | None = None

    print(f"[1/4] Scanning container {args.container!r} via docker exec ...")
    scan = _run_container_scan(args.container)
    scan_path.write_text(json.dumps(scan, indent=2, default=str), encoding="utf-8")
    apps = scan.get("scanners", {}).get("software", {}).get("installed_apps", [])
    print(f"      {len(apps)} installed packages captured -> {scan_path}")

    print(f"[2/4] Matching against KEV catalog ...")
    from cve_matcher import kev as kev_mod
    from cve_matcher import matcher as matcher_mod
    from cve_matcher.inventory import Inventory, Package

    inventory = _scan_to_inventory(args.container, scan)
    catalog = kev_mod.load()
    print(f"      KEV catalog: {len(catalog)} entries (v{catalog.catalog_version})")
    result = matcher_mod.match(inventory, catalog)
    print(f"      matched {len(result.findings)} candidate(s) from {inventory.host_os} inventory")

    if args.check_versions and result.findings:
        print(f"[2b/4] NVD version-check pass on {len({f.entry.cve_id for f in result.findings})} unique CVEs ...")

        def progress(i, total, cve):
            print(f"       [{i}/{total}] {cve}", flush=True)

        matcher_mod.enrich_with_versions(result.findings, on_progress=progress)

    kev_findings = [_finding_to_kev_finding(f) for f in result.findings]
    candidates_payload = {
        "schema_version": 1,
        "source": f"run_full_scan.py against {args.container}",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "kev_findings": kev_findings,
    }
    candidates_path.write_text(
        json.dumps(candidates_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"      wrote {len(kev_findings)} KEV finding(s) -> {candidates_path}")

    host_state = _derive_host_state(args.container, scan)
    host_state_path.write_text(json.dumps(host_state, indent=2, default=str), encoding="utf-8")

    # --------------------------------------------------------------- #
    # v2 prober stage (opt-in, must run before analyzer)              #
    # --------------------------------------------------------------- #
    if args.prober_target:
        network_state_path = out_dir / "network_state.json"
        print(f"[v2-4] Running network-prober against {args.prober_target!r} "
              f"via eval-attacker ...")
        rc = _run_network_prober(
            target=args.prober_target,
            output_path=network_state_path,
            ports=args.prober_ports,
        )
        if rc != 0:
            print(f"      network-prober failed (rc={rc}); "
                  f"analyzer will run without --network-state.", file=sys.stderr)
            network_state_path = None
        else:
            print(f"      wrote {network_state_path.name}")

    if args.banner_candidates or args.nvd_discovery or args.osv_discovery:
        from exposure_analyzer import candidates as cand_mod

        def _say(m: str) -> None:
            print(f"      {m}", file=sys.stderr)

        net_obs: list[dict[str, Any]] = []
        if network_state_path is not None:
            try:
                loaded = json.loads(network_state_path.read_text(encoding="utf-8"))
                net_obs = loaded if isinstance(loaded, list) else []
            except (json.JSONDecodeError, OSError):
                net_obs = []
        known = [f["cve_id"] for f in kev_findings]
        if args.banner_candidates:
            if net_obs:
                kev_findings += cand_mod.banner_candidates(net_obs, existing_cve_ids=known, log=_say)
            else:
                print("      warning: --banner-candidates needs a network_state "
                      "(--prober-target); skipped.", file=sys.stderr)
        if args.nvd_discovery:
            pkgs = list(inventory.packages) + cand_mod.banner_packages(cand_mod.banner_services(net_obs))
            kev_findings += cand_mod.nvd_candidates(
                pkgs, existing_cve_ids=[f["cve_id"] for f in kev_findings],
                min_cvss=cfg.min_cvss, per_product=cfg.per_product,
                max_total=cfg.max_per_source, log=_say)
        if args.osv_discovery:
            libs = scan.get("scanners", {}).get("software", {}).get("libraries", [])
            kev_findings += cand_mod.osv_candidates(
                libs, existing_cve_ids=[f["cve_id"] for f in kev_findings],
                min_cvss=cfg.min_cvss, per_product=cfg.per_product,
                max_total=cfg.max_per_source, log=_say)
        candidates_payload["kev_findings"] = kev_findings
        candidates_path.write_text(
            json.dumps(candidates_payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"      candidates after discovery: {len(kev_findings)} -> {candidates_path.name}")

    if not kev_findings:
        print("[3/4] No KEV candidates to analyze -- writing empty verdicts.json and exiting.")
        verdicts_path.write_text(
            json.dumps({"schema_version": 1, "verdicts": []}, indent=2),
            encoding="utf-8",
        )
        return 0

    print(f"[3/4] Running exposure-analyzer (engine={args.engine!r}"
          + (f", with network_state" if network_state_path else "")
          + ") ...")
    from exposure_analyzer.agent import (
        AgentConfig, CallBudget, ExposureAgent, build_claude_verdict_fn, docker_exec_probe_runner
    )
    from exposure_analyzer.verdicts import dump_verdicts

    # Load network_state if the prober ran.
    network_state: list[dict[str, Any]] | None = None
    if network_state_path is not None:
        try:
            network_state = json.loads(network_state_path.read_text(encoding="utf-8"))
            if not isinstance(network_state, list):
                print(f"      warning: network_state.json root is not a list; ignoring.",
                      file=sys.stderr)
                network_state = None
        except (json.JSONDecodeError, OSError) as e:
            print(f"      warning: could not read {network_state_path}: {e}", file=sys.stderr)
            network_state = None

    if args.engine == "claude":
        budget = CallBudget(max_calls=cfg.max_calls or None, max_cost_usd=cfg.max_cost_usd or None)
        verdict_fn = build_claude_verdict_fn(budget)
        agent_cfg = AgentConfig(run_probes=cfg.run_probes, probe_timeout_sec=cfg.probe_timeout_sec,
                                max_output_chars=cfg.max_output_chars)
        probe_runner = docker_exec_probe_runner(args.container, agent_cfg)
        agent = ExposureAgent(verdict_fn=verdict_fn, config=agent_cfg, probe_runner=probe_runner)
        if cfg.prioritize:  # the call cap must not starve the sources built last
            kev_findings = order_for_budget(kev_findings)
        try:
            verdicts = asyncio.run(
                agent.analyze_batch(kev_findings, host_state, network_state=network_state)
            )
        except Exception as e:
            print(f"      ERROR: analyzer failed: {type(e).__name__}: {e}", file=sys.stderr)
            return 1
        for cve_id, msg in agent.last_batch_errors:
            print(f"      WARNING: no verdict for {cve_id}: {msg}", file=sys.stderr)
        print(f"      model calls: {budget.calls}, spend ${budget.cost_usd:.3f}"
              + (f", STOPPED BY BUDGET ({agent.stopped_by_budget}); {len(kev_findings) - len(verdicts)} "
                 f"candidate(s) not judged" if agent.stopped_by_budget else ""))
    else:
        # Fake engine: cve-matcher passthrough. Still respects the v2 flow so
        # scaffolding tests can exercise the whole chain without Claude.
        from exposure_analyzer.cli import _fake_verdict
        verdicts = [_fake_verdict(f) for f in kev_findings]

    dump_verdicts(verdicts, verdicts_path)
    print(f"      wrote {len(verdicts)} verdict(s) -> {verdicts_path}")

    print(f"[4/4] Summary:")
    counts: dict[str, int] = {}
    for v in verdicts:
        counts[v.verdict.value] = counts.get(v.verdict.value, 0) + 1
    for verdict_name in ("CONFIRMED", "MITIGATED_BY_CONFIG", "MITIGATED_BY_EXPOSURE", "NOT_RUNNING", "NO_EVIDENCE"):
        n = counts.get(verdict_name, 0)
        if n:
            print(f"      {verdict_name:22s} {n}")

    # --------------------------------------------------------------- #
    # v2 stages                                                       #
    # --------------------------------------------------------------- #
    confirmed_count = counts.get("CONFIRMED", 0)

    if args.attack_simulator:
        if confirmed_count == 0:
            print("[v2-9] attack-simulator skipped — no CONFIRMED verdicts.")
        else:
            attack_json_path = out_dir / "attack_narratives.json"
            attack_md_path = out_dir / "attack_narratives.md"
            print(f"[v2-9] Running attack-simulator on {confirmed_count} CONFIRMED verdict(s) ...")
            rc = _run_attack_simulator(
                verdicts_path=verdicts_path,
                output_path=attack_json_path,
                markdown_path=attack_md_path,
                target=args.container,
                engine=args.engine,
            )
            if rc != 0:
                print(f"      attack-simulator failed (rc={rc}); skipping in-report injection.")
                attack_json_path = None
                attack_md_path = None
            else:
                print(f"      wrote {attack_json_path.name} + {attack_md_path.name}")

    if args.fix_publisher:
        if confirmed_count == 0:
            print("[v2-10] fix-publisher skipped — no CONFIRMED verdicts.")
        else:
            remediations_json_path = out_dir / "remediations.json"
            remediations_md_path = out_dir / "remediations.md"
            print(f"[v2-10] Running fix-publisher on {confirmed_count} CONFIRMED verdict(s) ...")
            rc = _run_fix_publisher(
                verdicts_path=verdicts_path,
                output_path=remediations_json_path,
                markdown_path=remediations_md_path,
                target=args.container,
                engine=args.engine,
            )
            if rc != 0:
                print(f"      fix-publisher failed (rc={rc}); skipping in-report injection.")
                remediations_json_path = None
                remediations_md_path = None
            else:
                print(f"      wrote {remediations_json_path.name} + {remediations_md_path.name}")

    if args.report is not None:
        report_path: Path = args.report
        if not report_path.exists():
            print(f"[v2-11] Creating minimal report at {report_path} ...")
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(
                _MINIMAL_REPORT_TEMPLATE.format(container=args.container),
                encoding="utf-8",
            )
        print(f"[v2-11] Injecting sections into {report_path} ...")
        # Use exposure_analyzer.report directly since it's already on sys.path.
        from exposure_analyzer.report import append_verdicts_to_report
        append_verdicts_to_report(
            verdicts,
            report_path,
            attack_narratives_path=attack_json_path,
            remediations_path=remediations_json_path,
        )
        sections = ["Verdicts"]
        if attack_json_path:
            sections.append("Attack Narratives")
        if remediations_json_path:
            sections.append("Remediation Drafts")
        print(f"      appended {' + '.join(sections)} section(s)")

    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="run_full_scan.py",
                                description="End-to-end scan+match+analyze for one eval-lab container.")
    p.add_argument("--container", required=True,
                   help="Target container name (e.g. eval-web-vuln).")
    p.add_argument("--engine", choices=("fake", "claude"), default=None,
                   help="Verdict engine. Default: claude (real Agent SDK).")
    p.add_argument("--settings", type=Path, default=None,
                   help="JSON file of tunables (see exposure_analyzer.settings); explicit flags win over it.")
    p.add_argument("--max-calls", type=int, default=None,
                   help="Hard cap on model calls (0 = none). Each candidate costs one call. Default 60.")
    p.add_argument("--max-cost-usd", type=float, default=None,
                   help="Hard cap on spend as reported by the SDK (0 = none). Default 2.0.")
    p.add_argument("--no-prioritize", action="store_true",
                   help="Judge candidates in discovery order instead of KEV-first, sources in rotation.")
    p.add_argument("--check-versions", action="store_true",
                   help="Run cve-matcher's NVD version-check pass. Slower.")
    p.add_argument("--no-probes", action="store_true",
                   help="Skip probe execution (analyzer decides from candidate+host_state only).")
    p.add_argument("--out-dir", type=Path, default=None,
                   help="Output directory. Default: eval-lab/reports/<container>/")

    # v2 stages — opt-in.
    p.add_argument("--v2", action="store_true",
                   help="Turn on all v2 stages: --prober-target=<container>, --attack-simulator, "
                        "--fix-publisher, and auto-create a minimal report.html if --report absent.")
    p.add_argument("--prober-target", default=None,
                   help="Enable network-prober stage. Value is the target hostname to scan from "
                        "the eval-attacker container (usually same as --container).")
    p.add_argument("--prober-ports", default="22,80,443,3306,6379,8000-8100",
                   help="Comma-separated ports for network-prober -p (default covers the eval-lab set). "
                        "Format matches nmap -p syntax.")
    p.add_argument("--banner-candidates", action="store_true",
                   help="v3-1: also analyse CVEs matched from service banners (needs --prober-target).")
    p.add_argument("--nvd-discovery", action="store_true",
                   help="v3-2 (experimental): also analyse CVEs NVD lists for the detected software, "
                        "beyond CISA KEV. Needs network access to NVD; see --nvd-min-cvss.")
    p.add_argument("--nvd-min-cvss", type=float, default=None,
                   help="With --nvd-discovery: only CVEs at or above this CVSS base score (default 7.0).")
    p.add_argument("--osv-discovery", action="store_true",
                   help="v3-7 (experimental): also analyse CVEs OSV.dev lists for every library the "
                        "scanner found (jar, Composer, npm, PyPI), looked up by package coordinates.")
    p.add_argument("--nvd-max-candidates", type=int, default=None,
                   help="With --nvd-discovery / --osv-discovery: safety cap per discovery source "
                        "(default 60; each candidate costs one model call).")
    p.add_argument("--per-product", type=int, default=None,
                   help="With --nvd-discovery / --osv-discovery: at most this many candidates per "
                        "product or library, so one noisy product cannot crowd out the rest (default 15).")
    p.add_argument("--attack-simulator", action="store_true",
                   help="Run attack-simulator after the analyzer to produce attack_narratives.{json,md}.")
    p.add_argument("--fix-publisher", action="store_true",
                   help="Run fix-publisher after the analyzer to produce remediations.{json,md}.")
    p.add_argument("--report", type=Path, default=None,
                   help="HTML report path. If it exists, sections are injected in-place. "
                        "If missing and --v2 is set, a minimal template is created first.")
    return p


def _run_network_prober(*, target: str, output_path: Path, ports: str) -> int:
    """Invoke network-prober inside the eval-attacker container.

    Assumes `eval-attacker` is up (via `docker compose up -d`). Writes to
    /prober-output/<target>.json inside the container (bind-mounted to
    ./prober-output/) then copies it to the final output_path.
    """
    if not _NETWORK_PROBER_ROOT.exists():
        print(f"      network-prober package not found at {_NETWORK_PROBER_ROOT}", file=sys.stderr)
        return 3
    in_container_out = f"/prober-output/{target}.net.json"
    env = dict(os.environ); env["MSYS_NO_PATHCONV"] = "1"
    cmd = [
        "docker", "exec", "eval-attacker",
        "python", "-m", "network_prober", "scan",
        "--target", target,
        "--ports", ports,
        "--output", in_container_out,
        "--schema", "/repo/docs/schemas/network_state.schema.json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          check=False, env=env, timeout=180)
    if proc.returncode != 0:
        stderr = proc.stderr[:1500] if proc.stderr else "(no stderr)"
        print(f"      docker exec eval-attacker failed:\n{stderr}", file=sys.stderr)
        return proc.returncode

    # Copy the prober's output from the bind-mount to the caller-specified path.
    bind_mount = HERE / "prober-output" / f"{target}.net.json"
    if not bind_mount.exists():
        print(f"      prober output not found at {bind_mount}", file=sys.stderr)
        return 4
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(bind_mount.read_text(encoding="utf-8"), encoding="utf-8")
    return 0


def _run_attack_simulator(
    *, verdicts_path: Path, output_path: Path, markdown_path: Path,
    target: str, engine: str,
) -> int:
    """Invoke `python -m attack_simulator narrate`."""
    if not _ATTACK_SIMULATOR_ROOT.exists():
        print(f"      attack-simulator not found at {_ATTACK_SIMULATOR_ROOT}", file=sys.stderr)
        return 3
    env = dict(os.environ); env["MSYS_NO_PATHCONV"] = "1"
    env["PYTHONPATH"] = str(_ATTACK_SIMULATOR_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [
        sys.executable, "-m", "attack_simulator", "narrate",
        "--verdicts", str(verdicts_path),
        "--output", str(output_path),
        "--markdown", str(markdown_path),
        "--target", target,
        "--engine", engine,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          check=False, env=env, timeout=600)
    if proc.returncode != 0:
        print(f"      {proc.stderr[:1500]}", file=sys.stderr)
    return proc.returncode


def _run_fix_publisher(
    *, verdicts_path: Path, output_path: Path, markdown_path: Path,
    target: str, engine: str,
) -> int:
    """Invoke `python -m fix_publisher publish`."""
    if not _FIX_PUBLISHER_ROOT.exists():
        print(f"      fix-publisher not found at {_FIX_PUBLISHER_ROOT}", file=sys.stderr)
        return 3
    env = dict(os.environ); env["MSYS_NO_PATHCONV"] = "1"
    env["PYTHONPATH"] = str(_FIX_PUBLISHER_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [
        sys.executable, "-m", "fix_publisher", "publish",
        "--verdicts", str(verdicts_path),
        "--output", str(output_path),
        "--markdown", str(markdown_path),
        "--target", target,
        "--engine", engine,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          check=False, env=env, timeout=600)
    if proc.returncode != 0:
        print(f"      {proc.stderr[:1500]}", file=sys.stderr)
    return proc.returncode


def _run_container_scan(container: str) -> dict[str, Any]:
    """Invoke scan_target.py inside the container via docker exec."""
    env = dict(os.environ)
    env["MSYS_NO_PATHCONV"] = "1"  # git-bash on Windows mangles /opt/... paths otherwise
    proc = subprocess.run(
        ["docker", "exec", container, "python3", "/opt/host-scanner/scan_target.py"],
        capture_output=True, text=True, check=False, timeout=180, env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"scan_target.py failed in {container}: rc={proc.returncode}\n"
            f"stderr:\n{proc.stderr[:2000]}"
        )
    return json.loads(proc.stdout)


def _scan_to_inventory(container: str, scan: dict[str, Any]):
    """Adapter: host-scanner scanners.software.installed_apps -> cve-matcher Inventory."""
    from cve_matcher.inventory import Inventory, Package

    apps = scan.get("scanners", {}).get("software", {}).get("installed_apps", [])
    packages = [
        Package(
            name=a.get("DisplayName", ""),
            version=a.get("DisplayVersion", ""),
            vendor=(a.get("Publisher") or "").split("<")[0].strip(),
            # Unmanaged-binary / ecosystem apps carry their own KEV-style
            # Product and Source; dpkg apps have neither.
            product=a.get("Product") or a.get("DisplayName", ""),
            source=a.get("Source") or "dpkg (via host-scanner)",
            cpe=a.get("Cpe") or "",
        )
        for a in apps
        if a.get("DisplayName")
    ]
    system = scan.get("system", {})
    return Inventory(
        scanned_at=system.get("scan_time", ""),
        host_os=f"linux (container: {container})",
        host_version=system.get("platform", ""),
        packages=packages,
    )


def _finding_to_kev_finding(finding) -> dict[str, Any]:
    """Adapter: cve-matcher Finding -> exposure-analyzer kev_findings entry."""
    entry = finding.entry
    return {
        "cve_id": entry.cve_id,
        "kev_name": entry.name,
        "kev_vendor": entry.vendor,
        "kev_product": entry.product,
        "kev_description": entry.description,
        "cwes": [],
        "package_name": finding.package.name,
        "package_version": finding.package.version,
        "package_vendor": finding.package.vendor,
        "package_source": getattr(finding.package, "source", ""),
        "match_reason": finding.match_reason,
        "match_score": finding.match_score,
        "verdict": finding.verdict,
        "verdict_detail": finding.verdict_detail,
        "ransomware_linked": entry.ransomware,
    }


def _derive_host_state(container: str, scan: dict[str, Any]) -> dict[str, Any]:
    """Squeeze the scan blob down to the parts the analyzer actually reasons over.

    We deliberately drop noisy per-package inventory (kept in candidates.json) and
    keep OS / processes / listening ports / config-adjacent snippets.
    """
    scanners = scan.get("scanners", {})
    system = scanners.get("system", {})
    procs = scanners.get("processes", {})
    users = scanners.get("users", {})

    from exposure_analyzer.hoststate import summarize_services

    state = {
        "container": container,
        "system": {
            "hostname": scan.get("system", {}).get("hostname"),
            "platform": scan.get("system", {}).get("platform"),
            "os_info": system.get("os_info", {}),
        },
        "process_summary": {
            k: procs.get(k)
            for k in ("running_process_count", "top_by_cpu", "top_by_memory")
            if k in procs
        },
        "user_summary": {
            k: users.get(k)
            for k in ("user_count", "users_with_shell", "root_uid_zero_accounts")
            if k in users
        },
    }
    services = summarize_services(scanners.get("services"))
    if services:
        state["services"] = services
    return state


if __name__ == "__main__":
    raise SystemExit(main())
