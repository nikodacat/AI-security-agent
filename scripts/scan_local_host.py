"""Local-host equivalent of eval-lab/run_full_scan.py.

Invoked from scripts/scan-local-host.sh. Uses the same three-module chain
(host-scanner -> cve-matcher -> exposure-analyzer) but:
  - runs host-scanner directly on the host (no `docker exec`)
  - uses the local probe runner (no docker), so probes see the host's
    actual binaries and config
  - appends verdicts to the host-scanner HTML report in place

Keeps the eval-lab driver focused on containerized targets; keeps this
one focused on real-server deployment.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "cve-matcher"))
sys.path.insert(0, str(REPO_ROOT / "exposure-analyzer"))
sys.path.insert(0, str(REPO_ROOT / "host-scanner"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="scan_local_host.py",
                                description="End-to-end CVE scan of the local host.")
    p.add_argument("--engine", choices=("fake", "claude"), default="claude")
    p.add_argument("--check-versions", action="store_true")
    p.add_argument("--out-dir", type=Path, required=True)
    args = p.parse_args(argv)

    args.out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Run host-scanner in-process (no Claude analysis pass -- that's
    #    the exposure-analyzer's job; we don't want it running twice).
    print(f"[1/4] Running host-scanner on the local host ...")
    scan = _run_host_scanner()
    scan_path = args.out_dir / "scan.json"
    scan_path.write_text(json.dumps(scan, indent=2, default=str), encoding="utf-8")
    apps = scan.get("scanners", {}).get("software", {}).get("installed_apps", [])
    print(f"      {len(apps)} installed packages captured -> {scan_path}")

    # 2. cve-matcher: adapt scan -> Inventory, match against KEV.
    print(f"[2/4] Matching against KEV catalog ...")
    from cve_matcher import kev as kev_mod, matcher as matcher_mod

    inventory = _scan_to_inventory(scan)
    catalog = kev_mod.load()
    print(f"      KEV catalog: {len(catalog)} entries (v{catalog.catalog_version})")
    result = matcher_mod.match(inventory, catalog)
    print(f"      {len(result.findings)} candidate(s) matched")

    if args.check_versions and result.findings:
        n_unique = len({f.entry.cve_id for f in result.findings})
        print(f"[2b/4] NVD version-check on {n_unique} unique CVEs ...")

        def progress(i, total, cve):
            print(f"       [{i}/{total}] {cve}", flush=True)

        matcher_mod.enrich_with_versions(result.findings, on_progress=progress)

    kev_findings = [_finding_to_kev_finding(f) for f in result.findings]
    candidates_path = args.out_dir / "candidates.json"
    candidates_path.write_text(json.dumps({
        "schema_version": 1,
        "source": "scripts/scan_local_host.py",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "kev_findings": kev_findings,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"      wrote {len(kev_findings)} KEV finding(s) -> {candidates_path}")

    host_state = _derive_host_state(scan)
    (args.out_dir / "host_state.json").write_text(
        json.dumps(host_state, indent=2, default=str), encoding="utf-8"
    )

    verdicts_path = args.out_dir / "verdicts.json"
    if not kev_findings:
        print("[3/4] No KEV candidates -- writing empty verdicts.json and exiting.")
        verdicts_path.write_text(json.dumps({"schema_version": 1, "verdicts": []}, indent=2),
                                 encoding="utf-8")
        return 0

    # 3. exposure-analyzer with the LOCAL probe runner (not docker_exec).
    print(f"[3/4] Running exposure-analyzer (engine={args.engine!r}, local probes) ...")
    from exposure_analyzer.agent import (
        AgentConfig, ExposureAgent, build_claude_verdict_fn,
    )
    from exposure_analyzer.verdicts import dump_verdicts

    if args.engine == "fake":
        from exposure_analyzer.cli import _fake_verdict
        verdicts = [_fake_verdict(f) for f in kev_findings]
        dump_verdicts(verdicts, verdicts_path)
        print(f"      wrote {len(verdicts)} verdict(s) -> {verdicts_path}")
        return _finalize_report(scan, args.out_dir, verdicts)

    try:
        verdict_fn = build_claude_verdict_fn()
    except RuntimeError as e:
        print(f"      ERROR: {e}", file=sys.stderr)
        return 1

    # probe_runner=None picks the default local runner (no docker exec).
    agent = ExposureAgent(
        verdict_fn=verdict_fn,
        config=AgentConfig(run_probes=True),
        probe_runner=None,
    )
    try:
        verdicts = asyncio.run(agent.analyze_batch(kev_findings, host_state))
    except Exception as e:
        print(f"      ERROR: analyzer failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    dump_verdicts(verdicts, verdicts_path)
    print(f"      wrote {len(verdicts)} verdict(s) -> {verdicts_path}")

    print(f"[4/4] Summary:")
    counts: dict[str, int] = {}
    for v in verdicts:
        counts[v.verdict.value] = counts.get(v.verdict.value, 0) + 1
    for verdict_name in ("CONFIRMED", "MITIGATED_BY_CONFIG", "MITIGATED_BY_EXPOSURE",
                          "NOT_RUNNING", "NO_EVIDENCE"):
        n = counts.get(verdict_name, 0)
        if n:
            print(f"      {verdict_name:22s} {n}")

    return _finalize_report(scan, args.out_dir, verdicts)


def _run_host_scanner() -> dict[str, Any]:
    """In-process host-scanner run: N scanners, JSON out, no Claude/report."""
    import socket
    import platform
    from core.scanner import run_all
    from main import load_config

    cfg = load_config()
    scanners = cfg.setdefault("scanners", {})
    # Network scanner needs nmap; skip by default so this doesn't fail on
    # servers where nmap isn't installed.
    scanners.setdefault("network", {})["enabled"] = False

    results = run_all(cfg)
    return {
        "schema_version": 1,
        "source": "scripts/scan_local_host.py -> host-scanner in-process",
        "system": {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": sys.version,
            "scan_time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        "scanners": results,
    }


def _scan_to_inventory(scan: dict[str, Any]):
    from cve_matcher.inventory import Inventory, Package
    apps = scan.get("scanners", {}).get("software", {}).get("installed_apps", [])
    packages = [
        Package(
            name=a.get("DisplayName", ""),
            version=a.get("DisplayVersion", ""),
            vendor=(a.get("Publisher") or "").split("<")[0].strip(),
            product=a.get("DisplayName", ""),
            source="host-scanner",
        )
        for a in apps if a.get("DisplayName")
    ]
    system = scan.get("system", {})
    return Inventory(
        scanned_at=system.get("scan_time", ""),
        host_os="linux (local host)",
        host_version=system.get("platform", ""),
        packages=packages,
    )


def _finding_to_kev_finding(finding) -> dict[str, Any]:
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


def _derive_host_state(scan: dict[str, Any]) -> dict[str, Any]:
    scanners = scan.get("scanners", {})
    from exposure_analyzer.hoststate import summarize_services
    services = summarize_services(scanners.get("services"))
    return {
        **({"services": services} if services else {}),
        "target": "local host",
        "system": {
            "hostname": scan.get("system", {}).get("hostname"),
            "platform": scan.get("system", {}).get("platform"),
            "os_info": scanners.get("system", {}).get("os_info", {}),
        },
        "process_summary": {
            k: scanners.get("processes", {}).get(k)
            for k in ("running_process_count", "top_by_cpu", "top_by_memory")
            if k in scanners.get("processes", {})
        },
        "user_summary": {
            k: scanners.get("users", {}).get(k)
            for k in ("user_count", "users_with_shell", "root_uid_zero_accounts")
            if k in scanners.get("users", {})
        },
    }


def _finalize_report(scan: dict[str, Any], out_dir: Path, verdicts) -> int:
    """Render host-scanner HTML report and append the verdicts section."""
    try:
        from core.report import build_report_data, render_html
        from exposure_analyzer.report import append_verdicts_to_report
    except ImportError as e:
        print(f"      (report rendering skipped: {e})", file=sys.stderr)
        return 0

    # Minimal executive placeholder. Full executive summary needs the
    # Claude analysis pass in host-scanner/main.py which we deliberately
    # skip (the exposure-analyzer is the AI-reasoning layer for this
    # deployment flow).
    executive = {
        "overall_score": 0,
        "grade": "?",
        "headline": "Analyzer verdicts below. Full executive summary requires host-scanner/main.py separately.",
        "summary_paragraphs": [],
        "top_risks": [],
        "quick_wins": [],
        "priority_actions": [],
    }
    report_data = build_report_data(scan.get("scanners", {}), analyses={},
                                    executive=executive)
    html_path = out_dir / "report.html"
    render_html(report_data, str(html_path))
    append_verdicts_to_report(verdicts, html_path, scan=scan)
    print(f"      wrote report -> {html_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
