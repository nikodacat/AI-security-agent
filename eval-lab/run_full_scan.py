"""End-to-end evaluation driver: scan -> match -> analyze against one target.

Chains the three pipeline stages so a single command produces the full
verdicts JSON + optional HTML report append for a given eval-lab container:

    1. `docker exec <container> python3 /opt/host-scanner/scan_target.py`
       -> raw host-scanner scan JSON
    2. Adapt scan.software.installed_apps -> cve-matcher inventory;
       run `cve_matcher.matcher.match(inventory, kev_catalog)`
       -> KEV findings (with optional NVD version-check)
    3. Adapt findings -> exposure-analyzer kev_findings shape;
       run `ExposureAgent.analyze_batch()` with `docker_exec_probe_runner`
       -> per-CVE verdicts JSON

Usage:

    python eval-lab/run_full_scan.py --container eval-web-vuln [--engine claude]

Emits three files under --out-dir (default eval-lab/reports/<container>/):
  - scan.json          the raw scan_target output
  - candidates.json    the cve-matcher findings, in kev_findings shape
  - verdicts.json      the analyzer output
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


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    out_dir: Path = args.out_dir or (HERE / "reports" / args.container)
    out_dir.mkdir(parents=True, exist_ok=True)

    scan_path = out_dir / "scan.json"
    candidates_path = out_dir / "candidates.json"
    host_state_path = out_dir / "host_state.json"
    verdicts_path = out_dir / "verdicts.json"

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

    if not kev_findings:
        print("[3/4] No KEV candidates to analyze -- writing empty verdicts.json and exiting.")
        verdicts_path.write_text(
            json.dumps({"schema_version": 1, "verdicts": []}, indent=2),
            encoding="utf-8",
        )
        return 0

    print(f"[3/4] Running exposure-analyzer (engine={args.engine!r}) ...")
    from exposure_analyzer.agent import (
        AgentConfig, ExposureAgent, build_claude_verdict_fn, docker_exec_probe_runner
    )
    from exposure_analyzer.verdicts import dump_verdicts

    if args.engine == "claude":
        verdict_fn = build_claude_verdict_fn()
    else:
        # Reuse the fake engine from exposure_analyzer.cli
        from exposure_analyzer.cli import _fake_verdict
        verdicts = [_fake_verdict(f) for f in kev_findings]
        dump_verdicts(verdicts, verdicts_path)
        print(f"      wrote {len(verdicts)} verdict(s) -> {verdicts_path}")
        return 0

    agent_cfg = AgentConfig(interactive=False, run_probes=not args.no_probes)
    probe_runner = docker_exec_probe_runner(args.container, agent_cfg)
    agent = ExposureAgent(verdict_fn=verdict_fn, config=agent_cfg, probe_runner=probe_runner)

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
    for verdict_name in ("CONFIRMED", "MITIGATED_BY_CONFIG", "MITIGATED_BY_EXPOSURE", "NOT_RUNNING", "NO_EVIDENCE"):
        n = counts.get(verdict_name, 0)
        if n:
            print(f"      {verdict_name:22s} {n}")

    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="run_full_scan.py",
                                description="End-to-end scan+match+analyze for one eval-lab container.")
    p.add_argument("--container", required=True,
                   help="Target container name (e.g. eval-web-vuln).")
    p.add_argument("--engine", choices=("fake", "claude"), default="claude",
                   help="Verdict engine. Default: claude (real Agent SDK).")
    p.add_argument("--check-versions", action="store_true",
                   help="Run cve-matcher's NVD version-check pass. Slower.")
    p.add_argument("--no-probes", action="store_true",
                   help="Skip probe execution (analyzer decides from candidate+host_state only).")
    p.add_argument("--out-dir", type=Path, default=None,
                   help="Output directory. Default: eval-lab/reports/<container>/")
    return p


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
            product=a.get("DisplayName", ""),
            source="dpkg (via host-scanner)",
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

    return {
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


if __name__ == "__main__":
    raise SystemExit(main())
