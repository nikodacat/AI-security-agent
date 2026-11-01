"""Offline stage for the Vulhub scenarios: scan, probe, build candidates. No model.

For each scenario in vulhub_scenarios.yaml, one at a time (they share host ports):
  docker compose up -> join the eval-lab network -> copy in sec-agent-target ->
  host.json -> network_state.json (via eval-attacker) -> compare_arms.py
  --candidates-only for the "now", "nvd" and "osv" arms -> docker compose down.

Output: <out>/<scenario>/{host.json, network_state.json, candidates.{now,nvd,osv}/result.json,
scenario.json}. scenario.json records whether each step worked, so a scenario the
scanner cannot read (e.g. an Alpine image) is reported, not silently skipped.

    python run_vulhub_offline.py --out <dir> [--only name,name]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
BINARY = REPO / "target-agent" / "dist" / "sec-agent-target-glibc217"  # glibc >= 2.17: runs on Vulhub-era jessie/stretch
NETWORK = "eval-lab_evallab"
ENV = dict(os.environ, MSYS_NO_PATHCONV="1", PYTHONIOENCODING="utf-8")


def sh(cmd: list[str], cwd: Path | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=ENV, timeout=timeout, check=False)


def compose_args(vdir: Path, proj: str, out: Path) -> list[str]:
    """`docker compose -p <proj> -f <base> -f <override>` where the override drops every
    host port mapping. The harness reaches the container over the eval-lab network, never
    through a host port, and on Windows ports such as 445 and 61616 sit in reserved ranges
    and make `up` fail ("ports are not available")."""
    base = next((vdir / n for n in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
                 if (vdir / n).exists()), None)
    svcs = sh(["docker", "compose", "-p", proj, "config", "--services"], cwd=vdir).stdout.split()
    if base is None or not svcs:
        return ["docker", "compose", "-p", proj]
    over = out / "no-host-ports.yml"
    over.write_text("services:\n" + "".join(f"  {sv}:\n    ports: !reset []\n" for sv in svcs), encoding="utf-8")
    return ["docker", "compose", "-p", proj, "-f", str(base), "-f", str(over)]


def pick_container(dc: list[str], vdir: Path) -> str:
    """The container under test: among the running ones, prefer a vulhub/ image that exposes a
    port (a stack may also run a database, a cache, or an init job that has already exited)."""
    ids = sh(dc + ["ps", "-q"], cwd=vdir).stdout.split()   # `ps` lists running containers only

    def score(cid: str) -> tuple[int, int]:
        img = sh(["docker", "inspect", "-f", "{{.Config.Image}}", cid]).stdout.strip()
        ports = sh(["docker", "inspect", "-f", "{{len .Config.ExposedPorts}}", cid]).stdout.strip()
        return (img.startswith("vulhub/"), int(ports or 0) > 0)

    return max(ids, key=score)


def wait_ready(cid: str, alias: str, timeout: int = 120) -> str:
    """Poll from eval-attacker until the container accepts a TCP connection on any port
    it exposes. A fixed sleep scanned Solr before it was up (it needs ~20 s) and made the
    prober report nothing reachable. Returns a short status string for the log."""
    ports = sh(["docker", "inspect", "-f", "{{range $p,$_ := .Config.ExposedPorts}}{{$p}} {{end}}", cid]).stdout.split()
    tcp = [p.split("/")[0] for p in ports if p.endswith("/tcp")]
    if not tcp:
        time.sleep(8)
        return "no exposed tcp ports; waited 8s"
    t0 = time.time()
    while time.time() - t0 < timeout:
        for port in tcp:
            r = sh(["docker", "exec", "eval-attacker", "python", "-c",
                    f"import socket;socket.create_connection(('{alias}',{port}),2)"])
            if r.returncode == 0:
                time.sleep(3)
                return f"port {port} up after {time.time() - t0:.0f}s"
        time.sleep(3)
    return f"no port answered within {timeout}s (continuing anyway)"


def run_one(sc: dict, vulhub: Path, out: Path, ports: str) -> dict:
    name, vdir = sc["name"], vulhub / sc["dir"]
    proj = f"vh-{name}"
    out.mkdir(parents=True, exist_ok=True)
    rec: dict = {"name": name, "expected": sc.get("expected"), "steps": {}}

    def step(key: str, ok: bool, detail: str = "") -> bool:
        rec["steps"][key] = {"ok": ok, "detail": detail[:400]}
        print(f"  [{name}] {key}: {'ok' if ok else 'FAILED'} {detail[:120]}", flush=True)
        return ok

    try:
        dc = compose_args(vdir, proj, out)
        up = sh(dc + ["up", "-d"], cwd=vdir, timeout=420)
        if not step("up", up.returncode == 0, up.stderr.strip()[-300:]):
            return rec
        cid = pick_container(dc, vdir)
        cname = sh(["docker", "inspect", "-f", "{{.Name}}", cid]).stdout.strip().lstrip("/")
        rec["container"] = cname
        alias = proj
        sh(["docker", "network", "connect", "--alias", alias, NETWORK, cid])
        step("ready", True, wait_ready(cid, alias))

        sh(["docker", "cp", str(BINARY), f"{cname}:/tmp/sec-agent-target"])
        sc_run = sh(["docker", "exec", cname, "/tmp/sec-agent-target"], timeout=240)
        try:
            scan = json.loads(sc_run.stdout)
            (out / "host.json").write_text(json.dumps(scan, indent=2), encoding="utf-8")
            n = len(scan.get("scanners", {}).get("software", {}).get("installed_apps", []))
            step("scan", n > 0, f"{n} installed_apps")
        except Exception as e:
            step("scan", False, f"{type(e).__name__}: {sc_run.stderr.strip()[-200:]}")
            return rec

        pr = sh(["docker", "exec", "eval-attacker", "python", "-m", "network_prober", "scan",
                 "--target", alias, "--ports", ports, "--output", f"/prober-output/{alias}.net.json",
                 "--timeout", "900",  # the default 60 s abandons a whole-range scan with no result
                 "--schema", "/repo/docs/schemas/network_state.schema.json"], timeout=1000)
        src = HERE / "prober-output" / f"{alias}.net.json"
        if step("probe", pr.returncode == 0 and src.exists(), pr.stderr.strip()[-200:]):
            (out / "network_state.json").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

        for arm in ("now", "nvd", "osv"):
            d = out / f"candidates.{arm}"
            cmd = [sys.executable, str(HERE / "compare_arms.py"), "--container", cname, "--arm", arm,
                   "--host-json", str(out / "host.json"), "--candidates-only", "--out", str(d)]
            if (out / "network_state.json").exists():
                cmd += ["--network-state", str(out / "network_state.json")]
            elif arm != "w9":
                step(f"candidates.{arm}", False, "needs network_state")
                continue
            cp = sh(cmd, timeout=900)
            rj = d / "result.json"
            ok = cp.returncode == 0 and rj.exists()
            detail = f"{json.loads(rj.read_text(encoding='utf-8'))['n_candidates']} candidates" if ok else cp.stderr.strip()[-300:]
            step(f"candidates.{arm}", ok, detail)
            (out / f"candidates.{arm}.log").write_text(cp.stderr, encoding="utf-8")
    finally:
        sh(compose_args(vdir, proj, out) + ["down", "-v", "--remove-orphans"], cwd=vdir, timeout=240)
        (out / "scenario.json").write_text(json.dumps(rec, indent=2), encoding="utf-8")
    return rec


def analyze_one(sc: dict, vulhub: Path, out: Path, arm: str, run: int,
                max_calls: int, max_cost: float) -> dict | None:
    """Model stage for one scenario: container up (probes run against it), reuse the
    host.json / network_state.json from the offline stage, then compare_arms.py."""
    name, vdir = sc["name"], vulhub / sc["dir"]
    proj = f"vh-{name}"
    if not (out / "host.json").exists() or not (out / "network_state.json").exists():
        print(f"  [{name}] no offline output; run the offline stage first", flush=True)
        return None
    res_dir = out / f"claude.{arm}.r{run}"
    dc = compose_args(vdir, proj, out)
    try:
        up = sh(dc + ["up", "-d"], cwd=vdir, timeout=420)
        if up.returncode != 0:
            print(f"  [{name}] up FAILED {up.stderr.strip()[-200:]}", flush=True)
            return None
        cid = pick_container(dc, vdir)
        cname = sh(["docker", "inspect", "-f", "{{.Name}}", cid]).stdout.strip().lstrip("/")
        sh(["docker", "network", "connect", "--alias", proj, NETWORK, cid])
        print(f"  [{name}] ready: {wait_ready(cid, proj)}", flush=True)
        cp = sh([sys.executable, str(HERE / "compare_arms.py"), "--container", cname, "--arm", arm,
                 "--host-json", str(out / "host.json"), "--network-state", str(out / "network_state.json"),
                 "--engine", "claude", "--max-calls", str(max_calls), "--max-cost-usd", str(max_cost),
                 "--run", str(run), "--out", str(res_dir)], timeout=3600)
        (out / f"claude.{arm}.r{run}.log").write_text(cp.stderr, encoding="utf-8")
        tail = [l for l in cp.stderr.splitlines() if "done in" in l]
        print(f"  [{name}] {arm}: {tail[-1].strip() if tail else 'no result: ' + cp.stderr.strip()[-200:]}", flush=True)
        rj = res_dir / "result.json"
        return json.loads(rj.read_text(encoding="utf-8")) if rj.exists() else None
    finally:
        sh(dc + ["down", "-v", "--remove-orphans"], cwd=vdir, timeout=240)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--vulhub", type=Path, default=Path("C:/Users/ideal/vulhub"))
    ap.add_argument("--only", default="")
    ap.add_argument("--ports", default="1-65535",
                    help="nmap -p syntax; the whole range, so no service depends on a hand-picked port list")
    ap.add_argument("--analyze", choices=("now", "nvd", "osv"), default=None,
                    help="Model stage instead of the offline stage (needs the offline output).")
    ap.add_argument("--run", type=int, default=1)
    ap.add_argument("--max-calls", type=int, default=60, help="per scenario")
    ap.add_argument("--max-cost-usd", type=float, default=1.5, help="per scenario")
    ap.add_argument("--max-total-usd", type=float, default=2.0,
                    help="across all scenarios of this invocation; stops before starting the next one")
    a = ap.parse_args()
    cfg = yaml.safe_load((HERE / "vulhub_scenarios.yaml").read_text(encoding="utf-8"))["scenarios"]
    only = {s for s in a.only.split(",") if s}
    spent = 0.0
    for sc in cfg:
        if only and sc["name"] not in only:
            continue
        print(f"== {sc['name']}", flush=True)
        if a.analyze:
            if spent >= a.max_total_usd:
                print(f"  total cap ${a.max_total_usd:.2f} reached (spent ${spent:.2f}); skipping", flush=True)
                continue
            r = analyze_one(sc, a.vulhub, a.out / sc["name"], a.analyze, a.run, a.max_calls, a.max_cost_usd)
            spent += (r or {}).get("cost_usd") or 0.0
            print(f"  running total ${spent:.3f}", flush=True)
        else:
            run_one(sc, a.vulhub, a.out / sc["name"], a.ports)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
