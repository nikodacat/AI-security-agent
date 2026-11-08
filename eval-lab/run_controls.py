"""Control experiment for the verdict stage: patched hosts and not-exposed hosts.

The answer key is fixed by how each target is built, not by anyone's judgment:

  H0 / R0   the lab's vulnerable httpd 2.4.49 / redis 6.2.6, reachable        -> CONFIRMED
  H1 / R1   the same product at a fixed version (httpd 2.4.62 / redis 6.2.14)  -> not CONFIRMED
  H2 / R2   the same vulnerable version, but listening on 127.0.0.1 only       -> not CONFIRMED

The controlled CVEs are, for httpd, CVE-2021-41773 and CVE-2021-42013 (the lab answer key marks them
CONFIRMED on H0). For redis they are the CVEs the tool itself judged CONFIRMED on R0 in every run
(the lab's two redis CVEs are not in NVD's list for 6.2.6, so they cannot be used).
H1/H2 and R2 have the identical configuration as H0/R0 apart from the one thing changed.
A CONFIRMED on H1, H2 or R2 is a false CONFIRMED; a missing CONFIRMED on H0/R0 is a miss.

R1 (redis 6.2.14) is informational only: redis CVEs come from NVD discovery, which already drops the CVEs
NVD says are fixed in the installed version, so a CVE that is still a candidate is one NVD still lists as
affecting 6.2.14, and CONFIRMED on it is not a false CONFIRMED.

Needs Docker with the eval-lab containers up (eval-lab/docker-compose.yml), the single-file scanner
at target-agent/dist/sec-agent-target, and a Claude engine for run_full_scan.py.

  python eval-lab/run_controls.py run --out <dir> [--runs 2]     # set up, scan, analyze
  python eval-lab/run_controls.py summary --out <dir>            # table from the saved verdicts
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
AGENT = REPO / "target-agent" / "dist" / "sec-agent-target"
NETWORK = "eval-lab_evallab"
PORTS = "22,80,443,3306,6379,8000-8100"

HTTPD_CVES = ["CVE-2021-41773", "CVE-2021-42013"]
REDIS_CVES = "R0"  # derived from the R0 verdicts (see controlled_cves); redis CVEs come from --nvd-discovery

# like-for-like config the lab's web-vuln Dockerfile adds to the stock httpd.conf
_HTTPD_CONF = "/usr/local/apache2/conf/httpd.conf"
_HTTPD_LAB_TWEAKS = (
    f'echo "LoadModule cgid_module modules/mod_cgid.so" >> {_HTTPD_CONF}; '
    f'echo "ScriptAlias /cgi-bin/ /usr/local/apache2/cgi-bin/" >> {_HTTPD_CONF}; '
    f"sed -i 's|Require all denied|Require all granted|' {_HTTPD_CONF}; "
)

TARGETS: dict[str, dict] = {
    "H0": {"existing": "eval-web-vuln", "cves": HTTPD_CVES, "expect": "CONFIRMED"},
    "H1": {"name": "ctl-httpd-patched", "image": "httpd:2.4.62", "cves": HTTPD_CVES, "expect": "not CONFIRMED", "port": 80,
           "cmd": ["sh", "-c", _HTTPD_LAB_TWEAKS + "exec httpd-foreground"]},
    "H2": {"name": "ctl-httpd-local", "image": "eval-lab-web-vuln", "cves": HTTPD_CVES, "expect": "not CONFIRMED", "port": 80,
           "cmd": ["sh", "-c", f"sed -i 's/^Listen 80/Listen 127.0.0.1:80/' {_HTTPD_CONF}; exec httpd-foreground"]},
    "R0": {"existing": "eval-db-exposed", "cves": REDIS_CVES, "extra": ["--nvd-discovery"], "expect": "CONFIRMED"},
    "R1": {"name": "ctl-redis-patched", "image": "redis:6.2.14", "cves": REDIS_CVES, "extra": ["--nvd-discovery"], "expect": "info", "port": 6379,
           "cmd": ["redis-server", "--bind", "0.0.0.0", "--protected-mode", "no"]},
    "R2": {"name": "ctl-redis-local", "image": "eval-lab-db-exposed", "cves": REDIS_CVES, "extra": ["--nvd-discovery"], "expect": "not CONFIRMED", "port": 6379,
           "cmd": ["redis-server", "/usr/local/etc/redis/redis.conf", "--bind", "127.0.0.1", "--protected-mode", "yes"]},
}


def sh(*cmd: str, check: bool = True, out=None) -> subprocess.CompletedProcess:
    return subprocess.run(list(cmd), check=check, stdout=out, stderr=subprocess.PIPE if out else None)


def start_container(t: dict) -> str:
    name = t["name"]
    sh("docker", "rm", "-f", name, check=False, out=subprocess.DEVNULL)
    sh("docker", "run", "-d", "--name", name, "--network", NETWORK, t["image"], *t["cmd"], out=subprocess.DEVNULL)
    wait_listening(name, t["port"])
    return name


def wait_listening(name: str, port: int, timeout: int = 60) -> None:
    """Wait until `port` is open inside the container. Some images do slow start-up work first
    (the redis entrypoint chowns /data), and a scan taken too early sees no service at all."""
    hexport = f":{port:04X}"
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(["docker", "exec", name, "sh", "-c", "cat /proc/net/tcp /proc/net/tcp6"],
                           capture_output=True, text=True)
        if any(hexport in line and " 0A " in line for line in r.stdout.splitlines()):
            time.sleep(1)
            return
        time.sleep(1)
    raise RuntimeError(f"{name}: port {port} not listening after {timeout}s")


def scan_container(name: str, dest: Path) -> None:
    sh("docker", "cp", str(AGENT), f"{name}:/tmp/sat", out=subprocess.DEVNULL)
    with dest.open("wb") as f:
        sh("docker", "exec", name, "/tmp/sat", out=f)


def analyze(label: str, scan: Path, out_dir: Path, extra: list[str] | None = None) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, str(HERE / "run_full_scan.py"), "--scan-json", str(scan), "--label", label,
           "--prober", "docker", "--prober-target", label, "--prober-ports", PORTS,
           "--banner-candidates", "--engine", "claude", "--max-cost-usd", "1.5", "--out-dir", str(out_dir),
           *(extra or [])]
    log = out_dir / "run.log"
    env = {**__import__("os").environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    with log.open("w", encoding="utf-8") as f:
        return subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, env=env).returncode


def cmd_run(args: argparse.Namespace) -> int:
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    for key, t in TARGETS.items():
        if args.only and key not in args.only:
            continue
        name = t.get("existing") or start_container(t)
        scan = out / f"{key}.scan.json"
        scan_container(name, scan)
        print(f"[{key}] scanned {name} -> {scan.name}", flush=True)
        for r in range(1, args.runs + 1):
            rc = analyze(name, scan, out / key / f"r{r}", t.get("extra"))
            print(f"[{key}] run {r}: rc={rc}", flush=True)
        if not t.get("existing") and not args.keep:
            sh("docker", "rm", "-f", name, check=False, out=subprocess.DEVNULL)
    return cmd_summary(args)


def controlled_cves(out: Path, key: str) -> list[str]:
    cves = TARGETS[key]["cves"]
    if cves != "R0":
        return cves
    runs = [out / "R0" / p.name / "verdicts.json" for p in sorted((out / "R0").glob("r*"))]
    sets = []
    for path in runs:
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8")).get("verdicts", [])
            cand = json.loads((path.parent / "candidates.json").read_text(encoding="utf-8")).get("kev_findings", [])
            redis = {c["cve_id"] for c in cand if "redis" in str(c.get("package_name") or c.get("package") or "").lower()}
            sets.append({v["cve_id"] for v in data if v.get("verdict") == "CONFIRMED" and v["cve_id"] in redis})
    return sorted(set.intersection(*sets)) if sets else []


def verdict_of(out: Path, key: str, r: int, cve: str) -> str:
    path = out / key / f"r{r}" / "verdicts.json"
    if not path.is_file():
        return "(no run)"
    data = json.loads(path.read_text(encoding="utf-8"))
    for v in data.get("verdicts", []):
        if v.get("cve_id") == cve:
            return v.get("verdict", "?")
    return "NOT_A_CANDIDATE"


def cmd_summary(args: argparse.Namespace) -> int:
    out = args.out
    rows = []
    false_confirmed = total_control = missed = total_base = 0
    print("target  cve              run  verdict")
    for key, t in TARGETS.items():
        runs = sorted(int(p.name[1:]) for p in (out / key).glob("r*") if (p / "verdicts.json").is_file()) if (out / key).is_dir() else []
        for r in runs:
            for cve in controlled_cves(out, key):
                v = verdict_of(out, key, r, cve)
                rows.append({"target": key, "cve": cve, "run": r, "verdict": v, "expect": t["expect"]})
                print(f"{key:6s}  {cve:15s}  r{r}   {v}")
                if t["expect"] == "CONFIRMED":
                    total_base += 1
                    missed += v != "CONFIRMED"
                elif t["expect"] == "info":
                    pass
                else:
                    total_control += 1
                    false_confirmed += v == "CONFIRMED"
    print(f"\nbaseline (should be CONFIRMED): {total_base - missed}/{total_base} CONFIRMED")
    print(f"controls (must not be CONFIRMED): {false_confirmed}/{total_control} false CONFIRMED")
    (out / "summary.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--out", type=Path, required=True)
    r.add_argument("--runs", type=int, default=2)
    r.add_argument("--only", nargs="*", help="e.g. H1 R2")
    r.add_argument("--keep", action="store_true", help="keep the control containers afterwards")
    s = sub.add_parser("summary")
    s.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    return cmd_run(args) if args.cmd == "run" else cmd_summary(args)


if __name__ == "__main__":
    raise SystemExit(main())
