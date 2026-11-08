"""Local web launcher for AI Security Agent.

A form around the commands the project already has: pick a target, press Run,
watch the log, open the report. It adds no scanning logic of its own; it builds
one of these command lines and starts it:

    python eval-lab/run_full_scan.py --container <name> ...     (a Docker container)
    bash scripts/scan-local-host.sh ...                         (this machine, Linux only)

    python -m gui [--port 8791]

Safety:
  * Listens on 127.0.0.1 only, and refuses requests whose Host header is not
    local (blocks DNS-rebinding).
  * Starting or stopping a run needs a random token that only this server's own
    page knows, so another website open in your browser cannot start a run (an
    AI run costs quota).
  * Commands are built from an allow-list as an argument list (no shell); the
    container name must be one `docker ps` reports.
  * One run at a time. Results land in ./scan-results/ (git-ignored).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
RESULTS = REPO / "scan-results"
LEGACY_REPORTS = REPO / "eval-lab" / "reports"

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
DEFAULT_MAX_CALLS = 60       # run_full_scan.py defaults, shown in the form
DEFAULT_MAX_COST_USD = 2.0
LOCAL = "__local__"


# --------------------------------------------------------------------------- #
# Building the command (pure, tested)
# --------------------------------------------------------------------------- #

def build_command(spec: dict, containers: list[str], *, out_dir: Path,
                  platform: str = sys.platform, python: str = sys.executable) -> list[str]:
    """Turn a form submission into an argument list, or raise ValueError."""
    engine = spec.get("engine")
    if engine not in ("fake", "claude"):
        raise ValueError("engine must be 'fake' or 'claude'")
    target = spec.get("target")
    flag = lambda k: bool(spec.get(k))  # noqa: E731

    if target == LOCAL:
        if not platform.startswith("linux"):
            raise ValueError("scanning this machine is supported on Linux only")
        cmd = ["bash", str(REPO / "scripts" / "scan-local-host.sh"),
               f"--engine={engine}", f"--out-dir={out_dir}"]
        if flag("check_versions"):
            cmd.append("--check-versions")
        return cmd

    if not isinstance(target, str) or not _NAME_RE.match(target) or target not in containers:
        raise ValueError("target must be a running container")
    if flag("banner") and not flag("v2"):
        raise ValueError("banner candidates need the full pipeline (v2) to be on")

    try:
        max_calls = int(spec.get("max_calls", DEFAULT_MAX_CALLS))
        max_cost = float(spec.get("max_cost_usd", DEFAULT_MAX_COST_USD))
    except (TypeError, ValueError):
        raise ValueError("limits must be numbers") from None
    if not 0 <= max_calls <= 500 or not 0 <= max_cost <= 50:
        raise ValueError("limits out of range (calls 0-500, cost 0-50 USD)")

    cmd = [python, str(REPO / "eval-lab" / "run_full_scan.py"),
           "--container", target, "--engine", engine, "--out-dir", str(out_dir)]
    if flag("v2"):
        cmd.append("--v2")
    if flag("banner"):
        cmd.append("--banner-candidates")
    if flag("nvd"):
        cmd.append("--nvd-discovery")
    if flag("osv"):
        cmd.append("--osv-discovery")
    if flag("check_versions"):
        cmd.append("--check-versions")
    if engine == "claude":
        cmd += ["--max-calls", str(max_calls), "--max-cost-usd", str(max_cost)]
    return cmd


def run_dir_name(target: str, now: float | None = None) -> str:
    label = "this-machine" if target == LOCAL else target
    return f"{label}-{time.strftime('%Y%m%d_%H%M%S', time.localtime(now))}"


# --------------------------------------------------------------------------- #
# Containers and finished runs
# --------------------------------------------------------------------------- #

def list_containers() -> tuple[list[str], str]:
    """Names of running Docker containers, and a message if Docker is unreachable."""
    try:
        p = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                           capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as e:
        return [], f"Docker not available ({type(e).__name__})"
    if p.returncode != 0:
        return [], "Docker is not running"
    return sorted(n for n in p.stdout.split() if _NAME_RE.match(n)), ""


def list_runs(*roots: Path) -> list[str]:
    """Run ids ('<root folder>/<name>') for every folder holding verdicts.json, newest first."""
    runs: list[tuple[float, str]] = []
    for root in roots:
        if root.is_dir():
            for p in root.iterdir():
                v = p / "verdicts.json"
                if v.is_file():
                    runs.append((v.stat().st_mtime, f"{root.name}/{p.name}"))
    return [r for _, r in sorted(runs, reverse=True)]


def resolve_run(roots: tuple[Path, ...], run_id: str) -> Path | None:
    """Folder for a run id, only if the id is in the discovered listing."""
    if run_id not in list_runs(*roots):
        return None
    root_name, name = run_id.split("/", 1)
    for root in roots:
        if root.name == root_name:
            return root / name
    return None


def _entries(path: Path, key: str) -> list:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get(key, [])
    return data if isinstance(data, list) else []


def load_run(roots: tuple[Path, ...], run_id: str) -> dict | None:
    d = resolve_run(roots, run_id)
    if d is None:
        return None
    out = {"name": run_id, "verdicts": _entries(d / "verdicts.json", "verdicts"),
           "remediations": [], "has_report": (d / "report.html").is_file()}
    if (d / "remediations.json").is_file():
        out["remediations"] = _entries(d / "remediations.json", "remediations")
    return out


# --------------------------------------------------------------------------- #
# One background run at a time
# --------------------------------------------------------------------------- #

class Jobs:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._log_path: Path | None = None
        self._run_id = ""
        self._cmd: list[str] = []
        self._started = 0.0
        self._stopped = False

    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self, cmd: list[str], out_dir: Path, run_id: str) -> None:
        with self._lock:
            if self.running():
                raise RuntimeError("a run is already in progress")
            out_dir.mkdir(parents=True, exist_ok=True)
            self._log_path = out_dir / "gui-run.log"
            env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
            log = open(self._log_path, "wb")
            try:
                self._proc = subprocess.Popen(cmd, cwd=str(REPO), stdout=log, stderr=subprocess.STDOUT,
                                              stdin=subprocess.DEVNULL, env=env)
            finally:
                log.close()  # the child holds its own handle
            self._run_id, self._cmd, self._started, self._stopped = run_id, cmd, time.time(), False

    def stop(self) -> bool:
        with self._lock:
            if not self.running():
                return False
            self._stopped = True
            self._proc.terminate()
            return True

    def status(self, offset: int = 0) -> dict:
        if self._proc is None:
            return {"state": "idle"}
        code = self._proc.poll()
        text, end = "", offset
        if self._log_path and self._log_path.is_file():
            with open(self._log_path, "rb") as f:
                f.seek(offset)
                chunk = f.read(200_000)
            end = offset + len(chunk)
            text = chunk.decode("utf-8", errors="replace")
        if code is None:
            state = "running"
        elif self._stopped:
            state = "stopped"
        else:
            state = "done" if code == 0 else "failed"
        return {"state": state, "exit_code": code, "run_id": self._run_id, "log": text, "offset": end,
                "seconds": int(time.time() - self._started), "command": " ".join(self._cmd)}


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

def make_handler(token: str, port: int, roots: tuple[Path, ...], jobs: Jobs, results_dir: Path):
    page = (HERE / "index.html").read_text(encoding="utf-8").replace("__TOKEN__", token).encode("utf-8")
    local_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj) -> None:
            self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def _host_ok(self) -> bool:
            if self.headers.get("Host", "") in local_hosts:
                return True
            self._json(403, {"error": "bad Host header"})
            return False

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            if not self._host_ok():
                return
            url = urlparse(self.path)
            path = url.path
            if path == "/":
                self._send(200, page, "text/html; charset=utf-8")
            elif path == "/api/setup":
                containers, problem = list_containers()
                self._json(200, {"containers": containers, "docker_problem": problem,
                                 "can_scan_local": sys.platform.startswith("linux"),
                                 "defaults": {"max_calls": DEFAULT_MAX_CALLS, "max_cost_usd": DEFAULT_MAX_COST_USD}})
            elif path == "/api/runs":
                self._json(200, list_runs(*roots))
            elif path.startswith("/api/run/"):
                try:
                    run = load_run(roots, unquote(path[len("/api/run/"):]))
                except (OSError, ValueError) as e:
                    return self._json(500, {"error": f"could not read run: {e}"})
                self._json(404 if run is None else 200, run or {"error": "no such run"})
            elif path == "/api/job":
                try:
                    offset = max(0, int(dict(p.split("=", 1) for p in url.query.split("&") if "=" in p).get("offset", 0)))
                except ValueError:
                    offset = 0
                self._json(200, jobs.status(offset))
            elif path.startswith("/report/"):
                d = resolve_run(roots, unquote(path[len("/report/"):]))
                f = d / "report.html" if d else None
                if f and f.is_file():
                    # The report embeds text from scanned hosts and model output; a
                    # CSP with no script source keeps any of it from running here.
                    body = f.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self._json(404, {"error": "no report for this run"})
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if not self._host_ok():
                return
            if not secrets.compare_digest(self.headers.get("X-Token", ""), token):
                return self._json(403, {"error": "missing or wrong token; reload the page"})
            path = urlparse(self.path).path
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(min(length, 10_000)) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._json(400, {"error": "bad request body"})

            if path == "/api/run":
                containers, _ = list_containers()
                try:
                    run_name = run_dir_name(str(body.get("target")))
                    out_dir = results_dir / run_name
                    cmd = build_command(body, containers, out_dir=out_dir)
                    jobs.start(cmd, out_dir, f"{results_dir.name}/{run_name}")
                except ValueError as e:
                    return self._json(400, {"error": str(e)})
                except RuntimeError as e:
                    return self._json(409, {"error": str(e)})
                except OSError as e:
                    return self._json(500, {"error": f"could not start: {e}"})
                self._json(200, {"ok": True, "run_id": f"{results_dir.name}/{run_name}"})
            elif path == "/api/stop":
                self._json(200, {"stopped": jobs.stop()})
            else:
                self._json(404, {"error": "not found"})

        def log_message(self, *args) -> None:
            pass

    return Handler


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="gui", description="Local launcher for AI Security Agent.")
    ap.add_argument("--port", type=int, default=8791)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args(argv)

    token = secrets.token_urlsafe(24)
    try:
        server = ThreadingHTTPServer(
            ("127.0.0.1", args.port),
            make_handler(token, args.port, (RESULTS, LEGACY_REPORTS), Jobs(), RESULTS))
    except OSError as e:
        print(f"error: cannot listen on port {args.port} ({e}). Try --port <other>.", file=sys.stderr)
        return 2
    url = f"http://127.0.0.1:{args.port}/"
    print(f"AI Security Agent launcher: {url}  (Ctrl+C to stop)")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
