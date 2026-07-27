"""FastAPI web frontend for HomeSecAI."""

import json
import os
import threading
from datetime import datetime
from pathlib import Path

import yaml
from fastapi import FastAPI, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).parent
ROOT_DIR = BASE_DIR.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="HomeSecAI")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Global state
_scan_state = {
    "running": False,
    "progress": {},    # scanner_name -> "running" | "done" | "error"
    "results": None,
    "analyses": None,
    "executive": None,
    "report_html": None,
    "started_at": None,
    "finished_at": None,
    "error": None,
}


def _load_config():
    with open(ROOT_DIR / "config.yaml") as f:
        return yaml.safe_load(f)


def _run_full_scan():
    import sys
    sys.path.insert(0, str(ROOT_DIR))

    from core.scanner import run_all
    from core.claude_engine import analyze_all
    from core.report import build_report_data, render_html

    cfg = _load_config()
    _scan_state["started_at"] = datetime.now().isoformat()
    _scan_state["error"] = None

    def progress_cb(name, status):
        _scan_state["progress"][name] = status

    try:
        scan_results = run_all(cfg, progress_cb=progress_cb)
        _scan_state["results"] = scan_results

        claude_cfg = cfg.get("claude", {})

        # Mark every non-errored scanner as "analyzing" before the batched call;
        # we can no longer report per-scanner progress mid-flight.
        ok_names = [n for n, d in scan_results.items()
                    if not (isinstance(d, dict) and d.get("status") == "error")]
        for n in ok_names:
            _scan_state["progress"][n] = "analyzing"

        system_info = {"hostname": "localhost", "scan_time": _scan_state["started_at"]}
        try:
            analyses, executive = analyze_all(scan_results, system_info, claude_cfg)
        except Exception as e:
            for n in ok_names:
                _scan_state["progress"][n] = "analysis_error"
            _scan_state["error"] = f"Claude analysis failed: {e}"
            analyses, executive = {}, {}

        for n in ok_names:
            if n in analyses:
                _scan_state["progress"][n] = "analyzed"
            else:
                _scan_state["progress"][n] = "analysis_error"

        _scan_state["analyses"] = analyses
        _scan_state["executive"] = executive

        # Build and save report
        report_data = build_report_data(scan_results, analyses, executive)
        out_dir = ROOT_DIR / cfg.get("report", {}).get("output_dir", "reports")
        out_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_path = out_dir / f"report_{ts}.html"
        render_html(report_data, str(html_path))
        _scan_state["report_html"] = str(html_path)

    except Exception as e:
        _scan_state["error"] = str(e)
    finally:
        _scan_state["running"] = False
        _scan_state["finished_at"] = datetime.now().isoformat()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/scan/start")
async def start_scan():
    if _scan_state["running"]:
        return JSONResponse({"error": "Scan already running"}, status_code=409)
    _scan_state["running"] = True
    _scan_state["progress"] = {}
    _scan_state["results"] = None
    _scan_state["analyses"] = None
    _scan_state["executive"] = None
    _scan_state["report_html"] = None
    thread = threading.Thread(target=_run_full_scan, daemon=True)
    thread.start()
    return {"status": "started"}


@app.get("/api/scan/status")
async def scan_status():
    return {
        "running": _scan_state["running"],
        "progress": _scan_state["progress"],
        "started_at": _scan_state["started_at"],
        "finished_at": _scan_state["finished_at"],
        "has_results": _scan_state["results"] is not None,
        "has_report": _scan_state["report_html"] is not None,
        "error": _scan_state["error"],
    }


@app.get("/api/results")
async def get_results():
    if not _scan_state["executive"]:
        return JSONResponse({"error": "No results yet"}, status_code=404)
    return {
        "executive": _scan_state["executive"],
        "analyses": _scan_state["analyses"],
        "progress": _scan_state["progress"],
    }


@app.get("/api/report")
async def get_report():
    if not _scan_state["report_html"]:
        return JSONResponse({"error": "No report yet"}, status_code=404)
    return FileResponse(
        _scan_state["report_html"],
        media_type="text/html",
        filename="security_report.html",
    )


@app.get("/api/report/view", response_class=HTMLResponse)
async def view_report():
    if not _scan_state["report_html"]:
        return HTMLResponse("<h1>No report yet. Run a scan first.</h1>", status_code=404)
    return HTMLResponse(Path(_scan_state["report_html"]).read_text(encoding="utf-8"))
