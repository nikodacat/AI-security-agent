"""Scanner orchestrator — runs all enabled scanners and collects results."""

import asyncio
import importlib
import time
import traceback
from datetime import datetime
from typing import Callable

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

console = Console()

SCANNER_MODULES = [
    ("network",   "scanners.network",    "NetworkScanner"),
    ("system",    "scanners.system",     "SystemScanner"),
    ("software",  "scanners.software",   "SoftwareScanner"),
    ("users",     "scanners.users",      "UsersScanner"),
    ("processes", "scanners.processes",  "ProcessScanner"),
    ("services",  "scanners.services",   "ServicesScanner"),
    ("filesystem","scanners.filesystem", "FilesystemScanner"),
    ("startup",   "scanners.startup",    "StartupScanner"),
    ("hardware",  "scanners.hardware",   "HardwareScanner"),
]


def _load_scanner(module_path: str, class_name: str):
    mod = importlib.import_module(module_path)
    return getattr(mod, class_name)


def run_all(cfg: dict, progress_cb: Callable[[str, str], None] | None = None) -> dict:
    """Run every enabled scanner. Returns raw results keyed by scanner name."""
    results = {}
    scanner_cfg = cfg.get("scanners", {})

    for name, module_path, class_name in SCANNER_MODULES:
        if not scanner_cfg.get(name, {}).get("enabled", True):
            continue

        if progress_cb:
            progress_cb(name, "running")

        start = time.time()
        try:
            cls = _load_scanner(module_path, class_name)
            scanner = cls(cfg)
            data = scanner.run()
            data["scan_duration_s"] = round(time.time() - start, 2)
            data["status"] = data.get("status", "completed")
            results[name] = data
            if progress_cb:
                progress_cb(name, "done")
        except Exception as exc:
            results[name] = {
                "status": "error",
                "error": str(exc),
                "traceback": traceback.format_exc(),
                "scan_duration_s": round(time.time() - start, 2),
            }
            if progress_cb:
                progress_cb(name, "error")

    return results


def run_all_cli(cfg: dict) -> dict:
    """CLI-friendly wrapper with rich progress display."""
    results = {}
    scanner_cfg = cfg.get("scanners", {})
    enabled = [(n, m, c) for n, m, c in SCANNER_MODULES if scanner_cfg.get(n, {}).get("enabled", True)]

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        tasks = {name: progress.add_task(f"[{name}]", total=1) for name, _, _ in enabled}

        for name, module_path, class_name in enabled:
            progress.update(tasks[name], description=f"Scanning: {name:<12}")
            start = time.time()
            try:
                cls = _load_scanner(module_path, class_name)
                scanner = cls(cfg)
                data = scanner.run()
                data["scan_duration_s"] = round(time.time() - start, 2)
                data["status"] = data.get("status", "completed")
                results[name] = data
                progress.update(tasks[name], advance=1, description=f"[green]Done:    {name:<12}")
            except Exception as exc:
                results[name] = {
                    "status": "error",
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                    "scan_duration_s": round(time.time() - start, 2),
                }
                progress.update(tasks[name], advance=1, description=f"[red]Error:   {name:<12}")

    return results
