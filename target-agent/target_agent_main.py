"""sec-agent-target: self-contained host-scanner for arbitrary Linux targets.

Entry point for the PyInstaller-built binary. Mirrors the behaviour of
``eval-lab/scan_target.py`` but imports host-scanner's scanner tree from
a frozen PyInstaller bundle instead of a sys.path mount -- the whole
scanner package is baked into the executable so this binary runs on any
x86_64 Linux with glibc >= 2.17 (manylinux2014 baseline).

Usage on the target:

    docker cp sec-agent-target <container>:/tmp/sec-agent-target
    docker exec <container> /tmp/sec-agent-target > host.json

The output JSON matches host-scanner's run_all() shape so the downstream
cve-matcher + exposure-analyzer + attack-simulator + fix-publisher chain
consumes it unchanged.
"""

from __future__ import annotations

import importlib
import json
import socket
import sys
import time
import traceback
from datetime import datetime
from typing import Any


# (name, module_path, class_name) -- same set as eval-lab/scan_target.py.
# These are the scanners that are safe + informative to run from inside a
# target (no nmap, no filesystem crawl, no CVE lookup).
_SCANNERS = [
    ("system",     "scanners.system",     "SystemScanner"),
    ("software",   "scanners.software",   "SoftwareScanner"),
    ("users",      "scanners.users",      "UsersScanner"),
    ("processes",  "scanners.processes",  "ProcessScanner"),
    ("services",   "scanners.services",   "ServicesScanner"),
    ("startup",    "scanners.startup",    "StartupScanner"),
    ("hardware",   "scanners.hardware",   "HardwareScanner"),
]


def _cfg() -> dict[str, Any]:
    return {
        "scanners": {
            "network":    {"enabled": False},
            "filesystem": {"enabled": False},
            "software": {
                "enabled": True,
                "cve_lookup": False,
                "engine":    "kev",
                "check_versions": False,
            },
        },
    }


def _system_info() -> dict[str, Any]:
    import platform
    return {
        "hostname":  socket.gethostname(),
        "platform":  platform.platform(),
        "python":    sys.version,
        "scan_time": datetime.now().isoformat(),
    }


def _run_one(name: str, module_path: str, class_name: str, cfg: dict) -> dict[str, Any]:
    start = time.time()
    try:
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        data = cls(cfg).run()
        data["scan_duration_s"] = round(time.time() - start, 2)
        data["status"] = data.get("status", "completed")
        return data
    except Exception as e:
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "traceback": traceback.format_exc(),
            "scan_duration_s": round(time.time() - start, 2),
        }


def main() -> int:
    cfg = _cfg()
    scanner_cfg = cfg["scanners"]
    results: dict[str, Any] = {}
    for name, module_path, class_name in _SCANNERS:
        if not scanner_cfg.get(name, {}).get("enabled", True):
            continue
        results[name] = _run_one(name, module_path, class_name, cfg)

    payload = {
        "schema_version": 1,
        "source": "sec-agent-target/v3-0",
        "system": _system_info(),
        "scanners": results,
    }
    json.dump(payload, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
