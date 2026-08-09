"""Gray-box scan bootstrap for eval-lab containers.

Runs a subset of host-scanner's scanners inside the container -- the ones
that make sense for a self-scan of a target -- and prints the raw scan
JSON to stdout. Deliberately skips:

  - The Claude analysis pass (needs the `claude` CLI + auth).
  - The HTML report render (needs Jinja templates + is out of scope here).
  - The network scanner (uses nmap; self-scanning is uninformative and
    external-perspective scanning belongs on the host side).
  - CVE matching in the software scanner (that's cve-matcher's job in the
    real pipeline; here we just want the raw package inventory).

Usage inside a container:

    docker exec eval-web-vuln python /opt/host-scanner/scan_target.py > web.json

The output shape mirrors host-scanner's `run_all(cfg)` return value so the
downstream cve-matcher + exposure-analyzer pipeline can consume it directly.
"""

from __future__ import annotations

import json
import socket
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any


# host-scanner lives at /opt/host-scanner inside the container, and this
# script is copied in there too, so a relative import works.
sys.path.insert(0, str(Path(__file__).resolve().parent))


_SCANNERS = [
    # (name, module, class)  -- keep to scanners that are self-contained
    # and safe to run inside a small container.
    ("system",     "scanners.system",     "SystemScanner"),
    ("software",   "scanners.software",   "SoftwareScanner"),
    ("users",      "scanners.users",      "UsersScanner"),
    ("processes",  "scanners.processes",  "ProcessScanner"),
    ("startup",    "scanners.startup",    "StartupScanner"),
    ("hardware",   "scanners.hardware",   "HardwareScanner"),
]


def _cfg() -> dict[str, Any]:
    """Minimal config -- disable anything the eval-lab does not need."""
    return {
        "scanners": {
            "network":    {"enabled": False},
            "filesystem": {"enabled": False},
            "software": {
                "enabled": True,
                "cve_lookup": False,       # cve-matcher does this from the host
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
    import importlib
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
        "source": "eval-lab/scan_target.py",
        "system": _system_info(),
        "scanners": results,
    }
    json.dump(payload, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
