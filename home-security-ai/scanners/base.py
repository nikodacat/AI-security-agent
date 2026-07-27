"""Base class for all scanners.

Cross-platform note
-------------------
This file used to assume Windows + PowerShell only. It now exposes a small
platform-detection layer plus three runners:

  * ``_ps(script)``  — PowerShell. Raises NotImplementedError on non-Windows.
  * ``_sh(script)``  — POSIX shell. Raises NotImplementedError on Windows.
  * ``_cmd(argv)``   — plain argv subprocess. Works on both.

Each concrete scanner is expected to detect the platform via the
``IS_WINDOWS`` / ``IS_LINUX`` constants exported from this module and dispatch
to a ``_run_windows()`` / ``_run_linux()`` helper. Keeping the dispatch inside
the scanner (rather than splitting files per-OS) makes it easy to compare the
two backends side by side, which matters for a thesis where both branches need
to be reviewed.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable


# ------------------------------------------------------------------
# Platform detection
# ------------------------------------------------------------------

IS_WINDOWS: bool = platform.system() == "Windows"
IS_LINUX: bool = platform.system() == "Linux"
IS_MACOS: bool = platform.system() == "Darwin"


def current_platform() -> str:
    """Return a short identifier the rest of the code can switch on."""
    if IS_WINDOWS:
        return "windows"
    if IS_LINUX:
        return "linux"
    if IS_MACOS:
        return "macos"
    return platform.system().lower() or "unknown"


# ------------------------------------------------------------------
# PowerShell prefix — UTF-8 console output regardless of system locale.
# ------------------------------------------------------------------

_PS_PREFIX = (
    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
    "$OutputEncoding = [System.Text.Encoding]::UTF8; "
)


class BaseScanner(ABC):
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.scanner_cfg = cfg.get("scanners", {}).get(self.name, {})

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def run(self) -> dict: ...

    # ----- runners --------------------------------------------------

    def _ps(self, script: str, timeout: int = 60) -> str:
        """Run a PowerShell script (Windows only). Always returns UTF-8 stdout."""
        if not IS_WINDOWS:
            raise NotImplementedError(
                "_ps() is only available on Windows; use _sh() or _cmd() instead."
            )
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command",
             _PS_PREFIX + script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return result.stdout.strip()

    def _sh(self, script: str, timeout: int = 60) -> str:
        """Run a POSIX shell script via /bin/sh -c. Linux/macOS only."""
        if IS_WINDOWS:
            raise NotImplementedError(
                "_sh() is not available on Windows; use _ps() instead."
            )
        # LANG/LC_ALL forced so tools like 'ss' or 'last' produce predictable
        # English output that downstream parsers expect.
        env = {**os.environ, "LANG": "C", "LC_ALL": "C"}
        result = subprocess.run(
            ["/bin/sh", "-c", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )
        return result.stdout.strip()

    def _cmd(self, args: list[str], timeout: int = 60) -> str:
        """Run a plain argv subprocess. Works on every platform."""
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            return result.stdout.strip()
        except FileNotFoundError:
            return ""

    # ----- small filesystem helpers --------------------------------

    def _read_file(self, path: str | Path, max_bytes: int = 65536) -> str:
        """Best-effort UTF-8 read of a file with a byte cap. Returns "" on error."""
        try:
            p = Path(path)
            if not p.exists() or not p.is_file():
                return ""
            data = p.read_bytes()[:max_bytes]
            return data.decode("utf-8", errors="replace").strip()
        except (PermissionError, OSError):
            return ""

    def _which(self, *names: str) -> str:
        """Return the absolute path of the first available binary, or ""."""
        for n in names:
            found = shutil.which(n)
            if found:
                return found
        return ""

    def _which_any(self, names: Iterable[str]) -> bool:
        """True if ANY of the named binaries exists on PATH."""
        return any(shutil.which(n) for n in names)
