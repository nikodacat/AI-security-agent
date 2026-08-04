"""Startup scanner — persistence mechanisms.

Windows: registry Run keys, scheduled tasks, Startup folder, browser extensions,
WMI event subscriptions.
Linux  : enabled systemd unit files, cron (system + per-user), XDG autostart,
/etc/rc.local, ~/.bashrc / ~/.profile injection candidates.
"""

from __future__ import annotations

import json
from pathlib import Path

from .base import BaseScanner, IS_LINUX, IS_WINDOWS

# Windows registry run-key locations.
RUN_KEYS = [
    r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM:\SYSTEM\CurrentControlSet\Services",
]


class StartupScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "startup"

    def run(self) -> dict:
        if IS_LINUX:
            return self._run_linux()
        if IS_WINDOWS:
            return self._run_windows()
        return {"status": "skipped", "reason": "unsupported platform"}

    # ==================================================================
    # Windows backend.
    # ==================================================================

    def _run_windows(self) -> dict:
        return {
            "status": "completed",
            "platform": "windows",
            "registry_run_keys": self._win_run_keys(),
            "scheduled_tasks": self._win_scheduled_tasks(),
            "startup_folder": self._win_startup_folder(),
            "browser_extensions": self._win_browser_extensions(),
            "wmi_subscriptions": self._win_wmi_persistence(),
        }

    def _win_run_keys(self) -> list:
        entries = []
        for key in RUN_KEYS[:5]:  # skip Services — too large
            raw = self._ps(f"""
try {{
    $props = Get-ItemProperty -Path '{key}' -ErrorAction Stop
    $props.PSObject.Properties |
    Where-Object {{ $_.Name -notmatch '^PS' }} |
    ForEach-Object {{
        [PSCustomObject]@{{ Key='{key}'; Name=$_.Name; Value=$_.Value }}
    }} | ConvertTo-Json
}} catch {{ '[]' }}
""")
            try:
                data = json.loads(raw) if raw else []
                if isinstance(data, dict):
                    data = [data]
                entries.extend(data)
            except Exception:
                pass
        return entries

    def _win_scheduled_tasks(self) -> list:
        raw = self._ps("""
Get-ScheduledTask |
Where-Object { $_.State -ne 'Disabled' } |
Select-Object TaskName, TaskPath, State,
    @{N='Actions';E={ ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; ' }},
    @{N='Author';E={ $_.Principal.UserId }} |
ConvertTo-Json
""")
        try:
            data = json.loads(raw) if raw else []
            if isinstance(data, dict):
                data = [data]
            return data
        except Exception:
            return []

    def _win_startup_folder(self) -> list:
        raw = self._ps(r"""
$folders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
)
$results = foreach ($f in $folders) {
    if (Test-Path $f) {
        Get-ChildItem -Path $f |
        Select-Object Name, FullName, Extension, LastWriteTime
    }
}
$results | ConvertTo-Json
""")
        try:
            data = json.loads(raw) if raw else []
            if isinstance(data, dict):
                data = [data]
            return data
        except Exception:
            return []

    def _win_browser_extensions(self) -> dict:
        raw = self._ps(r"""
$results = @{}
$chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
if (Test-Path $chromePath) {
    $exts = Get-ChildItem $chromePath -Directory | Select-Object -ExpandProperty Name
    $results['Chrome'] = $exts
}
$edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
if (Test-Path $edgePath) {
    $exts = Get-ChildItem $edgePath -Directory | Select-Object -ExpandProperty Name
    $results['Edge'] = $exts
}
$ffPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
if (Test-Path $ffPath) {
    $profiles = Get-ChildItem $ffPath -Directory | Select-Object -ExpandProperty Name
    $results['Firefox_Profiles'] = $profiles
}
$results | ConvertTo-Json
""")
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _win_wmi_persistence(self) -> list:
        raw = self._ps("""
try {
    $subs = Get-WMIObject -Namespace "root\\subscription" -Class __EventFilter -ErrorAction Stop
    $subs | Select-Object Name, Query | ConvertTo-Json
} catch {
    @() | ConvertTo-Json
}
""")
        try:
            data = json.loads(raw) if raw else []
            if isinstance(data, dict):
                data = [data]
            return data
        except Exception:
            return []

    # ==================================================================
    # Linux backend.
    # ==================================================================

    def _run_linux(self) -> dict:
        return {
            "status": "completed",
            "platform": "linux",
            "registry_run_keys": self._lin_enabled_units(),
            "scheduled_tasks": self._lin_cron_jobs(),
            "startup_folder": self._lin_xdg_autostart(),
            "browser_extensions": self._lin_browser_extensions(),
            "wmi_subscriptions": self._lin_rc_local(),
        }

    def _lin_enabled_units(self) -> list:
        """systemd unit files enabled at boot.

        Returns the same shape as the Windows run-key walk: Key / Name / Value
        so the AI prompt and report renderer don't have to special-case Linux.
        """
        if not self._which("systemctl"):
            return []
        raw = self._sh(
            "systemctl list-unit-files --state=enabled --no-legend --no-pager 2>/dev/null"
        )
        out: list[dict] = []
        for line in raw.splitlines():
            parts = line.split()
            if not parts:
                continue
            unit = parts[0]
            # Look up the ExecStart for context (best-effort):
            exec_start = self._sh(
                f"systemctl show -p ExecStart --value {unit} 2>/dev/null | head -n 1"
            ).strip()
            out.append({
                "Key": "systemd",
                "Name": unit,
                "Value": exec_start[:200] if exec_start else "",
            })
        return out[:60]

    def _lin_cron_jobs(self) -> list:
        """Aggregate cron from /etc/crontab, /etc/cron.d/*, and per-user crontabs.

        Returns entries shaped like Windows scheduled tasks (TaskName, TaskPath,
        State, Actions, Author).
        """
        out: list[dict] = []

        def collect_file(path: str, author: str = "system"):
            raw = self._read_file(path, max_bytes=32768)
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                out.append({
                    "TaskName": Path(path).name,
                    "TaskPath": path,
                    "State": "Enabled",
                    "Actions": line[:200],
                    "Author": author,
                })

        collect_file("/etc/crontab")
        cron_d = self._sh("ls /etc/cron.d 2>/dev/null")
        for entry in cron_d.splitlines():
            entry = entry.strip()
            if entry:
                collect_file(f"/etc/cron.d/{entry}")

        # Per-user crontabs (need sudo for most, best-effort).
        users_raw = self._sh("ls /var/spool/cron/crontabs 2>/dev/null")
        for u in users_raw.splitlines():
            u = u.strip()
            if u:
                collect_file(f"/var/spool/cron/crontabs/{u}", author=u)

        # systemd timers — modern cron replacement worth reporting.
        if self._which("systemctl"):
            timers = self._sh(
                "systemctl list-timers --all --no-legend --no-pager 2>/dev/null | head -n 30"
            )
            for line in timers.splitlines():
                line = line.strip()
                if not line:
                    continue
                out.append({
                    "TaskName": "systemd-timer",
                    "TaskPath": "/etc/systemd/system",
                    "State": "Enabled",
                    "Actions": line[:200],
                    "Author": "systemd",
                })

        return out[:80]

    def _lin_xdg_autostart(self) -> list:
        """XDG autostart .desktop files — both system-wide and per-user."""
        paths = [
            "/etc/xdg/autostart",
            str(Path.home() / ".config" / "autostart"),
        ]
        out: list[dict] = []
        for p in paths:
            base = Path(p)
            if not base.exists():
                continue
            try:
                for entry in base.iterdir():
                    if entry.is_file() and entry.suffix == ".desktop":
                        try:
                            stat_res = entry.stat()
                            mtime = stat_res.st_mtime
                        except OSError:
                            mtime = 0
                        out.append({
                            "Name": entry.name,
                            "FullName": str(entry),
                            "Extension": entry.suffix,
                            "LastWriteTime": mtime,
                        })
            except OSError:
                continue
        return out

    def _lin_browser_extensions(self) -> dict:
        """Browser extensions on Linux live in ~/.config/<browser> or ~/.mozilla."""
        home = Path.home()
        results: dict[str, list[str]] = {}
        chrome = home / ".config" / "google-chrome" / "Default" / "Extensions"
        if chrome.exists():
            try:
                results["Chrome"] = [d.name for d in chrome.iterdir() if d.is_dir()]
            except OSError:
                pass
        chromium = home / ".config" / "chromium" / "Default" / "Extensions"
        if chromium.exists():
            try:
                results["Chromium"] = [d.name for d in chromium.iterdir() if d.is_dir()]
            except OSError:
                pass
        ff = home / ".mozilla" / "firefox"
        if ff.exists():
            try:
                results["Firefox_Profiles"] = [d.name for d in ff.iterdir() if d.is_dir()]
            except OSError:
                pass
        return results

    def _lin_rc_local(self) -> list:
        """rc.local and shell-init injection candidates.

        Mirrors the WMI persistence slot — these are the "weird leftover places
        attackers like" on Linux.
        """
        out: list[dict] = []
        for path in ("/etc/rc.local", "/etc/profile", "/etc/bash.bashrc"):
            data = self._read_file(path, max_bytes=8192)
            if data:
                out.append({"Name": path, "Query": data[:500]})
        return out
