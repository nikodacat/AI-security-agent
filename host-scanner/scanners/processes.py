"""Process scanner — running processes, suspicious names, signature/origin checks."""

from __future__ import annotations

import json
import re

from .base import BaseScanner, IS_LINUX, IS_WINDOWS

# Well-known suspicious process / binary names — partial match.
SUSPICIOUS_KEYWORDS = [
    # Windows / pen-test toolkit
    "mimikatz", "metasploit", "meterpreter", "cobalt", "empire",
    "powersploit", "invoke-", "psexec", "nc.exe", "ncat", "netcat",
    "procdump", "lsass", "wce.exe", "fgdump", "pwdump",
    # Linux / generic
    "xmrig",      # crypto miner
    "kinsing",    # cloud cryptojacker
    "kdevtmpfsi", # crypto miner masquerading as a kernel thread
    "perl.dump",
    "/tmp/.",     # binaries in /tmp/. hidden dirs
    "/dev/shm/",  # binaries under /dev/shm
]


class ProcessScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "processes"

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
        processes = self._win_processes()
        services = self._win_services()
        suspicious = self._flag_suspicious(processes)
        unsigned = self._win_check_unsigned(processes[:50])
        return {
            "status": "completed",
            "platform": "windows",
            "process_count": len(processes),
            "processes": processes,
            "services_stopped_disabled": services,
            "suspicious_flagged": suspicious,
            "unsigned_executables": unsigned,
        }

    def _win_processes(self) -> list:
        raw = self._ps(
            "Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet, "
            "Path, Company, Description | ConvertTo-Json -Depth 2"
        )
        try:
            data = json.loads(raw) if raw else []
            if isinstance(data, dict):
                data = [data]
            return data
        except Exception:
            return []

    def _win_services(self) -> list:
        raw = self._ps(
            "Get-Service | Where-Object { $_.StartType -eq 'Disabled' -or $_.Status -eq 'Stopped' } | "
            "Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json"
        )
        try:
            data = json.loads(raw) if raw else []
            if isinstance(data, dict):
                data = [data]
            return data
        except Exception:
            return []

    def _win_check_unsigned(self, processes: list) -> list:
        paths = [p["Path"] for p in processes if p.get("Path") and p["Path"].strip()]
        if not paths:
            return []
        path_list = "'" + "','".join(p.replace("'", "`'") for p in paths[:30]) + "'"
        raw = self._ps(f"""
$paths = @({path_list})
$results = foreach ($p in $paths) {{
    try {{
        $sig = Get-AuthenticodeSignature -FilePath $p -ErrorAction Stop
        if ($sig.Status -ne 'Valid') {{
            [PSCustomObject]@{{ Path=$p; Status=$sig.Status.ToString() }}
        }}
    }} catch {{ }}
}}
$results | ConvertTo-Json
""", timeout=90)
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
        processes = self._lin_processes()
        services = self._lin_services_inactive()
        suspicious = self._flag_suspicious(processes)
        unsigned = self._lin_check_unpackaged(processes[:50])
        return {
            "status": "completed",
            "platform": "linux",
            "process_count": len(processes),
            "processes": processes,
            "services_stopped_disabled": services,
            "suspicious_flagged": suspicious,
            "unsigned_executables": unsigned,  # 'unpackaged' on Linux
        }

    def _lin_processes(self) -> list:
        """Collect via ps. Output mirrors the Windows shape (Id/ProcessName/Path/...)."""
        raw = self._sh(
            "ps -eo pid=,comm=,pcpu=,rss=,user=,args= "
            "--sort=-pcpu --no-headers 2>/dev/null | head -n 200"
        )
        out: list[dict] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            try:
                pid = int(parts[0])
            except ValueError:
                continue
            try:
                rss = int(parts[3]) * 1024  # ps -o rss is in KB
            except ValueError:
                rss = 0
            try:
                cpu = float(parts[2])
            except ValueError:
                cpu = 0.0
            comm = parts[1]
            user = parts[4]
            args = parts[5]
            # Best-effort exe path:
            exe = self._sh(f"readlink -f /proc/{pid}/exe 2>/dev/null").strip()
            out.append({
                "Id": pid,
                "ProcessName": comm,
                "CPU": cpu,
                "WorkingSet": rss,
                "Path": exe,
                "Company": user,           # username fills the 'Company' slot
                "Description": args[:200], # full command line, capped
            })
        return out

    def _lin_services_inactive(self) -> list:
        """systemd units that are inactive or disabled."""
        if not self._which("systemctl"):
            return []
        raw = self._sh(
            "systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | head -n 200"
        )
        services: list[dict] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            unit, state = parts[0], parts[1]
            if state in ("disabled", "masked"):
                # Cheap loaded-state probe:
                active = self._cmd(["systemctl", "is-active", unit]).strip()
                services.append({
                    "Name": unit,
                    "DisplayName": unit,
                    "Status": active or "inactive",
                    "StartType": state.capitalize(),
                })
        return services[:60]

    def _lin_check_unpackaged(self, processes: list) -> list:
        """The Linux equivalent of 'unsigned' is 'not owned by any package'.

        For each running binary path, ask dpkg -S whether the file belongs to
        an installed package. Binaries under /tmp, /dev/shm, /home, /opt, /root
        that no package owns are suspicious.
        """
        if not self._which("dpkg"):
            return []
        suspicious_roots = ("/tmp/", "/dev/shm/", "/home/", "/root/", "/var/tmp/")
        seen: set[str] = set()
        out: list[dict] = []
        for p in processes:
            path = (p.get("Path") or "").strip()
            if not path or path in seen:
                continue
            seen.add(path)
            owned = self._sh(f"dpkg -S {path!r} 2>/dev/null").strip()
            if owned:
                continue  # package-owned, considered "signed"
            looks_suspicious = path.startswith(suspicious_roots)
            if not looks_suspicious:
                # Still report anything not under /usr or /bin / /sbin:
                if not (path.startswith("/usr/") or path.startswith("/bin/") or path.startswith("/sbin/")):
                    looks_suspicious = True
            if looks_suspicious:
                out.append({"Path": path, "Status": "unpackaged"})
            if len(out) >= 30:
                break
        return out

    # ==================================================================
    # Shared.
    # ==================================================================

    @staticmethod
    def _flag_suspicious(processes: list) -> list:
        flagged: list[dict] = []
        for p in processes:
            name = (p.get("ProcessName") or "").lower()
            path = (p.get("Path") or "").lower()
            desc = (p.get("Description") or "").lower()
            haystack = f"{name} {path} {desc}"
            for kw in SUSPICIOUS_KEYWORDS:
                if kw in haystack:
                    flagged.append({
                        "pid": p.get("Id"),
                        "name": p.get("ProcessName"),
                        "path": p.get("Path"),
                        "matched_keyword": kw,
                    })
                    break
        return flagged
