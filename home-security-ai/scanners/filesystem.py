"""Filesystem scanner — sensitive file exposure, world-writable dirs, credential files."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from .base import BaseScanner, IS_LINUX, IS_WINDOWS

SENSITIVE_PATTERNS = [
    "*.pem", "*.key", "*.pfx", "*.p12",
    "*.kdbx",                          # KeePass
    "id_rsa", "id_ed25519",            # SSH private keys
    "*.env", ".env",
    "credentials", "credentials.json",
    "*.rdp",
    "*.vnc",
    "ntds.dit",
    "SAM",
    "*.ovpn",
    "*.wallet",
]


def _default_sensitive_dirs() -> list[Path]:
    """Build a per-platform default list of dirs to walk for sensitive files."""
    dirs: list[Path] = [
        Path.home() / ".ssh",
        Path.home() / "Desktop",
        Path.home() / "Downloads",
        Path.home() / "Documents",
    ]
    if IS_WINDOWS:
        dirs.append(Path("C:/Windows/System32/config"))
    if IS_LINUX:
        # Server / unix locations worth checking.
        dirs.extend([
            Path("/etc/ssh"),
            Path("/root/.ssh"),
            Path("/var/backups"),
        ])
    return dirs


class FilesystemScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "filesystem"

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
            "sensitive_files_found": self._find_sensitive_files(),
            "world_writable_system_dirs": self._win_check_world_writable(),
            "temp_executables": self._win_check_temp_executables(),
            "recycle_bin_items": self._win_check_recycle_bin(),
            "bitlocker_status": self._win_check_bitlocker(),
        }

    def _win_check_world_writable(self) -> list:
        raw = self._ps(r"""
$dirs = @('C:\Windows\System32', 'C:\Windows\SysWOW64', 'C:\Program Files', 'C:\Program Files (x86)')
$results = foreach ($d in $dirs) {
    try {
        $acl = Get-Acl $d -ErrorAction Stop
        $worldWrite = $acl.Access | Where-Object {
            $_.IdentityReference -match 'Everyone|BUILTIN\\Users' -and
            $_.FileSystemRights -match 'Write|Modify|FullControl' -and
            $_.AccessControlType -eq 'Allow'
        }
        if ($worldWrite) {
            [PSCustomObject]@{ Directory=$d; Rule=($worldWrite | Select-Object -First 1).FileSystemRights.ToString() }
        }
    } catch {}
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

    def _win_check_temp_executables(self) -> list:
        raw = self._ps(r"""
$tempDirs = @($env:TEMP, $env:TMP, 'C:\Windows\Temp')
$results = foreach ($d in $tempDirs) {
    if (Test-Path $d) {
        Get-ChildItem -Path $d -Filter '*.exe' -ErrorAction SilentlyContinue |
        Select-Object FullName, Length, LastWriteTime |
        Select-Object -First 20
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

    def _win_check_recycle_bin(self) -> dict:
        raw = self._ps(r"""
try {
    $shell = New-Object -ComObject Shell.Application
    $bin = $shell.Namespace(10)
    $count = ($bin.Items() | Measure-Object).Count
    [PSCustomObject]@{ ItemCount=$count } | ConvertTo-Json
} catch {
    [PSCustomObject]@{ ItemCount='unknown' } | ConvertTo-Json
}
""")
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _win_check_bitlocker(self) -> list:
        raw = self._ps(
            "Get-BitLockerVolume -ErrorAction SilentlyContinue | "
            "Select-Object MountPoint, EncryptionMethod, ProtectionStatus, "
            "EncryptionPercentage, VolumeStatus | ConvertTo-Json"
        )
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
            "sensitive_files_found": self._find_sensitive_files(),
            "world_writable_system_dirs": self._lin_world_writable(),
            "temp_executables": self._lin_temp_executables(),
            "recycle_bin_items": self._lin_trash(),
            "bitlocker_status": self._lin_disk_encryption(),
            "shadow_perms": self._lin_shadow_perms(),
            "suid_binaries": self._lin_suid_binaries(),
        }

    def _lin_world_writable(self) -> list:
        roots = "/etc /var /opt /srv /usr/local"
        raw = self._sh(
            f"find {roots} -xdev -type f -perm -0002 ! -perm -1000 2>/dev/null | head -n 30"
        )
        out: list[dict] = []
        for line in raw.splitlines():
            line = line.strip()
            if line:
                out.append({"Directory": line, "Rule": "world-writable"})
        return out

    def _lin_temp_executables(self) -> list:
        raw = self._sh(
            "find /tmp /var/tmp /dev/shm -xdev -type f -perm -u+x 2>/dev/null | head -n 30"
        )
        out: list[dict] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                st = os.stat(line)
                size = st.st_size
            except OSError:
                size = 0
            out.append({"FullName": line, "Length": size, "LastWriteTime": ""})
        return out

    def _lin_trash(self) -> dict:
        trash = Path.home() / ".local" / "share" / "Trash" / "files"
        try:
            if not trash.exists():
                return {"ItemCount": 0}
            return {"ItemCount": sum(1 for _ in trash.iterdir())}
        except (PermissionError, OSError):
            return {"ItemCount": "unknown"}

    def _lin_disk_encryption(self) -> list:
        out: list[dict] = []
        raw = self._sh(
            "lsblk -rno NAME,FSTYPE,MOUNTPOINT,TYPE 2>/dev/null"
        )
        crypt_mounts: dict[str, str] = {}
        crypt_names: set[str] = set()
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            name = parts[0]
            fstype = parts[1]
            mount = parts[2] if len(parts) >= 3 else ""
            dtype = parts[3] if len(parts) >= 4 else ""
            if fstype == "crypto_LUKS":
                crypt_names.add(name)
            if dtype == "crypt":
                crypt_mounts[name] = mount

        for name in crypt_names:
            out.append({
                "MountPoint": crypt_mounts.get(name) or "(locked)",
                "EncryptionMethod": "LUKS",
                "ProtectionStatus": "On",
                "EncryptionPercentage": 100,
                "VolumeStatus": "Encrypted" if crypt_mounts.get(name) else "Locked",
                "Device": name,
            })

        if not out:
            out.append({
                "MountPoint": "/",
                "EncryptionMethod": "None",
                "ProtectionStatus": "Off",
                "EncryptionPercentage": 0,
                "VolumeStatus": "Unencrypted",
            })
        return out

    def _lin_shadow_perms(self) -> dict:
        path = Path("/etc/shadow")
        try:
            if not path.exists():
                return {"present": False}
            st = path.stat()
            mode = stat.S_IMODE(st.st_mode)
            return {
                "present": True,
                "mode_octal": oct(mode),
                "world_readable": bool(mode & stat.S_IROTH),
                "group_readable": bool(mode & stat.S_IRGRP),
                "owner_uid": st.st_uid,
                "owner_gid": st.st_gid,
            }
        except (PermissionError, OSError) as error:
            return {"present": True, "error": str(error)}

    def _lin_suid_binaries(self) -> list:
        raw = self._sh(
            "find / -xdev -type f -perm -4000 2>/dev/null | head -n 30"
        )
        return [{"Path": line.strip()} for line in raw.splitlines() if line.strip()]

    # ==================================================================
    # Shared.
    # ==================================================================

    def _find_sensitive_files(self) -> list:
        """Walk a curated set of paths for sensitive filename patterns.

        Config can override the directory set via
        ``scanners.filesystem.sensitive_paths``. Each path is resolved against
        the runtime user's home, so '~/.ssh' works.
        """
        config_paths = self.scanner_cfg.get("sensitive_paths")
        if config_paths:
            base_dirs = [Path(os.path.expanduser(str(p))) for p in config_paths]
        else:
            base_dirs = _default_sensitive_dirs()

        max_depth = int(self.scanner_cfg.get("max_depth", 3))
        found: list[dict] = []
        for base_dir in base_dirs:
            # base_dir.exists() can raise PermissionError when the stat itself
            # is denied (e.g. /root/.ssh as an unprivileged user). Skip those.
            try:
                if not base_dir.exists():
                    continue
            except (PermissionError, OSError):
                continue
            for pattern in SENSITIVE_PATTERNS:
                try:
                    matches: list[Path] = []
                    for m in base_dir.rglob(pattern):
                        try:
                            rel_parts = m.relative_to(base_dir).parts
                        except ValueError:
                            rel_parts = ()
                        if len(rel_parts) > max_depth:
                            continue
                        matches.append(m)
                        if len(matches) >= 10:
                            break
                    for m in matches:
                        try:
                            size = m.stat().st_size
                        except OSError:
                            size = 0
                        found.append({
                            "path": str(m),
                            "size_bytes": size,
                            "pattern": pattern,
                        })
                except (PermissionError, OSError):
                    pass
        return found
