"""Filesystem exposure findings: dangerous permissions and leaked files.

Read-only: walks bounded directories and stats files. Reports PATHS, sizes,
modes and booleans. It never returns file contents; the one content check
(does a *.pem/*.key hold a private key?) reads a few bytes and reports only a
yes/no.

Findings use the same normalized shape as the posture scanner
({id, severity, title, evidence}).
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from typing import Callable

from .base import BaseScanner, IS_LINUX
from .ecosystems import Fs, linux_fs
from .posture import Finding

MAX_FILES_VISITED = 200_000
MAX_FINDINGS_PER_KIND = 40
WALK_DEPTH = 5

SUID_ROOTS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local", "/opt", "/srv", "/home", "/tmp", "/var/www")
STANDARD_BIN_DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/")
WORLD_WRITABLE_ROOTS = ("/etc", "/usr/local/bin", "/usr/local/sbin")
WEB_ROOTS = ("/var/www", "/srv", "/opt", "/app", "/usr/share/nginx")
CAP_ROOTS = ("/usr/local", "/opt", "/srv", "/home", "/tmp", "/var/www")

# Names that are normally SUID/SGID in standard directories on Debian/Ubuntu/Alpine.
SUID_BASELINE = {
    "passwd", "su", "sudo", "sudoedit", "mount", "umount", "chsh", "chfn", "gpasswd", "newgrp",
    "ping", "ping6", "unix_chkpwd", "pt_chown", "expiry", "chage", "wall", "write", "ssh-agent",
    "dotlockfile", "mail-lock", "mail-touchlock", "mail-unlock", "crontab", "at", "fusermount",
    "fusermount3", "pkexec", "polkit-agent-helper-1", "ssh-keysign", "dbus-daemon-launch-helper",
    "bsd-write", "mlocate", "locate", "plocate", "ssmtp", "Xorg.wrap",
}

# Linux capability bit numbers worth flagging when set on a regular file.
DANGEROUS_CAPS = {1: "cap_dac_override", 2: "cap_dac_read_search", 6: "cap_setgid", 7: "cap_setuid",
                  16: "cap_sys_module", 19: "cap_sys_ptrace", 21: "cap_sys_admin", 12: "cap_net_admin"}

LEAK_NAMES = (
    # (regex on file name, finding id, severity, title)
    (re.compile(r"^\.env(\.(?!example|sample|dist|template)[\w.-]+)?$"), "leak-dotenv", "high", ".env file in a web/app directory"),
    (re.compile(r"^\.htpasswd$"), "leak-htpasswd", "high", ".htpasswd file in a web/app directory"),
    (re.compile(r"\.(sql|sql\.gz|dump)$", re.I), "leak-sql-dump", "high", "Database dump in a web/app directory"),
    (re.compile(r"^(id_rsa|id_ed25519|id_ecdsa)$"), "leak-ssh-key", "high", "SSH private key in a web/app directory"),
    (re.compile(r"(\.bak|\.old|\.orig|\.save|\.swp|~)$", re.I), "leak-backup", "medium", "Editor/backup copy in a web/app directory"),
    (re.compile(r"^(phpinfo|info|test|i)\.php$", re.I), "leak-phpinfo", "medium", "Diagnostic PHP page in a web directory"),
    (re.compile(r"^(database|credentials|secrets)\.(yml|yaml|json)$", re.I), "leak-credentials-file", "medium", "Credentials-style config file"),
)
KEY_EXTS = (".pem", ".key")


@dataclass
class LeakHost:
    fs: Fs
    # path -> (mode, size, is_symlink) or None
    stat: Callable[[str], tuple[int, int, bool] | None]
    getxattr: Callable[[str, str], bytes | None]


def _cap(findings: dict[str, list[Finding]], kind: str, f: Finding) -> None:
    lst = findings.setdefault(kind, [])
    if len(lst) < MAX_FINDINGS_PER_KIND:
        lst.append(f)
    elif len(lst) == MAX_FINDINGS_PER_KIND:
        lst.append(Finding(f"{f.id}-truncated", "info", f"More {kind} findings omitted", f"capped at {MAX_FINDINGS_PER_KIND}"))


def decode_caps(blob: bytes | None) -> list[str]:
    """Names of dangerous capabilities in a security.capability xattr (permitted set)."""
    if not blob or len(blob) < 8:
        return []
    permitted = int.from_bytes(blob[4:8], "little")
    return [name for bit, name in sorted(DANGEROUS_CAPS.items()) if bit < 32 and permitted & (1 << bit)]


def _walk_files(host: LeakHost, roots, depth: int, budget: list[int]):
    for root in roots:
        if not host.fs.isdir(root):
            continue
        for dirpath, dirnames, filenames in host.fs.walk(root, depth):
            for dn in dirnames:
                yield dirpath, dn, True
            for fn in filenames:
                budget[0] -= 1
                if budget[0] < 0:
                    return
                yield dirpath, fn, False


def _join(a: str, b: str) -> str:
    return a.rstrip("/") + "/" + b


def collect(host: LeakHost) -> dict:
    kinds: dict[str, list[Finding]] = {}
    notes: list[str] = []
    suid_baseline_count = 0
    budget = [MAX_FILES_VISITED]
    seen: set[str] = set()

    # --- SUID/SGID + capabilities ---------------------------------------
    for dirpath, name, is_dir in _walk_files(host, SUID_ROOTS, WALK_DEPTH, budget):
        if is_dir:
            continue
        path = _join(dirpath, name)
        if path in seen:
            continue
        seen.add(path)
        st = host.stat(path)
        if st is None or st[2] or not stat.S_ISREG(st[0]):
            continue
        mode = st[0]
        if mode & (stat.S_ISUID | stat.S_ISGID):
            kind = "SUID" if mode & stat.S_ISUID else "SGID"
            standard = path.startswith(STANDARD_BIN_DIRS) and name in SUID_BASELINE
            if standard:
                suid_baseline_count += 1
            else:
                outside = not path.startswith(STANDARD_BIN_DIRS)
                _cap(kinds, "suid", Finding(
                    "suid-unusual-location" if outside else "suid-unknown-binary",
                    "high" if outside else "medium",
                    f"{kind} binary {'outside system directories' if outside else 'not on the usual list'}",
                    f"{path} mode={oct(mode & 0o7777)}"))
        if path.startswith(CAP_ROOTS) or path.startswith(STANDARD_BIN_DIRS):
            caps = decode_caps(host.getxattr(path, "security.capability"))
            if caps:
                _cap(kinds, "caps", Finding("file-capabilities", "medium",
                                            "File carries powerful Linux capabilities",
                                            f"{path}: {', '.join(caps)}"))

    # --- world-writable in sensitive places -----------------------------
    for dirpath, name, is_dir in _walk_files(host, WORLD_WRITABLE_ROOTS, WALK_DEPTH, budget):
        path = _join(dirpath, name)
        st = host.stat(path)
        if st is None or st[2]:
            continue
        mode = st[0]
        if not (mode & stat.S_IWOTH):
            continue
        if is_dir and mode & stat.S_ISVTX:
            continue  # sticky world-writable dir (like /tmp) is intentional
        _cap(kinds, "ww", Finding("world-writable-sensitive", "high",
                                  "World-writable path in a sensitive location",
                                  f"{path} mode={oct(mode & 0o7777)}"))

    # --- leaked files in web / app roots --------------------------------
    for dirpath, name, is_dir in _walk_files(host, WEB_ROOTS, WALK_DEPTH, budget):
        path = _join(dirpath, name)
        if is_dir:
            if name in (".git", ".svn", ".hg"):
                _cap(kinds, "leak", Finding("leak-vcs-dir", "high",
                                            f"{name} directory in a web/app directory (source + history exposure)", path))
            continue
        for rx, fid, sev, title in LEAK_NAMES:
            if rx.search(name):
                st = host.stat(path)
                size = st[1] if st else 0
                _cap(kinds, "leak", Finding(fid, sev, title, f"{path} ({size} bytes)"))
                break
        else:
            if name.endswith(KEY_EXTS):
                head = host.fs.read(path)[:200]
                if "PRIVATE KEY" in head:
                    _cap(kinds, "leak", Finding("leak-private-key", "high",
                                                "Private key file in a web/app directory", path))
            elif name == "wp-config.php":
                st = host.stat(path)
                if st and st[0] & stat.S_IROTH:
                    _cap(kinds, "leak", Finding("wp-config-world-readable", "medium",
                                                "wp-config.php readable by all local users",
                                                f"{path} mode={oct(st[0] & 0o7777)}"))
    if budget[0] < 0:
        notes.append(f"file budget of {MAX_FILES_VISITED} exhausted; scan incomplete")

    findings = [f for lst in kinds.values() for f in lst]
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda x: (order.get(x.severity, 9), x.id, x.evidence))
    return {"findings": [f.to_dict() for f in findings],
            "suid_baseline_binaries": suid_baseline_count, "notes": notes}


# --------------------------------------------------------------------------
# Real (Linux) access
# --------------------------------------------------------------------------


def _stat_linux(path: str):
    try:
        st = os.lstat(path)
        return st.st_mode, st.st_size, stat.S_ISLNK(st.st_mode)
    except OSError:
        return None


def _getxattr_linux(path: str, name: str):
    try:
        return os.getxattr(path, name, follow_symlinks=False)  # type: ignore[attr-defined]
    except (OSError, AttributeError):
        return None


def linux_leak_host() -> LeakHost:
    return LeakHost(fs=linux_fs(), stat=_stat_linux, getxattr=_getxattr_linux)


class LeaksScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "leaks"

    def run(self) -> dict:
        if not IS_LINUX:
            return {"status": "skipped", "reason": "leaks scanner is Linux-only"}
        return {"status": "completed", "platform": "linux", **collect(linux_leak_host())}
