"""Unmanaged-software discovery — programs the package manager does not know about.

The software scanner reads dpkg, so anything built from source or copied into
/usr/local, /opt or /srv (PHP in the official php image, Apache built from
source, a vendored nginx/redis) is invisible to CVE matching. This module
finds those binaries and reads their version so the software scanner can feed
them to cve-matcher like any other package.

Safety (this runs on the target):
  * Only binaries whose file name is on the ALLOWLIST below are ever executed,
    never arbitrary files, so a planted binary with another name is not run.
  * Binaries in world-writable locations (or under /tmp, /dev/shm, /var/tmp)
    are not executed; they are reported with no version instead.
  * Executed with a 5 s timeout, no shell, a minimal environment, cwd="/".
  * Read-only otherwise: only reads /proc, stats files, and asks dpkg/rpm
    who owns a path.

Everything that touches the machine is injected through ``Probes`` so the
logic is unit-testable on any OS.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# --------------------------------------------------------------------------
# What we know how to identify
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ProgramSpec:
    key: str                       # stable id, also the DisplayName used downstream
    binaries: tuple[str, ...]      # file names that identify this program
    version_args: tuple[str, ...]  # argv after the binary that prints the version
    version_regex: str             # group 1 = version
    product: str                   # KEV product spelling (cve-matcher matches on it)
    cpe: str = ""                  # NVD "vendor:product"; lets cve-matcher query NVD without a table


# `product` strings are the CISA KEV spellings; vendor is left empty on purpose
# so cve-matcher falls back to product-only matching (KEV spreads e.g. PHP over
# two vendor names, "PHP Group" and "PHP").
SPECS: tuple[ProgramSpec, ...] = (
    ProgramSpec("php", ("php", "php-cgi"), ("-v",), r"PHP (\d+\.\d+\.\d+[^\s]*)", "PHP", "php:php"),
    ProgramSpec("php-fpm", ("php-fpm",), ("-v",), r"PHP (\d+\.\d+\.\d+[^\s]*)",
                "FastCGI Process Manager (FPM)", "php:php"),
    ProgramSpec("apache-httpd", ("httpd", "apache2"), ("-v",), r"Apache/(\d+\.\d+\.\d+)",
                "HTTP Server", "apache:http_server"),
    ProgramSpec("nginx", ("nginx",), ("-v",), r"nginx/(\d+\.\d+\.\d+)", "nginx", "f5:nginx"),
    ProgramSpec("redis", ("redis-server",), ("--version",), r"v=(\d+\.\d+\.\d+)", "Redis", "redis:redis"),
    ProgramSpec("tomcat", ("catalina.sh",), ("version",), r"Server number:\s*(\d+\.\d+\.\d+)",
                "Tomcat", "apache:tomcat"),
    ProgramSpec("openssl", ("openssl",), ("version",), r"OpenSSL (\d+\.\d+\.\d+[a-z]*)",
                "OpenSSL", "openssl:openssl"),
    ProgramSpec("exim", ("exim", "exim4"), ("-bV",), r"Exim version (\d+\.\d+(?:\.\d+)?)", "Exim", "exim:exim"),
    ProgramSpec("sudo", ("sudo",), ("-V",), r"Sudo version (\d+\.\d+\.\d+[^\s]*)", "Sudo", "sudo_project:sudo"),
    ProgramSpec("git", ("git",), ("--version",), r"git version (\d+\.\d+\.\d+)", "Git", "git-scm:git"),
    ProgramSpec("ghostscript", ("gs",), ("--version",), r"^(\d+\.\d+(?:\.\d+)?)", "Ghostscript",
                "artifex:ghostscript"),
    ProgramSpec("imagemagick", ("convert", "magick"), ("-version",),
                r"ImageMagick (\d+\.\d+\.\d+-?\d*)", "ImageMagick", "imagemagick:imagemagick"),
    # Common network daemons. The version flag and output shape are each project's documented
    # one; entries marked UNVERIFIED have not been run against a real binary in this project.
    ProgramSpec("samba", ("smbd",), ("-V",), r"Version (\d+\.\d+\.\d+)", "Samba", "samba:samba"),
    ProgramSpec("postgresql", ("postgres",), ("--version",), r"\(PostgreSQL\) (\d+\.\d+(?:\.\d+)?)",
                "PostgreSQL", "postgresql:postgresql"),
    ProgramSpec("mongodb", ("mongod",), ("--version",), r"db version v(\d+\.\d+\.\d+)", "MongoDB",
                "mongodb:mongodb"),
    ProgramSpec("memcached", ("memcached",), ("-V",), r"memcached (\d+\.\d+\.\d+)", "Memcached",
                "memcached:memcached"),
    ProgramSpec("haproxy", ("haproxy",), ("-v",), r"HAProxy version (\d+\.\d+\.\d+)", "HAProxy",
                "haproxy:haproxy"),
    ProgramSpec("squid", ("squid",), ("-v",), r"Squid Cache: Version (\d+\.\d+(?:\.\d+)?)", "Squid",
                "squid-cache:squid"),
    ProgramSpec("vsftpd", ("vsftpd",), ("-v",), r"version (\d+\.\d+\.\d+)", "vsftpd",
                "vsftpd_project:vsftpd"),
    ProgramSpec("proftpd", ("proftpd",), ("-v",), r"Version (\d+\.\d+\.\d+[a-z]*)", "ProFTPD",
                "proftpd:proftpd"),
    ProgramSpec("dovecot", ("dovecot",), ("--version",), r"^(\d+\.\d+\.\d+)", "Dovecot", "dovecot:dovecot"),
    ProgramSpec("openvpn", ("openvpn",), ("--version",), r"OpenVPN (\d+\.\d+\.\d+)", "OpenVPN",
                "openvpn:openvpn"),
    ProgramSpec("bind", ("named",), ("-v",), r"BIND (\d+\.\d+\.\d+)", "BIND", "isc:bind"),
    ProgramSpec("dnsmasq", ("dnsmasq",), ("--version",), r"Dnsmasq version (\d+\.\d+)", "Dnsmasq",
                "thekelleys:dnsmasq"),
    ProgramSpec("lighttpd", ("lighttpd",), ("-v",), r"lighttpd/(\d+\.\d+\.\d+)", "lighttpd",
                "lighttpd:lighttpd"),
    ProgramSpec("nodejs", ("node",), ("--version",), r"^v(\d+\.\d+\.\d+)", "Node.js", "nodejs:node.js"),
)

_SPEC_BY_BINARY: dict[str, ProgramSpec] = {b: s for s in SPECS for b in s.binaries}

# Where unmanaged installs usually live. Directories are listed (depth 1);
# the *_WALK roots are searched a few levels down (e.g. /opt/tomcat/bin).
SEARCH_DIRS = (
    "/usr/local/bin", "/usr/local/sbin",
    "/usr/local/apache2/bin", "/usr/local/nginx/sbin", "/usr/local/php/bin",
)
WALK_ROOTS = ("/opt", "/srv", "/usr/local")
WALK_MAX_DEPTH = 4

UNSAFE_PREFIXES = ("/tmp/", "/dev/shm/", "/var/tmp/")
MAX_UNMANAGED_RUNNING = 50
VERSION_TIMEOUT_S = 5


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------


def parse_version(spec: ProgramSpec, output: str) -> str:
    """Pull a version out of a program's version output; "" if not found."""
    m = re.search(spec.version_regex, output or "", re.MULTILINE)
    return m.group(1) if m else ""


def is_unsafe_to_execute(path: str, mode: int | None = None) -> bool:
    """True for locations/permissions where running the file is not safe."""
    if path.startswith(UNSAFE_PREFIXES):
        return True
    if mode is not None and (mode & stat.S_IWOTH):
        return True
    return False


# --------------------------------------------------------------------------
# Machine access, injectable for tests
# --------------------------------------------------------------------------


@dataclass
class Probes:
    # () -> existing executable candidate paths (not yet realpath-ed)
    find_binaries: Callable[[], list[str]]
    # path -> bool: is the file/containing dir writable by "other"
    mode_of: Callable[[str], int | None]
    # (path, args) -> combined stdout+stderr ("" on failure)
    run_version: Callable[[str, tuple[str, ...]], str]
    # realpath -> owning package name or None
    owner_of: Callable[[str], str | None]
    # () -> {realpath: [pid, ...]} for running processes
    running_exes: Callable[[], dict[str, list[int]]]
    realpath: Callable[[str], str] = os.path.realpath


@dataclass
class UnmanagedResult:
    binaries: list[dict] = field(default_factory=list)          # identified, with version
    running_unmanaged: list[dict] = field(default_factory=list)  # running, unowned, not identified
    notes: list[str] = field(default_factory=list)


def collect(probes: Probes) -> UnmanagedResult:
    """Find unmanaged, identifiable binaries + running binaries no package owns."""
    result = UnmanagedResult()
    running = probes.running_exes()
    running_real = {probes.realpath(p): pids for p, pids in running.items()}

    # --- identifiable binaries (allowlist) -------------------------------
    seen_real: set[str] = set()
    for path in probes.find_binaries():
        spec = _SPEC_BY_BINARY.get(os.path.basename(path))
        if spec is None:
            continue
        real = probes.realpath(path)
        if real in seen_real:
            continue
        seen_real.add(real)
        owner = probes.owner_of(real)
        if owner:
            continue  # the package manager knows it; the dpkg path covers it

        mode = probes.mode_of(real)
        version = ""
        if is_unsafe_to_execute(real, mode):
            result.notes.append(f"not executed (unsafe location/permissions): {real}")
        else:
            version = parse_version(spec, probes.run_version(real, spec.version_args))
            if not version:
                result.notes.append(f"version not readable for {real}")

        pids = running_real.get(real, [])
        result.binaries.append({
            "name": spec.key,
            "product": spec.product,
            "cpe": spec.cpe,
            "version": version,
            "path": real,
            "running": bool(pids),
            "pids": pids,
            "managed_by_package": False,
        })

    # --- running binaries nobody owns and we could not identify ----------
    identified = {b["path"] for b in result.binaries}
    extra: list[dict] = []
    for real, pids in sorted(running_real.items()):
        if real in identified:
            continue
        if probes.owner_of(real):
            continue
        extra.append({"path": real, "pids": pids, "managed_by_package": False})
    result.running_unmanaged = extra[:MAX_UNMANAGED_RUNNING]
    if len(extra) > MAX_UNMANAGED_RUNNING:
        result.notes.append(f"running_unmanaged truncated to {MAX_UNMANAGED_RUNNING} of {len(extra)}")
    return result


def to_installed_apps(result: UnmanagedResult) -> list[dict]:
    """Shape identified binaries like the software scanner's installed_apps rows.

    Rows without a version are dropped: a name-only package would match KEV by
    name alone and flag every CVE of that product regardless of version.
    """
    apps = []
    for b in result.binaries:
        if not b["version"]:
            continue
        apps.append({
            "DisplayName": b["name"],
            "DisplayVersion": b["version"],
            "Publisher": "",
            "InstallDate": "",
            "Product": b["product"],
            "Source": "unmanaged-binary",
            "Path": b["path"],
            "Running": b["running"],
            **({"Cpe": b["cpe"]} if b.get("cpe") else {}),
        })
    return apps


# --------------------------------------------------------------------------
# Real (Linux) probes
# --------------------------------------------------------------------------


def _find_binaries_linux() -> list[str]:
    found: list[str] = []
    names = set(_SPEC_BY_BINARY)
    for d in SEARCH_DIRS:
        try:
            for entry in os.scandir(d):
                if entry.name in names and entry.is_file() and os.access(entry.path, os.X_OK):
                    found.append(entry.path)
        except OSError:
            continue
    for root in WALK_ROOTS:
        if not os.path.isdir(root):
            continue
        base_depth = root.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if dirpath.count("/") - base_depth >= WALK_MAX_DEPTH:
                dirnames[:] = []
            for fn in filenames:
                if fn in names:
                    p = os.path.join(dirpath, fn)
                    if os.access(p, os.X_OK):
                        found.append(p)
    return found


def _mode_of_linux(path: str) -> int | None:
    """Permission bits of the file OR its directory (a writable dir lets anyone swap the file)."""
    try:
        file_mode = os.stat(path).st_mode
        dir_mode = os.stat(os.path.dirname(path) or "/").st_mode
        return file_mode | (dir_mode & stat.S_IWOTH)
    except OSError:
        return None


def _run_version_linux(path: str, args: tuple[str, ...]) -> str:
    try:
        proc = subprocess.run(
            [path, *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=VERSION_TIMEOUT_S, cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
        return (proc.stdout or "") + "\n" + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return ""


def _owner_of_linux(path: str) -> str | None:
    for argv in (["dpkg-query", "-S", path], ["rpm", "-qf", "--qf", "%{NAME}", path]):
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip().split(":")[0].split()[0]
    return _apk_owner(path)


def _apk_owner(path: str) -> str | None:
    """Alpine: `apk info -W <path>` prints '<path> is owned by <name>-<version>-r<N>'."""
    try:
        proc = subprocess.run(["apk", "info", "-W", path], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"is owned by (\S+)", proc.stdout or "")
    if not m:
        return None
    return re.sub(r"-\d.*$", "", m.group(1)) or None


def _running_exes_linux() -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return out
    own = {os.getpid(), os.getppid()}  # the scanner itself (PyInstaller runs as parent+child)
    for pid in pids:
        if int(pid) in own:
            continue
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            continue  # kernel thread or no permission
        if exe.endswith(" (deleted)"):
            exe = exe[: -len(" (deleted)")]
        out.setdefault(exe, []).append(int(pid))
    return out


def linux_probes() -> Probes:
    return Probes(
        find_binaries=_find_binaries_linux,
        mode_of=_mode_of_linux,
        run_version=_run_version_linux,
        owner_of=_owner_of_linux,
        running_exes=_running_exes_linux,
    )
