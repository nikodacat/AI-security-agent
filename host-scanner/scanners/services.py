"""Service configuration facts: what is listening, and how the web stack is configured.

Many "is this CVE actually exploitable here?" questions are config questions:
is mod_proxy loaded, is mod_cgi loaded, does PHP expose itself or allow
remote includes, which process owns port 80 and what address is it bound to.
Today the analyzer has to guess these from a version banner or an LLM probe.
This scanner reads them as facts.

Everything here is read-only and executes nothing: it parses /proc/net/tcp*,
/proc/<pid>/{fd,exe,cmdline} and configuration files only.
"""

from __future__ import annotations

import os
import re
import socket
from dataclasses import dataclass, field
from typing import Callable

from .base import BaseScanner, IS_LINUX
from .ecosystems import Fs, linux_fs

MAX_DIRECTIVES = 120
CONF_READ_BYTES = 200_000

APACHE_CONF_DIRS = ("/etc/apache2", "/usr/local/apache2/conf", "/etc/httpd")
NGINX_CONF_DIRS = ("/etc/nginx", "/usr/local/nginx/conf")
PHP_INI_DIRS = ("/usr/local/etc/php", "/etc/php", "/etc")

APACHE_INTERESTING = re.compile(
    r"^\s*(DocumentRoot|ScriptAlias|AddHandler|SetHandler|ProxyPass|ProxyPassMatch|"
    r"ProxyPassReverse|ProxyRequests|Options|Require|AllowOverride|ServerTokens|"
    r"ServerSignature|TraceEnable|Listen|LoadModule|<Directory|<VirtualHost|"
    r"RewriteRule|RewriteEngine|AddType|php_flag|php_value)\b", re.IGNORECASE)
NGINX_INTERESTING = re.compile(
    r"^\s*(listen|server_name|root|proxy_pass|fastcgi_pass|autoindex|"
    r"ssl_protocols|server_tokens|location|client_max_body_size)\b", re.IGNORECASE)
PHP_KEYS = (
    "expose_php", "disable_functions", "allow_url_include", "allow_url_fopen",
    "display_errors", "open_basedir", "enable_dl", "file_uploads",
    "upload_max_filesize", "session.use_strict_mode", "register_argc_argv",
)


# --------------------------------------------------------------------------
# Pure parsers
# --------------------------------------------------------------------------


def _decode_addr(hex_ip: str) -> str:
    """/proc/net/tcp little-endian hex address -> dotted/colon text."""
    raw = bytes.fromhex(hex_ip)
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw[::-1])
    # IPv6: four 32-bit words, each little-endian
    words = [raw[i:i + 4][::-1] for i in range(0, 16, 4)]
    return socket.inet_ntop(socket.AF_INET6, b"".join(words))


def parse_proc_net_tcp(text: str, family: str) -> list[dict]:
    """Listening sockets (state 0A) from /proc/net/tcp or tcp6."""
    out = []
    for line in (text or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10 or parts[3] != "0A":
            continue
        try:
            ip_hex, port_hex = parts[1].split(":")
            out.append({
                "bind": _decode_addr(ip_hex),
                "port": int(port_hex, 16),
                "family": family,
                "inode": int(parts[9]),
            })
        except (ValueError, OSError):
            continue
    return out


def is_loopback(bind: str) -> bool:
    return bind.startswith("127.") or bind == "::1"


def parse_loaded_modules(files: dict[str, str]) -> list[str]:
    """Apache module names from `LoadModule x_module ...` lines and mods-enabled/*.load."""
    mods: set[str] = set()
    for path, text in files.items():
        for line in text.splitlines():
            m = re.match(r"^\s*LoadModule\s+(\S+)\s+\S+", line)
            if m:
                mods.add(m.group(1))
        if path.endswith(".load") and "mods-enabled" in path:
            base = os.path.basename(path)[: -len(".load")]
            mods.add(base if base.endswith("_module") else f"{base}_module")
    return sorted(mods)


def grep_directives(text: str, pattern: re.Pattern, source: str, limit: int) -> list[str]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if pattern.match(line):
            out.append(f"{source}:{i}: {stripped[:200]}")
            if len(out) >= limit:
                break
    return out


def parse_php_ini(text: str) -> dict[str, str]:
    """Selected php.ini keys; last assignment wins, comments ignored."""
    found: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith((";", "#", "[")):
            continue
        m = re.match(r"^([A-Za-z0-9_.]+)\s*=\s*(.*?)\s*(?:;.*)?$", line)
        if m and m.group(1) in PHP_KEYS:
            found[m.group(1)] = m.group(2).strip('"\' ')
    return found


# --------------------------------------------------------------------------
# Machine access (injectable) and orchestration
# --------------------------------------------------------------------------


@dataclass
class Proc:
    net_tcp: str
    net_tcp6: str
    socket_owners: Callable[[], dict[int, list[int]]]   # inode -> pids
    exe_of: Callable[[int], str]
    cmdline_of: Callable[[int], str]


@dataclass
class ServicesResult:
    listening: list[dict] = field(default_factory=list)
    apache: dict = field(default_factory=dict)
    nginx: dict = field(default_factory=dict)
    php: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"listening": self.listening, "apache": self.apache,
                "nginx": self.nginx, "php": self.php, "notes": self.notes}


def _conf_files(fs: Fs, roots: tuple[str, ...], suffixes: tuple[str, ...]) -> list[str]:
    paths: list[str] = []
    for root in roots:
        if not fs.isdir(root):
            continue
        for dirpath, _dirs, files in fs.walk(root, 4):
            for fn in files:
                if fn.endswith(suffixes):
                    paths.append(f"{dirpath.rstrip('/')}/{fn}")
    return sorted(paths)


def collect_listening(proc: Proc) -> list[dict]:
    socks = parse_proc_net_tcp(proc.net_tcp, "ipv4") + parse_proc_net_tcp(proc.net_tcp6, "ipv6")
    owners = proc.socket_owners()
    out = []
    for s in sorted(socks, key=lambda x: (x["port"], x["family"])):
        pids = owners.get(s["inode"], [])
        first = pids[0] if pids else None
        out.append({
            "port": s["port"], "bind": s["bind"], "family": s["family"],
            "loopback_only": is_loopback(s["bind"]),
            "pids": pids[:8],
            "exe": proc.exe_of(first) if first is not None else "",
            "cmdline": proc.cmdline_of(first)[:200] if first is not None else "",
        })
    return out


def collect_apache(fs: Fs) -> dict:
    # Debian layout: *-available/ holds every installed module/site/conf, only
    # *-enabled/ (symlinks) is actually loaded. Counting "available" would
    # report mod_proxy/mod_cgi as loaded on every Debian Apache.
    paths = [p for p in _conf_files(fs, APACHE_CONF_DIRS, (".conf", ".load"))
             if "-available/" not in p]
    if not paths:
        return {}
    texts = {p: fs.read(p) for p in paths}
    directives: list[str] = []
    for p, t in texts.items():
        if p.endswith(".conf"):
            directives += grep_directives(t, APACHE_INTERESTING, p, MAX_DIRECTIVES)
    mods = parse_loaded_modules(texts)
    return {
        "config_files": paths[:60],
        "modules": mods,
        "has_mod_proxy": any(m.startswith("proxy") for m in mods),
        "has_mod_cgi": any(m in ("cgi_module", "cgid_module") for m in mods),
        "has_mod_php": any(m.startswith("php") for m in mods),
        "has_mod_rewrite": "rewrite_module" in mods,
        "directives": directives[:MAX_DIRECTIVES],
    }


def collect_nginx(fs: Fs) -> dict:
    paths = _conf_files(fs, NGINX_CONF_DIRS, (".conf",))
    if not paths:
        return {}
    directives: list[str] = []
    for p in paths:
        directives += grep_directives(fs.read(p), NGINX_INTERESTING, p, MAX_DIRECTIVES)
    return {"config_files": paths[:60], "directives": directives[:MAX_DIRECTIVES]}


def collect_php(fs: Fs) -> dict:
    paths = [p for p in _conf_files(fs, PHP_INI_DIRS, (".ini",))
             if "/php" in p or os.path.basename(p) == "php.ini"]
    if not paths:
        return {}
    settings: dict[str, str] = {}
    # PHP reads php.ini first, then conf.d/*.ini alphabetically; later wins.
    for p in sorted(paths, key=lambda x: ("/conf.d/" in x, x)):
        settings.update(parse_php_ini(fs.read(p)))
    return {"ini_files": paths[:30], "settings": settings}


def collect(fs: Fs, proc: Proc | None) -> ServicesResult:
    r = ServicesResult()
    steps = [("apache", lambda: collect_apache(fs)),
             ("nginx", lambda: collect_nginx(fs)),
             ("php", lambda: collect_php(fs))]
    if proc is not None:
        steps.insert(0, ("listening", lambda: collect_listening(proc)))
    for name, fn in steps:
        try:
            setattr(r, name, fn())
        except Exception as e:  # one failing collector must not hide the others
            r.notes.append(f"{name} failed: {type(e).__name__}: {e}")
    return r


# --------------------------------------------------------------------------
# Real (Linux) /proc access
# --------------------------------------------------------------------------


def _read_proc(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(CONF_READ_BYTES)
    except OSError:
        return ""


def _socket_owners_linux() -> dict[int, list[int]]:
    owners: dict[int, list[int]] = {}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return owners
    for pid in pids:
        fd_dir = f"/proc/{pid}/fd"
        try:
            for fd in os.listdir(fd_dir):
                try:
                    link = os.readlink(f"{fd_dir}/{fd}")
                except OSError:
                    continue
                m = re.match(r"socket:\[(\d+)\]", link)
                if m:
                    owners.setdefault(int(m.group(1)), [])
                    if int(pid) not in owners[int(m.group(1))]:
                        owners[int(m.group(1))].append(int(pid))
        except OSError:
            continue
    return owners


def _exe_of_linux(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe").replace(" (deleted)", "")
    except OSError:
        return ""


def _cmdline_of_linux(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            return fh.read(2000).replace(b"\0", b" ").decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def linux_proc() -> Proc:
    return Proc(
        net_tcp=_read_proc("/proc/net/tcp"), net_tcp6=_read_proc("/proc/net/tcp6"),
        socket_owners=_socket_owners_linux, exe_of=_exe_of_linux, cmdline_of=_cmdline_of_linux,
    )


class ServicesScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "services"

    def run(self) -> dict:
        if not IS_LINUX:
            return {"status": "skipped", "reason": "services scanner is Linux-only"}
        result = collect(linux_fs(), linux_proc())
        return {"status": "completed", "platform": "linux", **result.to_dict()}
