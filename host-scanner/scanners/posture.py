"""Security-posture facts: configuration weaknesses that are not CVEs.

Complements the CVE-driven path. Reads (never executes, never modifies):
  * sshd_config            -> root login, password auth, empty passwords
  * sudoers                -> NOPASSWD / unrestricted entries
  * kernel sysctl          -> ASLR, kptr/dmesg restrict, ptrace scope, ...
  * container isolation    -> privileged capabilities, docker.sock, secret-named
                              environment variables (NAMES only, never values)
  * TLS certificates       -> expired / expiring / self-signed
  * OS and patch hygiene   -> end-of-life release, stale apt, no auto-updates,
                              reboot pending

Output is a list of normalized `findings` ({id, severity, title, evidence}) plus
the raw facts they were derived from. Evidence strings never contain secrets.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Callable

from .base import BaseScanner, IS_LINUX
from .ecosystems import Fs, linux_fs

STALE_APT_DAYS = 30
CERT_WARN_DAYS = 30
SECRET_ENV_RE = re.compile(r"(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL)", re.I)

# Approximate end-of-life dates (security support ended/ends). Static table:
# it ages and must be refreshed; findings quote the date so a reader can judge.
OS_EOL = {
    ("debian", "9"): date(2022, 6, 30), ("debian", "10"): date(2024, 6, 30),
    ("debian", "11"): date(2026, 8, 31), ("debian", "12"): date(2028, 6, 10),
    ("ubuntu", "16.04"): date(2021, 4, 30), ("ubuntu", "18.04"): date(2023, 5, 31),
    ("ubuntu", "20.04"): date(2025, 5, 31), ("ubuntu", "22.04"): date(2027, 4, 30),
    ("ubuntu", "24.04"): date(2029, 4, 30),
    ("alpine", "3.15"): date(2023, 11, 1), ("alpine", "3.16"): date(2024, 5, 23),
    ("alpine", "3.17"): date(2024, 11, 22), ("alpine", "3.18"): date(2025, 5, 9),
}

# sysctl key -> (predicate on int value that means "fine", why it matters)
SYSCTL_RULES = {
    "kernel/randomize_va_space": (lambda v: v == 2, "ASLR not fully enabled"),
    "kernel/kptr_restrict": (lambda v: v >= 1, "kernel pointers readable by unprivileged users"),
    "kernel/dmesg_restrict": (lambda v: v == 1, "dmesg readable by unprivileged users"),
    "kernel/yama/ptrace_scope": (lambda v: v >= 1, "any process may ptrace same-uid processes"),
    "kernel/unprivileged_bpf_disabled": (lambda v: v >= 1, "unprivileged BPF allowed"),
    "fs/protected_symlinks": (lambda v: v == 1, "symlink-following races in sticky dirs allowed"),
    "fs/protected_hardlinks": (lambda v: v == 1, "hardlink attacks in sticky dirs allowed"),
}


@dataclass
class Finding:
    id: str
    severity: str  # high | medium | low | info
    title: str
    evidence: str

    def to_dict(self) -> dict:
        return {"id": self.id, "severity": self.severity, "title": self.title, "evidence": self.evidence}


@dataclass
class Host:
    fs: Fs
    mtime: Callable[[str], float | None]
    now: Callable[[], datetime]
    decode_cert: Callable[[str], dict | None]


# --------------------------------------------------------------------------
# Pure parsers
# --------------------------------------------------------------------------


def parse_sshd_config(text: str) -> dict[str, str]:
    """Effective settings: first occurrence wins; stops at the first Match block."""
    out: dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        key = parts[0].lower()
        if key == "match":
            break
        if len(parts) == 2 and key not in out:
            out[key] = parts[1].strip().strip('"').lower() if key != "allowusers" else parts[1].strip()
    return out


def sshd_findings(cfg: dict[str, str]) -> list[Finding]:
    f: list[Finding] = []
    root = cfg.get("permitrootlogin")
    if root in ("yes", "without-password"):
        f.append(Finding("ssh-root-login", "high", "SSH allows root login",
                         f"PermitRootLogin {root}"))
    if cfg.get("passwordauthentication") == "yes":
        f.append(Finding("ssh-password-auth", "medium", "SSH password authentication enabled",
                         "PasswordAuthentication yes"))
    if cfg.get("permitemptypasswords") == "yes":
        f.append(Finding("ssh-empty-passwords", "high", "SSH permits empty passwords",
                         "PermitEmptyPasswords yes"))
    if cfg.get("x11forwarding") == "yes":
        f.append(Finding("ssh-x11-forwarding", "low", "SSH X11 forwarding enabled", "X11Forwarding yes"))
    return f


def sudoers_findings(files: dict[str, str]) -> list[Finding]:
    out: list[Finding] = []
    for path, text in files.items():
        for i, raw in enumerate((text or "").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith(("#", "Defaults", "@include")):
                continue
            if "NOPASSWD" in line:
                out.append(Finding("sudo-nopasswd", "high", "sudo entry without password",
                                   f"{path}:{i}: {line[:160]}"))
            elif "!authenticate" in line:
                out.append(Finding("sudo-no-authenticate", "high", "sudo authentication disabled",
                                   f"{path}:{i}: {line[:160]}"))
    return out


def parse_cap_eff(status_text: str) -> int | None:
    m = re.search(r"^CapEff:\s*([0-9a-fA-F]+)", status_text or "", re.MULTILINE)
    return int(m.group(1), 16) if m else None


def parse_status_field(status_text: str, name: str) -> str:
    m = re.search(rf"^{name}:\s*(.+)$", status_text or "", re.MULTILINE)
    return m.group(1).strip() if m else ""


def parse_os_release(text: str) -> dict[str, str]:
    out = {}
    for line in (text or "").splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


def os_eol_date(os_release: dict[str, str]) -> date | None:
    distro = os_release.get("ID", "").lower()
    ver = os_release.get("VERSION_ID", "")
    if distro == "alpine":
        ver = ".".join(ver.split(".")[:2])
    return OS_EOL.get((distro, ver))


def secret_env_names(environ_raw: str) -> list[str]:
    names = []
    for entry in (environ_raw or "").split("\0"):
        if "=" in entry:
            name = entry.split("=", 1)[0]
            if SECRET_ENV_RE.search(name):
                names.append(name)
    return sorted(set(names))


# Mounts Docker/containerd always add; not a configuration choice worth reporting.
DOCKER_MANAGED_MOUNTS = {"/etc/resolv.conf", "/etc/hostname", "/etc/hosts"}


def parse_mountinfo_binds(text: str) -> list[dict]:
    """Mounts backed by a real block/host filesystem (typical of docker bind mounts)."""
    host_fs = {"ext4", "xfs", "btrfs", "virtiofs", "9p", "fuseblk", "ext3", "zfs", "ntfs", "drvfs"}
    out = []
    for line in (text or "").splitlines():
        parts = line.split()
        if "-" not in parts:
            continue
        dash = parts.index("-")
        fstype = parts[dash + 1] if len(parts) > dash + 1 else ""
        if fstype in host_fs and len(parts) > 5 and parts[4] not in DOCKER_MANAGED_MOUNTS:
            out.append({"mount_point": parts[4], "root": parts[3], "fstype": fstype,
                        "readonly": "ro" in parts[5].split(",")})
    return out


# --------------------------------------------------------------------------
# Collectors
# --------------------------------------------------------------------------


def collect_ssh(host: Host) -> tuple[dict, list[Finding]]:
    paths = ["/etc/ssh/sshd_config"] + [f"/etc/ssh/sshd_config.d/{n}"
                                        for n in host.fs.listdir("/etc/ssh/sshd_config.d")
                                        if n.endswith(".conf")]
    text = "\n".join(host.fs.read(p) for p in paths if host.fs.isfile(p))
    if not text.strip():
        return {}, []
    cfg = parse_sshd_config(text)
    keep = ("permitrootlogin", "passwordauthentication", "permitemptypasswords", "port",
            "x11forwarding", "pubkeyauthentication", "maxauthtries", "allowusers")
    return {k: cfg[k] for k in keep if k in cfg}, sshd_findings(cfg)


def collect_sudo(host: Host) -> list[Finding]:
    files = {"/etc/sudoers": host.fs.read("/etc/sudoers")}
    for n in host.fs.listdir("/etc/sudoers.d"):
        files[f"/etc/sudoers.d/{n}"] = host.fs.read(f"/etc/sudoers.d/{n}")
    return sudoers_findings(files)


def collect_sysctl(host: Host) -> tuple[dict, list[Finding]]:
    values, findings = {}, []
    for key, (ok, why) in SYSCTL_RULES.items():
        raw = host.fs.read(f"/proc/sys/{key}").strip()
        if not raw.lstrip("-").isdigit():
            continue
        v = int(raw)
        values[key.replace("/", ".")] = v
        if not ok(v):
            findings.append(Finding(f"sysctl-{key.replace('/', '-')}", "low", why,
                                    f"{key.replace('/', '.')} = {v}"))
    return values, findings


def collect_container(host: Host) -> tuple[dict, list[Finding]]:
    cgroup = host.fs.read("/proc/1/cgroup")
    in_container = bool(re.search(r"docker|kubepods|containerd|lxc", cgroup)) or host.fs.isfile("/.dockerenv")
    if not in_container:
        return {"in_container": False}, []
    status = host.fs.read("/proc/self/status")
    cap = parse_cap_eff(status)
    uid_line = parse_status_field(host.fs.read("/proc/1/status"), "Uid")
    mounts = parse_mountinfo_binds(host.fs.read("/proc/self/mountinfo"))
    secrets = secret_env_names(host.fs.read("/proc/1/environ"))
    facts = {
        "in_container": True,
        "capabilities_effective": hex(cap) if cap is not None else None,
        "seccomp": parse_status_field(status, "Seccomp"),
        "no_new_privs": parse_status_field(status, "NoNewPrivs"),
        "init_uid": uid_line.split()[0] if uid_line else "",
        "docker_sock_present": host.fs.isfile("/var/run/docker.sock") or host.fs.isdir("/var/run/docker.sock"),
        "host_bind_mounts": mounts[:20],
        "secret_named_env_vars": secrets,
    }
    f: list[Finding] = []
    if cap is not None and cap >= 0x1FFFFFFFFF:  # (nearly) full capability set
        f.append(Finding("container-privileged", "high", "Container has (near-)full Linux capabilities",
                         f"CapEff={hex(cap)} (likely --privileged)"))
    if facts["docker_sock_present"]:
        f.append(Finding("container-docker-sock", "high", "Docker socket reachable inside the container",
                         "/var/run/docker.sock present (container escape / host takeover path)"))
    if facts["seccomp"] == "0":
        f.append(Finding("container-no-seccomp", "medium", "No seccomp filter applied", "Seccomp: 0"))
    if facts["init_uid"] == "0":
        f.append(Finding("container-runs-as-root", "low", "Main process runs as root", "PID 1 Uid 0"))
    if secrets:
        f.append(Finding("container-secret-env", "medium", "Secret-looking environment variable names",
                         "names only: " + ", ".join(secrets[:10])))
    return facts, f


def _cert_paths(host: Host) -> list[str]:
    paths: set[str] = set()
    for conf_root in ("/etc/apache2", "/etc/nginx", "/usr/local/apache2/conf", "/usr/local/nginx/conf"):
        if not host.fs.isdir(conf_root):
            continue
        for dirpath, _d, files in host.fs.walk(conf_root, 4):
            if "-available" in dirpath:
                continue
            for fn in files:
                if not fn.endswith((".conf", ".load")):
                    continue
                for m in re.finditer(r"^\s*(?:SSLCertificateFile|ssl_certificate)\s+(\S+?);?\s*$",
                                     host.fs.read(f"{dirpath}/{fn}"), re.MULTILINE):
                    paths.add(m.group(1))
    for d in ("/etc/letsencrypt/live",):
        for site in host.fs.listdir(d):
            paths.add(f"{d}/{site}/fullchain.pem")
    return sorted(p for p in paths if host.fs.isfile(p))


def collect_tls(host: Host) -> tuple[list[dict], list[Finding]]:
    certs, findings = [], []
    now = host.now()
    for path in _cert_paths(host)[:20]:
        info = host.decode_cert(path)
        if not info:
            continue
        not_after = info.get("not_after")
        entry = {"path": path, "subject": info.get("subject", ""), "issuer": info.get("issuer", ""),
                 "not_after": not_after.isoformat() if not_after else None}
        certs.append(entry)
        if not_after is not None:
            days = (not_after - now).days
            entry["days_left"] = days
            if days < 0:
                findings.append(Finding("tls-expired", "high", "TLS certificate expired",
                                        f"{path} expired {-days} day(s) ago"))
            elif days < CERT_WARN_DAYS:
                findings.append(Finding("tls-expiring", "medium", "TLS certificate expires soon",
                                        f"{path} expires in {days} day(s)"))
        if info.get("subject") and info.get("subject") == info.get("issuer"):
            findings.append(Finding("tls-self-signed", "low", "Self-signed TLS certificate", path))
    return certs, findings


def collect_hygiene(host: Host) -> tuple[dict, list[Finding]]:
    now = host.now()
    osr = parse_os_release(host.fs.read("/etc/os-release"))
    facts: dict = {"os": {k: osr.get(k, "") for k in ("ID", "VERSION_ID", "PRETTY_NAME")}}
    f: list[Finding] = []

    eol = os_eol_date(osr)
    if eol is not None:
        facts["os"]["eol_date"] = eol.isoformat()
        if now.date() > eol:
            f.append(Finding("os-eol", "high", "Operating system release is end-of-life",
                             f"{osr.get('PRETTY_NAME', osr.get('ID', ''))} security support ended {eol.isoformat()}"))

    stamp = host.mtime("/var/lib/apt/periodic/update-success-stamp") or host.mtime("/var/log/apt/history.log")
    if stamp is not None:
        days = int((now.timestamp() - stamp) // 86400)
        facts["apt_days_since_update"] = days
        if days > STALE_APT_DAYS:
            f.append(Finding("apt-stale", "medium", "Package lists/updates not refreshed recently",
                             f"last apt activity ~{days} day(s) ago"))
    dpkg = host.fs.read("/var/lib/dpkg/status")
    if dpkg:
        auto = "Package: unattended-upgrades\n" in dpkg
        facts["unattended_upgrades_installed"] = auto
        if not auto:
            f.append(Finding("no-auto-updates", "low", "unattended-upgrades is not installed",
                             "automatic security updates are not configured"))
    if host.fs.isfile("/var/run/reboot-required"):
        facts["reboot_required"] = True
        f.append(Finding("reboot-required", "medium", "Reboot pending after updates",
                         "/var/run/reboot-required exists"))
    return facts, f


def collect(host: Host) -> dict:
    result: dict = {"findings": [], "notes": []}
    findings: list[Finding] = []
    for name, fn in (("ssh", collect_ssh), ("sysctl", collect_sysctl), ("container", collect_container),
                     ("tls_certificates", collect_tls), ("hygiene", collect_hygiene)):
        try:
            facts, fs_ = fn(host)
            if facts:
                result[name] = facts
            findings += fs_
        except Exception as e:  # one broken collector must not hide the rest
            result["notes"].append(f"{name} failed: {type(e).__name__}: {e}")
    try:
        findings += collect_sudo(host)
    except Exception as e:
        result["notes"].append(f"sudo failed: {type(e).__name__}: {e}")
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda x: (order.get(x.severity, 9), x.id))
    result["findings"] = [x.to_dict() for x in findings]
    return result


# --------------------------------------------------------------------------
# Real (Linux) access
# --------------------------------------------------------------------------


def _mtime_linux(path: str) -> float | None:
    try:
        return os.stat(path).st_mtime
    except OSError:
        return None


def _decode_cert_linux(path: str) -> dict | None:
    """Parse a PEM certificate with the stdlib (private helper; best effort)."""
    try:
        import ssl
        d = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception:
        return None

    def name(parts) -> str:
        return ",".join(f"{k}={v}" for rdn in parts for (k, v) in rdn)

    try:
        not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(d["notAfter"]), tz=timezone.utc)
    except Exception:
        not_after = None
    return {"subject": name(d.get("subject", ())), "issuer": name(d.get("issuer", ())),
            "not_after": not_after}


def linux_host() -> Host:
    return Host(fs=linux_fs(), mtime=_mtime_linux, now=lambda: datetime.now(timezone.utc),
                decode_cert=_decode_cert_linux)


class PostureScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "posture"

    def run(self) -> dict:
        if not IS_LINUX:
            return {"status": "skipped", "reason": "posture scanner is Linux-only"}
        return {"status": "completed", "platform": "linux", **collect(linux_host())}
