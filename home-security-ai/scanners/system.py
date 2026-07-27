"""System scanner — OS version, patches, update config, security settings.

Windows side gathers Get-ComputerInfo, Get-HotFix, Defender, UAC, SMB, RDP,
AutoPlay. Linux side maps the same concepts to /etc/os-release, kernel, apt
upgradable packages, sshd_config, ufw, fail2ban, AppArmor, auditd.

Output keys are kept identical across platforms wherever possible so the
report renderer and Claude prompt continue to work unchanged. Linux-only
sections (sshd_config, ufw, apparmor, fail2ban) are exposed under their own
keys and simply absent from Windows scans.
"""

from __future__ import annotations

import json
import re
from .base import BaseScanner, IS_LINUX, IS_WINDOWS


class SystemScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "system"

    def run(self) -> dict:
        if IS_LINUX:
            return self._run_linux()
        if IS_WINDOWS:
            return self._run_windows()
        return {"status": "skipped", "reason": "unsupported platform"}

    # ==================================================================
    # Windows backend (unchanged behaviour from the original module).
    # ==================================================================

    def _run_windows(self) -> dict:
        return {
            "status": "completed",
            "platform": "windows",
            "os_info": self._win_os_info(),
            "hotfixes": self._win_hotfixes(),
            "windows_update": self._win_update_cfg(),
            "uac": self._win_uac(),
            "defender": self._win_defender(),
            "audit_policy": self._win_audit_policy(),
            "smb_settings": self._win_smb(),
            "rdp": self._win_rdp(),
            "auto_play": self._win_autoplay(),
        }

    def _win_os_info(self) -> dict:
        raw = self._ps(
            "Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, "
            "OsArchitecture, WindowsBuildLabEx, OsLastBootUpTime, "
            "CsName, CsDNSHostName | ConvertTo-Json"
        )
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _win_hotfixes(self) -> dict:
        raw = self._ps(
            "Get-HotFix | Sort-Object InstalledOn -Descending | "
            "Select-Object -First 20 HotFixID, InstalledOn, Description | ConvertTo-Json"
        )
        try:
            data = json.loads(raw) if raw else []
            if isinstance(data, dict):
                data = [data]
            return {"recent_patches": data, "count": len(data)}
        except Exception:
            return {"recent_patches": [], "count": 0}

    def _win_update_cfg(self) -> dict:
        raw = self._ps(r"""
$wu = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
$wuMain = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
[PSCustomObject]@{
    AutoUpdateEnabled   = if($wu) { $wu.NoAutoUpdate -eq 0 } else { $true }
    AUOptions           = if($wu) { $wu.AUOptions } else { "default" }
    WUServer            = if($wuMain) { $wuMain.WUServer } else { "Microsoft" }
} | ConvertTo-Json
""")
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _win_uac(self) -> dict:
        raw = self._ps(r"""
$uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
[PSCustomObject]@{
    EnableLUA            = $uac.EnableLUA
    ConsentPromptBehaviorAdmin = $uac.ConsentPromptBehaviorAdmin
    ConsentPromptBehaviorUser  = $uac.ConsentPromptBehaviorUser
    PromptOnSecureDesktop      = $uac.PromptOnSecureDesktop
} | ConvertTo-Json
""")
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _win_defender(self) -> dict:
        raw = self._ps(
            "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, "
            "AntispywareEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, "
            "OnAccessProtectionEnabled, AntivirusSignatureLastUpdated, "
            "AntispywareSignatureLastUpdated, NISEnabled | ConvertTo-Json"
        )
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _win_audit_policy(self) -> str:
        return self._cmd(["auditpol", "/get", "/category:*"])[:3000]

    def _win_smb(self) -> dict:
        raw = self._ps(
            "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, "
            "EnableSMB2Protocol, RequireSecuritySignature, "
            "EnableSecuritySignature | ConvertTo-Json"
        )
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _win_rdp(self) -> dict:
        raw = self._ps(r"""
$rdp = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
[PSCustomObject]@{
    RDPEnabled = if($rdp) { $rdp.fDenyTSConnections -eq 0 } else { $false }
    NLARequired = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication
} | ConvertTo-Json
""")
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _win_autoplay(self) -> dict:
        raw = self._ps(r"""
$ap = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ErrorAction SilentlyContinue
[PSCustomObject]@{
    NoDriveTypeAutoRun = if($ap) { $ap.NoDriveTypeAutoRun } else { "not set" }
    AutoRunDisabled    = if($ap) { $ap.NoDriveTypeAutoRun -eq 255 } else { $false }
} | ConvertTo-Json
""")
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    # ==================================================================
    # Linux backend.
    # ==================================================================

    def _run_linux(self) -> dict:
        return {
            "status": "completed",
            "platform": "linux",
            "os_info": self._lin_os_info(),
            "hotfixes": self._lin_recent_upgrades(),
            "windows_update": self._lin_update_cfg(),
            "uac": self._lin_sudo_policy(),                 # closest concept: sudo escalation policy
            "defender": self._lin_av_status(),              # closest concept: AV/AppArmor/SELinux
            "audit_policy": self._lin_audit_policy(),
            "smb_settings": self._lin_smb(),
            "rdp": self._lin_remote_access(),
            "auto_play": {"not_applicable": True},
            # Linux-only extras (richer signal for server posture):
            "sshd_config": self._lin_sshd_config(),
            "firewall": self._lin_firewall(),
            "fail2ban": self._lin_fail2ban(),
            "selinux": self._lin_selinux(),
        }

    def _lin_os_info(self) -> dict:
        os_release = self._parse_kv(self._read_file("/etc/os-release"))
        info = {
            "WindowsProductName": os_release.get("PRETTY_NAME", os_release.get("NAME", "Linux")),
            "WindowsVersion": os_release.get("VERSION_ID", ""),
            "OsArchitecture": self._cmd(["uname", "-m"]).strip(),
            "WindowsBuildLabEx": self._cmd(["uname", "-r"]).strip(),
            "OsLastBootUpTime": self._cmd(["uptime", "-s"]).strip(),
            "CsName": self._cmd(["hostname"]).strip(),
            "CsDNSHostName": self._cmd(["hostname", "-f"]).strip() or self._cmd(["hostname"]).strip(),
        }
        info["distro_id"] = os_release.get("ID", "")
        info["distro_id_like"] = os_release.get("ID_LIKE", "")
        info["kernel_version"] = info["WindowsBuildLabEx"]
        return info

    def _lin_recent_upgrades(self) -> dict:
        """Parse /var/log/dpkg.log for the 20 most recent upgrades.

        We avoid 'apt list --upgradable' because that needs the apt cache to be
        fresh and may take seconds. dpkg.log is local-only and instant.
        """
        log = self._read_file("/var/log/dpkg.log", max_bytes=256 * 1024)
        upgrades: list[dict] = []
        if log:
            pattern = re.compile(
                r"^(?P<date>\S+\s+\S+)\s+upgrade\s+(?P<pkg>\S+)\s+(?P<old>\S+)\s+(?P<new>\S+)"
            )
            for line in log.splitlines():
                m = pattern.match(line)
                if not m:
                    continue
                upgrades.append({
                    "HotFixID": m.group("pkg"),
                    "InstalledOn": m.group("date"),
                    "Description": f"upgraded {m.group('old')} -> {m.group('new')}",
                })
            upgrades = upgrades[-20:][::-1]  # newest first

        upgradable: list[str] = []
        # Only if apt is present AND it's been listed cheaply.
        if self._which("apt"):
            raw = self._sh(
                "apt list --upgradable 2>/dev/null | tail -n +2 | head -n 40"
            )
            for line in raw.splitlines():
                line = line.strip()
                if line:
                    upgradable.append(line)

        return {
            "recent_patches": upgrades,
            "count": len(upgrades),
            "pending_upgrades": upgradable,
            "pending_count": len(upgradable),
        }

    def _lin_update_cfg(self) -> dict:
        """Detect unattended-upgrades / auto-update posture."""
        unattended = self._read_file("/etc/apt/apt.conf.d/50unattended-upgrades")
        auto_upgrade = self._read_file("/etc/apt/apt.conf.d/20auto-upgrades")
        is_configured = bool(auto_upgrade) and "1" in auto_upgrade
        active = self._cmd(["systemctl", "is-active", "unattended-upgrades.service"]).strip()
        enabled = self._cmd(["systemctl", "is-enabled", "unattended-upgrades.service"]).strip()
        return {
            "AutoUpdateEnabled": is_configured or active == "active",
            "AUOptions": "unattended-upgrades" if is_configured else "manual",
            "WUServer": "apt",
            "service_active": active or "unknown",
            "service_enabled": enabled or "unknown",
            "has_unattended_config": bool(unattended),
        }

    def _lin_sudo_policy(self) -> dict:
        """Map UAC fields to sudo policy: who needs a password, who doesn't."""
        sudoers = self._read_file("/etc/sudoers", max_bytes=32768)
        nopasswd = "NOPASSWD" in sudoers
        # Drop-in /etc/sudoers.d/* files may relax password requirements:
        drop_in = self._sh("ls /etc/sudoers.d/ 2>/dev/null")
        return {
            "EnableLUA": True,  # sudo always requires explicit invocation
            "ConsentPromptBehaviorAdmin": "password_required" if not nopasswd else "nopasswd_present",
            "ConsentPromptBehaviorUser": "password_required",
            "PromptOnSecureDesktop": False,  # no equivalent on Linux
            "sudoers_has_nopasswd": nopasswd,
            "sudoers_drop_in_files": [f for f in drop_in.splitlines() if f.strip()],
        }

    def _lin_av_status(self) -> dict:
        """ClamAV / AppArmor / SELinux serve a similar role to Defender."""
        clamav_active = self._cmd(["systemctl", "is-active", "clamav-daemon.service"]).strip()
        apparmor_status = self._cmd(["systemctl", "is-active", "apparmor.service"]).strip()
        aa_count = ""
        if self._which("aa-status"):
            aa_count = self._sh("aa-status --enabled 2>/dev/null && echo enabled || echo disabled").strip()
        return {
            "AntivirusEnabled": clamav_active == "active",
            "RealTimeProtectionEnabled": clamav_active == "active",
            "AntispywareEnabled": False,
            "BehaviorMonitorEnabled": apparmor_status == "active",
            "IoavProtectionEnabled": False,
            "OnAccessProtectionEnabled": clamav_active == "active",
            "AntivirusSignatureLastUpdated": "",
            "AntispywareSignatureLastUpdated": "",
            "NISEnabled": False,
            "apparmor_active": apparmor_status,
            "apparmor_enabled": aa_count,
            "clamav_active": clamav_active,
        }

    def _lin_audit_policy(self) -> str:
        """auditd config + active rules. Mirrors Windows auditpol /get."""
        if not self._which("auditctl"):
            return "auditd not installed"
        rules = self._sh("auditctl -l 2>/dev/null | head -n 40")
        status = self._cmd(["systemctl", "is-active", "auditd.service"]).strip()
        return f"auditd status: {status}\n\nrules:\n{rules or '(none)'}"[:3000]

    def _lin_smb(self) -> dict:
        """Samba config: smb.conf flags that mirror Windows SMB hardening keys."""
        smb_conf = self._read_file("/etc/samba/smb.conf")
        return {
            "EnableSMB1Protocol": "ntlm auth = yes" in smb_conf.lower(),
            "EnableSMB2Protocol": True,
            "RequireSecuritySignature": "server signing = mandatory" in smb_conf.lower(),
            "EnableSecuritySignature": "server signing" in smb_conf.lower(),
            "samba_installed": bool(smb_conf),
        }

    def _lin_remote_access(self) -> dict:
        """SSH replaces RDP as the canonical remote access mechanism."""
        ssh_active = self._cmd(["systemctl", "is-active", "ssh.service"]).strip()
        if not ssh_active or ssh_active == "inactive":
            ssh_active = self._cmd(["systemctl", "is-active", "sshd.service"]).strip()
        sshd = self._read_file("/etc/ssh/sshd_config")
        permit_root = "yes" if re.search(r"^\s*PermitRootLogin\s+yes", sshd, re.MULTILINE) else "no"
        password_auth_off = bool(re.search(r"^\s*PasswordAuthentication\s+no", sshd, re.MULTILINE))
        return {
            "RDPEnabled": ssh_active == "active",
            "NLARequired": password_auth_off,
            "ssh_service_active": ssh_active or "unknown",
            "permit_root_login": permit_root,
            "password_auth_disabled": password_auth_off,
        }

    def _lin_sshd_config(self) -> dict:
        """Targeted sshd_config audit — eight hardening flags Lynis/CIS care about."""
        sshd = self._read_file("/etc/ssh/sshd_config")
        if not sshd:
            return {"present": False}

        def flag(name: str, want_no: bool = False, default: str = "") -> str:
            match = re.search(rf"^\s*{re.escape(name)}\s+(\S+)", sshd, re.MULTILINE | re.IGNORECASE)
            return match.group(1) if match else default

        return {
            "present": True,
            "PermitRootLogin": flag("PermitRootLogin"),
            "PasswordAuthentication": flag("PasswordAuthentication"),
            "PermitEmptyPasswords": flag("PermitEmptyPasswords"),
            "X11Forwarding": flag("X11Forwarding"),
            "ChallengeResponseAuthentication": flag("ChallengeResponseAuthentication"),
            "PubkeyAuthentication": flag("PubkeyAuthentication"),
            "MaxAuthTries": flag("MaxAuthTries"),
            "Protocol": flag("Protocol", default="2"),
            "LoginGraceTime": flag("LoginGraceTime"),
        }

    def _lin_firewall(self) -> dict:
        """Detect and summarize ufw / firewalld / iptables defaults."""
        if self._which("ufw"):
            raw = self._sh("ufw status verbose 2>/dev/null")
            default = re.search(r"Default:\s+(.+)", raw)
            active = "Status: active" in raw
            return {
                "tool": "ufw",
                "active": active,
                "default_policy": (default.group(1).strip() if default else ""),
                "raw_excerpt": raw[:600],
            }
        if self._which("firewall-cmd"):
            state = self._cmd(["firewall-cmd", "--state"]).strip()
            zones = self._cmd(["firewall-cmd", "--get-active-zones"]).strip()
            return {"tool": "firewalld", "active": state == "running", "active_zones": zones[:600]}
        if self._which("iptables"):
            raw = self._sh("iptables -L -n --line-numbers 2>/dev/null | head -n 40")
            return {"tool": "iptables", "active": bool(raw), "raw_excerpt": raw}
        return {"tool": "none", "active": False}

    def _lin_fail2ban(self) -> dict:
        if not self._which("fail2ban-client"):
            return {"installed": False}
        status = self._cmd(["systemctl", "is-active", "fail2ban.service"]).strip()
        jails = self._sh("fail2ban-client status 2>/dev/null | head -n 20")
        return {
            "installed": True,
            "service_active": status,
            "status_excerpt": jails[:600],
        }

    def _lin_selinux(self) -> dict:
        if self._which("getenforce"):
            return {"installed": True, "mode": self._cmd(["getenforce"]).strip()}
        return {"installed": False}

    # ----- helpers --------------------------------------------------

    @staticmethod
    def _parse_kv(text: str) -> dict:
        """Parse simple KEY=value lines (os-release style), stripping quotes."""
        out: dict[str, str] = {}
        for line in text.splitlines():
            if "=" not in line or line.lstrip().startswith("#"):
                continue
            key, _, val = line.partition("=")
            out[key.strip()] = val.strip().strip('"').strip("'")
        return out
