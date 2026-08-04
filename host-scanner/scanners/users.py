"""Users scanner — local accounts, admin/sudo group, password policy, recent logons.

Cross-platform: Windows uses Get-LocalUser / Get-LocalGroupMember / net accounts.
Linux maps the same concepts to /etc/passwd + /etc/shadow + sudo / wheel group
+ /etc/login.defs + last(1).
"""

from __future__ import annotations

import json
import re

from .base import BaseScanner, IS_LINUX, IS_WINDOWS


class UsersScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "users"

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
            "local_users": self._win_local_users(),
            "admins": self._win_admins(),
            "password_policy": self._win_password_policy(),
            "logon_events": self._win_recent_logons(),
            "guest_account": self._win_guest(),
        }

    def _win_local_users(self) -> list:
        raw = self._ps(
            "Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, "
            "PasswordLastSet, LastLogon, PasswordNeverExpires, "
            "AccountExpires | ConvertTo-Json"
        )
        try:
            data = json.loads(raw) if raw else []
            if isinstance(data, dict):
                data = [data]
            return data
        except Exception:
            return []

    def _win_admins(self) -> list:
        raw = self._ps(
            "Get-LocalGroupMember -Group 'Administrators' | "
            "Select-Object Name, ObjectClass, PrincipalSource | ConvertTo-Json"
        )
        try:
            data = json.loads(raw) if raw else []
            if isinstance(data, dict):
                data = [data]
            return data
        except Exception:
            return []

    def _win_password_policy(self) -> dict:
        raw = self._ps(r"""
$policy = net accounts 2>&1
$lines = $policy -split "`n"
$result = @{}
foreach ($line in $lines) {
    if ($line -match "^(.+?):\s+(.+)$") {
        $result[$matches[1].Trim()] = $matches[2].Trim()
    }
}
$result | ConvertTo-Json
""")
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _win_recent_logons(self) -> list:
        raw = self._ps("""
try {
    Get-EventLog -LogName Security -InstanceId 4624 -Newest 20 -ErrorAction Stop |
    Select-Object TimeGenerated, Message |
    ForEach-Object {
        [PSCustomObject]@{
            Time = $_.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss')
            Message = $_.Message.Substring(0, [Math]::Min(200, $_.Message.Length))
        }
    } | ConvertTo-Json
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

    def _win_guest(self) -> dict:
        raw = self._ps(
            "Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue | "
            "Select-Object Name, Enabled | ConvertTo-Json"
        )
        try:
            return json.loads(raw) if raw else {"Name": "Guest", "Enabled": False}
        except Exception:
            return {}

    # ==================================================================
    # Linux backend.
    # ==================================================================

    def _run_linux(self) -> dict:
        return {
            "status": "completed",
            "platform": "linux",
            "local_users": self._lin_local_users(),
            "admins": self._lin_admins(),
            "password_policy": self._lin_password_policy(),
            "logon_events": self._lin_recent_logons(),
            "guest_account": self._lin_guest_like(),
            # Linux-only extras:
            "passwordless_accounts": self._lin_passwordless(),
            "nopasswd_sudoers": self._lin_nopasswd_sudoers(),
        }

    def _lin_local_users(self) -> list:
        """Parse /etc/passwd and enrich with shadow status + last login.

        Field mapping (matches Windows where it makes sense):
          Name                  -> username
          Enabled               -> shadow account NOT locked (not "!" / "*")
          PasswordRequired      -> shadow field is a real hash, not "!" / "*"
          PasswordLastSet       -> from /etc/shadow days-since-epoch (best effort)
          LastLogon             -> last(1) output for that user
          PasswordNeverExpires  -> /etc/shadow max-age == 99999 or empty
          AccountExpires        -> /etc/shadow account-expire date if set
          UID, GID, Shell       -> Linux extras
        """
        passwd = self._read_file("/etc/passwd")
        shadow_lines = self._read_file("/etc/shadow").splitlines()
        shadow = {}
        for line in shadow_lines:
            parts = line.split(":")
            if len(parts) >= 9:
                shadow[parts[0]] = parts

        users: list[dict] = []
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name = parts[0]
            try:
                uid = int(parts[2])
            except ValueError:
                uid = -1
            home = parts[5]
            shell = parts[6]

            shadow_entry = shadow.get(name)
            hash_field = shadow_entry[1] if shadow_entry else "?"
            password_required = bool(hash_field) and hash_field not in ("!", "*", "x", "")
            account_locked = hash_field.startswith("!") or hash_field == "*"
            try:
                pw_last_set_days = int(shadow_entry[2]) if shadow_entry and shadow_entry[2] else None
            except ValueError:
                pw_last_set_days = None
            try:
                max_age = int(shadow_entry[4]) if shadow_entry and shadow_entry[4] else None
            except ValueError:
                max_age = None
            password_never_expires = max_age in (None, 99999)
            try:
                expire_days = int(shadow_entry[7]) if shadow_entry and shadow_entry[7] else None
            except ValueError:
                expire_days = None

            # last(1) for the most recent login of this user, head 1 line:
            last_login = ""
            last_raw = self._sh(f"last -F -n 1 {name} 2>/dev/null | head -n 1")
            if last_raw and not last_raw.lower().startswith("wtmp"):
                last_login = last_raw.strip()

            users.append({
                "Name": name,
                "Enabled": not account_locked,
                "PasswordRequired": password_required,
                "PasswordLastSet": (
                    f"{pw_last_set_days} days since epoch"
                    if pw_last_set_days is not None else ""
                ),
                "LastLogon": last_login,
                "PasswordNeverExpires": password_never_expires,
                "AccountExpires": (
                    f"{expire_days} days since epoch"
                    if expire_days is not None else "never"
                ),
                "UID": uid,
                "Shell": shell,
                "Home": home,
                "is_system": uid < 1000,
            })
        return users

    def _lin_admins(self) -> list:
        """Members of sudo / wheel / admin groups (whichever exists)."""
        group = self._read_file("/etc/group")
        members: dict[str, list[str]] = {}
        for line in group.splitlines():
            parts = line.split(":")
            if len(parts) < 4:
                continue
            gname = parts[0]
            if gname not in {"sudo", "wheel", "admin"}:
                continue
            users = [u for u in parts[3].split(",") if u]
            if users:
                members[gname] = users

        # Also include any user with UID 0 (root + accidental clones).
        passwd = self._read_file("/etc/passwd")
        uid0 = [line.split(":")[0] for line in passwd.splitlines()
                if len(line.split(":")) >= 3 and line.split(":")[2] == "0"]

        out: list[dict] = []
        for u in uid0:
            out.append({"Name": u, "ObjectClass": "User", "PrincipalSource": "uid0/root"})
        for gname, users in members.items():
            for u in users:
                out.append({"Name": u, "ObjectClass": "User", "PrincipalSource": f"group/{gname}"})
        return out

    def _lin_password_policy(self) -> dict:
        """Aggregate /etc/login.defs + (if present) /etc/security/pwquality.conf."""
        defs = self._read_file("/etc/login.defs")
        policy: dict[str, str] = {}
        for key in ("PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE", "PASS_MIN_LEN", "ENCRYPT_METHOD"):
            m = re.search(rf"^\s*{key}\s+(\S+)", defs, re.MULTILINE)
            if m:
                policy[key] = m.group(1)
        pwq = self._read_file("/etc/security/pwquality.conf")
        for key in ("minlen", "dcredit", "ucredit", "lcredit", "ocredit", "minclass"):
            m = re.search(rf"^\s*{key}\s*=\s*(\S+)", pwq, re.MULTILINE)
            if m:
                policy[f"pwquality.{key}"] = m.group(1)
        return policy

    def _lin_recent_logons(self) -> list:
        """Tail of last(1) — successful logins. Maps to Windows Security 4624."""
        raw = self._sh("last -F -n 20 2>/dev/null | head -n 20")
        out: list[dict] = []
        for line in raw.splitlines():
            if not line.strip() or line.startswith("wtmp"):
                continue
            out.append({"Time": "", "Message": line.strip()[:200]})
        return out

    def _lin_guest_like(self) -> dict:
        """No real 'Guest' on Linux — closest analogue is nobody / a 'guest' user
        if present. Report disabled-by-default status."""
        nobody = "nobody" in self._read_file("/etc/passwd")
        return {"Name": "nobody", "Enabled": nobody, "note": "linux has no Windows-style guest account"}

    def _lin_passwordless(self) -> list:
        """Accounts whose shadow hash is empty — login with no password."""
        shadow = self._read_file("/etc/shadow")
        accounts: list[str] = []
        for line in shadow.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "":
                accounts.append(parts[0])
        return accounts

    def _lin_nopasswd_sudoers(self) -> list:
        """sudo rules tagged NOPASSWD — these escalate without a re-prompt."""
        rules: list[str] = []
        for path in ("/etc/sudoers", "/etc/sudoers.d"):
            raw = self._sh(f"grep -rH 'NOPASSWD' {path} 2>/dev/null | head -n 20")
            for line in raw.splitlines():
                if "NOPASSWD" in line:
                    rules.append(line.strip()[:250])
        return rules
