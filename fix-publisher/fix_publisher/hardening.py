"""Security checks: host-scanner's posture / leak findings, each with a one-line fix hint.

Unlike the CVE remediations this part needs no AI. The scanner already decided what is wrong;
a fixed table (finding id -> hint) says what to do about it. A finding whose id is not in the
table is still listed, with a generic hint, so nothing the scanner found is hidden.
"""

from __future__ import annotations

import html
from typing import Any

SECTION_MARKER = "<!-- exposure-analyzer:security-checks -->"

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_GENERIC_HINT = "Review this finding and fix it if it is not intended."

# finding id -> one-line fix hint. Commands are examples for Debian/Ubuntu; adapt to your system.
HINTS: dict[str, str] = {
    # --- operating system / updates
    "os-eol": "This release no longer gets security fixes. Upgrade to a supported release.",
    "apt-stale": "Package lists have not been refreshed. Run `apt update` and apply the pending security updates.",
    "no-auto-updates": "Install automatic security updates: `apt install unattended-upgrades`, then `dpkg-reconfigure -plow unattended-upgrades`.",
    "reboot-required": "Updates are installed but not active. Reboot at the next maintenance window.",
    # --- ssh / sudo
    "ssh-root-login": "Set `PermitRootLogin no` in /etc/ssh/sshd_config and reload sshd.",
    "ssh-password-auth": "Use key-based login: set `PasswordAuthentication no` in /etc/ssh/sshd_config (after your key works) and reload sshd.",
    "ssh-empty-passwords": "Set `PermitEmptyPasswords no` in /etc/ssh/sshd_config and give every account a password or lock it.",
    "ssh-x11-forwarding": "Set `X11Forwarding no` in /etc/ssh/sshd_config unless users need it.",
    "sudo-nopasswd": "Remove `NOPASSWD` entries from sudoers (edit with `visudo`) unless a job really needs them.",
    "sudo-no-authenticate": "Remove `!authenticate` from sudoers (edit with `visudo`).",
    # --- containers
    "container-runs-as-root": "Run the service as a non-root user (`USER` in the Dockerfile, or `--user` / `user:` in compose).",
    "container-privileged": "Do not use `--privileged`. Grant only the capabilities the service needs (`--cap-add`).",
    "container-docker-sock": "Do not mount /var/run/docker.sock into the container: it gives full control of the host.",
    "container-no-seccomp": "Re-enable the default seccomp profile (remove `seccomp=unconfined`).",
    "container-secret-env": "Pass secrets as files or from a secret store instead of environment variables, and rotate the ones already exposed.",
    # --- files and permissions
    "world-writable-sensitive": "Remove world-write: `chmod o-w <path>` and check who changed it.",
    "file-capabilities": "Check the file needs these capabilities. If not, remove them: `setcap -r <path>`.",
    "suid-unusual-location": "A SUID program outside the system directories is suspicious. Check where it came from; remove the bit with `chmod u-s <path>` if not needed.",
    "suid-unknown-binary": "Check this SUID program is expected. If not, remove the bit with `chmod u-s <path>`.",
    "wp-config-world-readable": "Make wp-config.php readable only by the web server user: `chmod 640 wp-config.php`.",
    # --- TLS
    "tls-expired": "Renew the certificate now and reload the service that uses it.",
    "tls-expiring": "Renew the certificate before it expires and set up automatic renewal (for example certbot).",
    "tls-self-signed": "Use a certificate from a trusted CA (for example Let's Encrypt) for anything clients connect to.",
    # --- leaked files in web/app directories
    "leak-dotenv": "Remove the .env file from the web directory, or deny access to it in the web server. Rotate the secrets it holds.",
    "leak-htpasswd": "Move .htpasswd out of the web directory (or deny access) and change the passwords in it.",
    "leak-sql-dump": "Delete the dump from the web directory and keep backups outside it. Assume its data was readable.",
    "leak-ssh-key": "Remove the private key from the web directory, and replace the key pair.",
    "leak-private-key": "Remove the private key from this location and replace the key pair.",
    "leak-backup": "Delete the backup / editor copy from the web directory: it can be downloaded as plain text.",
    "leak-phpinfo": "Delete the diagnostic page: it shows versions, paths and settings to anyone.",
    "leak-credentials-file": "Move the file out of the web directory (or deny access) and rotate the credentials in it.",
    "leak-vcs-dir": "Remove the .git directory from the web root (deploy an export instead) or deny access to it.",
}

_SYSCTL_HINT = "Set `{key}` to the recommended value: `sysctl -w {key}=<value>`, and persist it in /etc/sysctl.d/."


def hint_for(finding_id: str) -> str:
    """The fix hint for a finding id (generic text when the id is not in the table)."""
    if finding_id in HINTS:
        return HINTS[finding_id]
    if finding_id.endswith("-truncated"):
        return "More findings of this kind exist. Fix the ones listed, then scan again."
    if finding_id.startswith("sysctl-"):
        # id is "sysctl-" + key with '/' replaced by '-'; show it in dotted form for the command
        return _SYSCTL_HINT.format(key=finding_id[len("sysctl-"):].replace("-", "."))
    return _GENERIC_HINT


def collect_findings(scan: dict[str, Any]) -> list[dict[str, str]]:
    """Posture + leak findings of a host scan, each with a `hint`, most severe first."""
    scanners = (scan or {}).get("scanners") or {}
    out: list[dict[str, str]] = []
    for source in ("posture", "leaks"):
        block = scanners.get(source)
        if not isinstance(block, dict):
            continue
        for f in block.get("findings") or []:
            if not isinstance(f, dict) or not f.get("id"):
                continue
            fid = str(f["id"])
            out.append({
                "source": source,
                "id": fid,
                "severity": str(f.get("severity", "info")).lower(),
                "title": str(f.get("title", "")),
                "evidence": str(f.get("evidence", "")),
                "hint": hint_for(fid),
            })
    out.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 9))  # stable: keeps scanner order
    return out


def _badge_class(severity: str) -> str:
    return {"critical": "sev-critical", "high": "sev-critical", "medium": "sev-medium",
            "low": "sev-low"}.get(severity, "sev-info")


def render_html_section(findings: list[dict[str, str]]) -> str:
    """The "Security checks" report block. Every field is escaped."""
    e = html.escape
    parts = [SECTION_MARKER, '  <div class="card">', "    <h2>Security checks</h2>"]
    parts.append(
        '    <p class="muted" style="margin-bottom:0.75rem;">'
        f"{len(findings)} finding(s) from the host's configuration and file checks "
        "(not CVEs). The fix hint is a fixed rule per finding type; review it before applying.</p>"
    )
    if not findings:
        parts.append('    <p class="muted" style="text-align:center;">(no findings)</p>')
    else:
        parts.append('    <table style="width:100%;border-collapse:collapse;">')
        parts.append("      <tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Fix hint</th></tr>")
        for f in findings:
            parts.append(
                "      <tr>"
                f'<td><span class="badge {_badge_class(f["severity"])}">{e(f["severity"].upper())}</span></td>'
                f'<td>{e(f["title"])}<div class="muted" style="font-size:0.8rem;font-family:monospace;">{e(f["id"])}</div></td>'
                f'<td class="muted" style="font-family:monospace;font-size:0.8rem;">{e(f["evidence"])}</td>'
                f'<td>{e(f["hint"])}</td>'
                "</tr>"
            )
        parts.append("    </table>")
    parts.append("  </div>")
    parts.append(SECTION_MARKER.replace("-->", "end -->"))
    return "\n".join(parts)
