# HomeSecAI — Linux quickstart

HomeSecAI runs end-to-end on Linux (Debian/Ubuntu family) in addition to
Windows. Every scanner has a Linux backend that produces the same JSON shape
as the Windows backend, so the Claude analysis layer and the HTML report
renderer work without changes.

## Prerequisites

- Python 3.10+ (`python3 --version`)
- The `cve-scanner` sibling project at `../cve-scanner/` (already in place
  if you cloned the repo as documented).
- Claude CLI (Claude Code) on `PATH` or pointed to by `$CLAUDE_CLI_PATH`.
- Optional but recommended on a server:
  - `dpkg-query` (Debian/Ubuntu — already present)
  - `ss` from `iproute2` (already present on most distros)
  - `ufw` or `firewalld` for the firewall scanner to read posture
  - `fail2ban-client` for the fail2ban scanner section
  - `auditctl` (from `auditd`) for audit policy
  - `nmap` for the network scanner's external probes (future work)

Most of the scanners gracefully report "not installed" when the
corresponding tool is missing — they will not error out.

## One-time setup

```bash
cd home-security-ai
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If you want the Claude CLI to be picked up from a non-PATH location:

```bash
export CLAUDE_CLI_PATH=/path/to/claude
claude   # one-time login
```

## Running a scan

CLI (terminal output + markdown/HTML report):

```bash
./run_cli.sh
```

Web dashboard (opens at http://localhost:8000):

```bash
./run_web.sh
```

Both scripts:

1. Locate Claude CLI via `$CLAUDE_CLI_PATH` first, then `PATH`.
2. Activate `.venv/` if present.
3. Force `PYTHONUTF8=1` so Rich renders Unicode reliably.
4. Hand off to `main.py` or `uvicorn frontend.app:app`.

## What each scanner looks at on Linux

| Scanner | Linux sources |
|---|---|
| `system` | `/etc/os-release`, `uname`, dpkg.log, `apt list --upgradable`, sudoers, ClamAV / AppArmor / SELinux status, auditctl rules, samba config, sshd_config flags, ufw / firewalld / iptables, fail2ban |
| `software` | `dpkg-query -W` → KEV catalog match → optional NVD version-range check |
| `users` | `/etc/passwd`, `/etc/shadow`, sudo/wheel/admin groups, UID-0 accounts, `/etc/login.defs`, `pwquality.conf`, `last -F`, NOPASSWD sudo rules, passwordless accounts |
| `processes` | `ps -eo`, `/proc/<pid>/exe`, systemd unit files, dpkg ownership check for "unpackaged" binaries (Linux analogue of "unsigned") |
| `filesystem` | `~/.ssh`, `/etc/ssh`, `/root/.ssh`, `/var/backups`, world-writable files under `/etc /var /opt /srv`, executables in `/tmp /var/tmp /dev/shm`, `/etc/shadow` mode, SUID binaries, LUKS volumes |
| `startup` | Enabled systemd unit files, `/etc/crontab`, `/etc/cron.d/*`, per-user crontabs, systemd timers, XDG autostart, `/etc/rc.local`, browser extensions |
| `hardware` | `/sys/firmware/efi/efivars/SecureBoot-*`, `/sys/class/tpm`, `/sys/class/dmi/id`, `systemd-detect-virt`, kernel hardening flags (KASLR/SMEP/SMAP/IOMMU/lockdown), userland hardening (ASLR / ptrace_scope / kptr_restrict / dmesg_restrict) |
| `network` | `ss -tlnp` / `ss -ulnp`, ufw/firewalld/iptables, `ip -j addr`, `ip neigh`, `nmcli`, `/etc/resolv.conf`, `/etc/samba/smb.conf` shares, `external_listeners` (everything bound to 0.0.0.0 or `::`) |

## Linux-only extras worth surfacing for server posture

These appear as additional keys in the scanner output and feed into the
Claude prompt:

- `system.sshd_config` — eight CIS / Lynis-style sshd hardening flags
- `system.firewall` — detected tool, state, default policy
- `system.fail2ban` — installed flag, service state, jail summary
- `system.selinux` — installed flag and enforcement mode
- `users.passwordless_accounts` — accounts whose `/etc/shadow` hash is empty
- `users.nopasswd_sudoers` — sudo rules tagged `NOPASSWD` (privilege creep)
- `filesystem.shadow_perms` — mode and ownership of `/etc/shadow`
- `filesystem.suid_binaries` — SUID-root binaries on disk
- `network.external_listeners` — listening sockets bound to 0.0.0.0 or `::`

## Caveats and known gaps

- **RPM family (Fedora/RHEL/Rocky) is not yet supported.** The dpkg path
  short-circuits if `dpkg-query` is missing, so the software scanner
  returns an empty inventory rather than erroring. RPM support is a
  follow-on task and means adding a parallel collector that calls
  `rpm -qa --queryformat=...`.
- **`/etc/shadow` reads require root.** Without root, the `users` scanner
  reports account-lock state as "unknown" and the
  `users.passwordless_accounts` list will be empty (it cannot rule out the
  presence of passwordless accounts — re-run with `sudo` to confirm).
- **`find` walks can be slow on large filesystems.** The world-writable
  and SUID checks are bounded with `head -n 30`. If you need fuller
  coverage, run them manually with the same `find` expressions documented
  in `scanners/filesystem.py`.
- **Many hardware checks are no-ops inside VMs.** Secure Boot, TPM, and
  BIOS info return `Supported: false` / empty when the VM doesn't
  emulate them. That is correct behaviour, not a bug.

## Running just the cve-scanner side (no AI)

If you only want the KEV-driven CVE report and not the full AI workflow,
the sibling `cve-scanner` package runs standalone:

```bash
cd ../cve-scanner
python -m cve_scanner scan --check-versions
```

That writes a markdown report into `cve-scanner/reports/`.
