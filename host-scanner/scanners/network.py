"""Network scanner — open ports, firewall, DNS, ARP, Wi-Fi, shares.

Windows: Get-NetTCPConnection / Get-NetFirewallProfile / Get-NetIPConfiguration /
netsh wlan / Get-DnsClientServerAddress / Get-SmbShare / Get-NetUDPEndpoint.
Linux  : ss -tlnp / ufw|firewalld|iptables / ip addr / nmcli|iwlist /
/etc/resolv.conf / /etc/samba/smb.conf / ss -ulnp.
"""

from __future__ import annotations

import json
import re

from .base import BaseScanner, IS_LINUX, IS_WINDOWS


class NetworkScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "network"

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
            "open_ports": self._win_open_ports(),
            "firewall": self._win_firewall_status(),
            "network_adapters": self._win_adapters(),
            "arp_table": self._win_arp(),
            "wifi_security": self._win_wifi(),
            "dns_config": self._win_dns(),
            "shares": self._win_shares(),
            "listening_services": self._win_udp_listeners(),
        }

    def _win_open_ports(self) -> list:
        raw = self._ps(
            "Get-NetTCPConnection -State Listen | "
            "Select-Object LocalPort, OwningProcess, State | "
            "Sort-Object LocalPort | ConvertTo-Json -Depth 3"
        )
        try:
            ports = json.loads(raw) if raw else []
            if isinstance(ports, dict):
                ports = [ports]
            pids = {str(p.get("OwningProcess", "")) for p in ports if p.get("OwningProcess")}
            pid_map: dict[str, str] = {}
            if pids:
                pid_list = ",".join(pids)
                proc_raw = self._ps(
                    f"Get-Process -Id {pid_list} -ErrorAction SilentlyContinue | "
                    "Select-Object Id, ProcessName | ConvertTo-Json"
                )
                try:
                    procs = json.loads(proc_raw) if proc_raw else []
                    if isinstance(procs, dict):
                        procs = [procs]
                    pid_map = {str(p["Id"]): p["ProcessName"] for p in procs}
                except Exception:
                    pass
            for p in ports:
                pid = str(p.get("OwningProcess", ""))
                p["ProcessName"] = pid_map.get(pid, "unknown")
            return ports
        except Exception:
            return []

    def _win_firewall_status(self) -> dict:
        raw = self._ps(
            "Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, "
            "DefaultOutboundAction | ConvertTo-Json"
        )
        try:
            data = json.loads(raw) if raw else []
            if isinstance(data, dict):
                data = [data]
            return {"profiles": data}
        except Exception:
            return {"profiles": [], "error": "parse failed"}

    def _win_adapters(self) -> list:
        raw = self._ps(
            "Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, "
            "IPv6Address, DNSServer | ConvertTo-Json -Depth 4"
        )
        try:
            data = json.loads(raw) if raw else []
            if isinstance(data, dict):
                data = [data]
            return data
        except Exception:
            return []

    def _win_arp(self) -> list:
        raw = self._cmd(["arp", "-a"])
        lines = [l.strip() for l in raw.splitlines() if re.match(r"\s+\d+\.\d+", l)]
        return lines[:50]

    def _win_wifi(self) -> dict:
        raw = self._cmd(["netsh", "wlan", "show", "interfaces"])
        profile_raw = self._cmd(["netsh", "wlan", "show", "profiles"])
        return {
            "interface_info": raw[:2000],
            "saved_profiles_raw": profile_raw[:1000],
        }

    def _win_dns(self) -> list:
        raw = self._ps(
            "Get-DnsClientServerAddress | Where-Object AddressFamily -eq 2 | "
            "Select-Object InterfaceAlias, ServerAddresses | ConvertTo-Json -Depth 3"
        )
        try:
            data = json.loads(raw) if raw else []
            if isinstance(data, dict):
                data = [data]
            return data
        except Exception:
            return []

    def _win_shares(self) -> list:
        raw = self._ps("Get-SmbShare | Select-Object Name, Path, Description | ConvertTo-Json")
        try:
            data = json.loads(raw) if raw else []
            if isinstance(data, dict):
                data = [data]
            return data
        except Exception:
            return []

    def _win_udp_listeners(self) -> list:
        raw = self._ps(
            "Get-NetUDPEndpoint | Select-Object LocalPort, OwningProcess | "
            "Sort-Object LocalPort | ConvertTo-Json"
        )
        try:
            data = json.loads(raw) if raw else []
            if isinstance(data, dict):
                data = [data]
            return data[:30]
        except Exception:
            return []

    # ==================================================================
    # Linux backend.
    # ==================================================================

    def _run_linux(self) -> dict:
        return {
            "status": "completed",
            "platform": "linux",
            "open_ports": self._lin_listening_tcp(),
            "firewall": self._lin_firewall_status(),
            "network_adapters": self._lin_adapters(),
            "arp_table": self._lin_arp(),
            "wifi_security": self._lin_wifi(),
            "dns_config": self._lin_dns(),
            "shares": self._lin_shares(),
            "listening_services": self._lin_listening_udp(),
            # Linux extras worth surfacing for servers:
            "external_listeners": self._lin_external_listeners(),
        }

    def _lin_listening_tcp(self) -> list:
        """ss -tlnp parsed into the same shape Windows produces."""
        raw = self._sh("ss -tlnp 2>/dev/null")
        return self._parse_ss(raw, proto="tcp")

    def _lin_listening_udp(self) -> list:
        raw = self._sh("ss -ulnp 2>/dev/null")
        return self._parse_ss(raw, proto="udp")[:30]

    @staticmethod
    def _parse_ss(raw: str, proto: str) -> list:
        """Parse `ss -tlnp` or `ss -ulnp` output.

        Sample line:
            LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=803,fd=3))
        """
        out: list[dict] = []
        for line in raw.splitlines()[1:]:  # skip header
            if not line.strip():
                continue
            cols = line.split()
            if len(cols) < 5:
                continue
            local = cols[3] if proto == "tcp" else cols[4]
            # local is "addr:port" — port is everything after the last ':'.
            if ":" not in local:
                continue
            addr, _, port = local.rpartition(":")
            try:
                port_n = int(port)
            except ValueError:
                continue
            # Extract process name and PID from the users:(("name",pid=N,...)) field.
            process = "unknown"
            pid = ""
            users_match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
            if users_match:
                process = users_match.group(1)
                pid = users_match.group(2)
            out.append({
                "LocalAddress": addr,
                "LocalPort": port_n,
                "OwningProcess": pid,
                "ProcessName": process,
                "State": "Listen",
            })
        out.sort(key=lambda d: d["LocalPort"])
        return out

    def _lin_firewall_status(self) -> dict:
        """Detect ufw / firewalld / iptables and report posture."""
        profiles: list[dict] = []
        if self._which("ufw"):
            raw = self._sh("ufw status verbose 2>/dev/null")
            active = "Status: active" in raw
            default = re.search(r"Default:\s+(.+)", raw)
            profiles.append({
                "Name": "ufw",
                "Enabled": active,
                "DefaultInboundAction": default.group(1).strip() if default else "",
                "DefaultOutboundAction": "",
            })
        elif self._which("firewall-cmd"):
            state = self._cmd(["firewall-cmd", "--state"]).strip()
            profiles.append({
                "Name": "firewalld",
                "Enabled": state == "running",
                "DefaultInboundAction": "zone-based",
                "DefaultOutboundAction": "zone-based",
            })
        elif self._which("iptables"):
            raw = self._sh("iptables -L INPUT --line-numbers 2>/dev/null | head -n 5")
            has_rules = "Chain INPUT" in raw
            profiles.append({
                "Name": "iptables",
                "Enabled": has_rules,
                "DefaultInboundAction": "raw_rules",
                "DefaultOutboundAction": "raw_rules",
            })
        else:
            profiles.append({
                "Name": "none",
                "Enabled": False,
                "DefaultInboundAction": "no-firewall-detected",
                "DefaultOutboundAction": "",
            })
        return {"profiles": profiles}

    def _lin_adapters(self) -> list:
        """ip -j addr if available, else parse ip addr text output."""
        if self._which("ip"):
            raw = self._sh("ip -j addr 2>/dev/null")
            try:
                data = json.loads(raw) if raw else []
                out: list[dict] = []
                for adapter in data:
                    ifname = adapter.get("ifname", "")
                    addrs_v4: list[str] = []
                    addrs_v6: list[str] = []
                    for a in adapter.get("addr_info", []):
                        if a.get("family") == "inet":
                            addrs_v4.append(a.get("local", ""))
                        elif a.get("family") == "inet6":
                            addrs_v6.append(a.get("local", ""))
                    out.append({
                        "InterfaceAlias": ifname,
                        "IPv4Address": addrs_v4,
                        "IPv6Address": addrs_v6,
                        "DNSServer": [],
                    })
                return out
            except json.JSONDecodeError:
                pass
        # Fallback: parse plain `ip addr`.
        raw = self._sh("ip addr 2>/dev/null") or self._sh("ifconfig 2>/dev/null")
        return [{"InterfaceAlias": "raw", "raw": raw[:2000]}]

    def _lin_arp(self) -> list:
        """ip neigh — the modern replacement for arp -a."""
        raw = self._sh("ip neigh 2>/dev/null")
        if not raw and self._which("arp"):
            raw = self._cmd(["arp", "-an"])
        return [l.strip() for l in raw.splitlines() if l.strip()][:50]

    def _lin_wifi(self) -> dict:
        """nmcli summary if NetworkManager is present, else empty."""
        if self._which("nmcli"):
            iface = self._sh("nmcli dev wifi list 2>/dev/null | head -n 20")
            saved = self._sh("nmcli connection show 2>/dev/null | head -n 30")
            return {
                "interface_info": iface[:2000],
                "saved_profiles_raw": saved[:1000],
            }
        if self._which("iw"):
            iface = self._sh("iw dev 2>/dev/null")
            return {"interface_info": iface[:2000], "saved_profiles_raw": ""}
        return {"interface_info": "no wifi tooling detected", "saved_profiles_raw": ""}

    def _lin_dns(self) -> list:
        """resolv.conf nameservers + systemd-resolved status if present."""
        out: list[dict] = []
        rc = self._read_file("/etc/resolv.conf")
        nameservers = [
            line.split()[1] for line in rc.splitlines()
            if line.startswith("nameserver") and len(line.split()) >= 2
        ]
        if nameservers:
            out.append({"InterfaceAlias": "resolv.conf", "ServerAddresses": nameservers})

        if self._which("resolvectl"):
            status = self._sh("resolvectl status 2>/dev/null | head -n 30")
            if status:
                out.append({"InterfaceAlias": "systemd-resolved", "ServerAddresses": [status[:500]]})
        return out

    def _lin_shares(self) -> list:
        """Samba shares from /etc/samba/smb.conf [section] headers + path entries."""
        smb_conf = self._read_file("/etc/samba/smb.conf")
        if not smb_conf:
            return []
        out: list[dict] = []
        section = None
        path = ""
        comment = ""
        for line in smb_conf.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                if section and section.lower() != "global":
                    out.append({"Name": section, "Path": path, "Description": comment})
                section = line.strip("[]")
                path = ""
                comment = ""
            elif "=" in line:
                key, _, val = line.partition("=")
                key = key.strip().lower()
                val = val.strip()
                if key == "path":
                    path = val
                elif key == "comment":
                    comment = val
        if section and section.lower() != "global":
            out.append({"Name": section, "Path": path, "Description": comment})
        return out

    def _lin_external_listeners(self) -> list:
        """Listeners bound to 0.0.0.0 or :: — the ones an external attacker can reach.

        On a server this is the single highest-leverage check: every entry here
        is an internet-exposed (or LAN-exposed) service that must be hardened.
        """
        tcp = self._lin_listening_tcp()
        out = []
        for p in tcp:
            addr = p.get("LocalAddress") or ""
            if addr in ("0.0.0.0", "::", "*"):
                out.append(p)
        return out
