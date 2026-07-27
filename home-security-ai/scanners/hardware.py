"""Hardware scanner — Secure Boot, TPM, BIOS, virtualisation, memory-integrity.

Windows: PowerShell wraps Confirm-SecureBootUEFI, Get-Tpm, Get-WmiObject Win32_BIOS,
DeviceGuard / HVCI registry keys, Get-ProcessMitigation.
Linux  : reads /sys/firmware/efi/efivars/SecureBoot-*, /sys/class/tpm, dmidecode,
/proc/cmdline + /proc/cpuinfo flags. On a VM most of these are absent — the
scanner reports that fact rather than failing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .base import BaseScanner, IS_LINUX, IS_WINDOWS


class HardwareScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "hardware"

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
            "secure_boot": self._win_secure_boot(),
            "tpm": self._win_tpm(),
            "virtualization_security": self._win_virt_security(),
            "bios_info": self._win_bios(),
            "memory_integrity": self._win_hvci(),
            "windows_security_features": self._win_security_features(),
        }

    def _win_secure_boot(self) -> dict:
        raw = self._ps("""
try {
    $sb = Confirm-SecureBootUEFI -ErrorAction Stop
    [PSCustomObject]@{ Enabled=$sb; Supported=$true } | ConvertTo-Json
} catch {
    [PSCustomObject]@{ Enabled=$false; Supported=$false; Error=$_.Exception.Message } | ConvertTo-Json
}
""")
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _win_tpm(self) -> dict:
        raw = self._ps("""
try {
    $tpm = Get-Tpm -ErrorAction Stop
    [PSCustomObject]@{
        TpmPresent     = $tpm.TpmPresent
        TpmReady       = $tpm.TpmReady
        TpmEnabled     = $tpm.TpmEnabled
        TpmActivated   = $tpm.TpmActivated
        ManufacturerId = $tpm.ManufacturerId
        ManagedAuthLevel = $tpm.ManagedAuthLevel
    } | ConvertTo-Json
} catch {
    [PSCustomObject]@{ Error=$_.Exception.Message } | ConvertTo-Json
}
""")
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _win_virt_security(self) -> dict:
        raw = self._ps(r"""
$vbs = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -ErrorAction SilentlyContinue
$hvci = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -ErrorAction SilentlyContinue
[PSCustomObject]@{
    VBSEnabled         = if($vbs) { $vbs.EnableVirtualizationBasedSecurity } else { "unknown" }
    HVCIEnabled        = if($hvci) { $hvci.Enabled } else { "unknown" }
    CredentialGuard    = if($vbs) { $vbs.LsaCfgFlags } else { "unknown" }
} | ConvertTo-Json
""")
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _win_bios(self) -> dict:
        raw = self._ps(
            "Get-WmiObject -Class Win32_BIOS | "
            "Select-Object Manufacturer, Name, Version, ReleaseDate, SMBIOSBIOSVersion | "
            "ConvertTo-Json"
        )
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _win_hvci(self) -> dict:
        raw = self._ps(r"""
$hvci = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -ErrorAction SilentlyContinue
[PSCustomObject]@{
    Enabled = if($hvci) { $hvci.Enabled -eq 1 } else { $false }
    WasEnabledBy = if($hvci) { $hvci.WasEnabledBy } else { "N/A" }
} | ConvertTo-Json
""")
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _win_security_features(self) -> dict:
        raw = self._ps(r"""
[PSCustomObject]@{
    DEP_Policy          = (Get-WmiObject -Class Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy
    ASLR_Enabled        = (Get-ProcessMitigation -System).ASLR.BottomUp
    CFG_Enabled         = (Get-ProcessMitigation -System).CFG.Enable
    SmartScreen         = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -ErrorAction SilentlyContinue).SmartScreenEnabled
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
            "secure_boot": self._lin_secure_boot(),
            "tpm": self._lin_tpm(),
            "virtualization_security": self._lin_virt_info(),
            "bios_info": self._lin_bios(),
            "memory_integrity": self._lin_kernel_hardening(),
            "windows_security_features": self._lin_userland_hardening(),
        }

    def _lin_secure_boot(self) -> dict:
        """Read EFI Secure Boot state.

        The canonical source is /sys/firmware/efi/efivars/SecureBoot-* whose
        first non-attribute byte is 1 (on) or 0 (off). On non-UEFI systems
        the path doesn't exist.
        """
        efivars = Path("/sys/firmware/efi/efivars")
        if not efivars.exists():
            return {"Enabled": False, "Supported": False, "reason": "Not booted in UEFI mode"}
        try:
            for entry in efivars.iterdir():
                if entry.name.startswith("SecureBoot-"):
                    data = entry.read_bytes()
                    if len(data) >= 5:
                        return {"Enabled": data[4] == 1, "Supported": True}
            return {"Enabled": False, "Supported": True, "reason": "SecureBoot var not readable"}
        except (PermissionError, OSError) as error:
            # mokutil --sb-state is the userspace fallback (no root needed).
            mok = self._cmd(["mokutil", "--sb-state"]).strip()
            if mok:
                return {
                    "Enabled": "enabled" in mok.lower(),
                    "Supported": True,
                    "source": "mokutil",
                    "raw": mok[:200],
                }
            return {"Enabled": False, "Supported": True, "Error": str(error)}

    def _lin_tpm(self) -> dict:
        """Detect TPM via /sys/class/tpm/."""
        tpm_dir = Path("/sys/class/tpm")
        if not tpm_dir.exists():
            return {"TpmPresent": False, "TpmReady": False, "reason": "/sys/class/tpm absent"}
        try:
            devices = [d for d in tpm_dir.iterdir() if d.name.startswith("tpm")]
        except OSError:
            return {"TpmPresent": False, "TpmReady": False}
        if not devices:
            return {"TpmPresent": False, "TpmReady": False}
        first = devices[0]
        vendor = (first / "device" / "description").read_text(errors="replace").strip() \
            if (first / "device" / "description").exists() else ""
        return {
            "TpmPresent": True,
            "TpmReady": True,
            "TpmEnabled": True,
            "TpmActivated": True,
            "ManufacturerId": vendor or "unknown",
            "ManagedAuthLevel": "kernel",
            "Device": first.name,
        }

    def _lin_virt_info(self) -> dict:
        """Are we IN a VM, and what virtualisation tech is the host using?"""
        # virt-what / systemd-detect-virt — the latter is on every systemd box.
        if self._which("systemd-detect-virt"):
            virt = self._cmd(["systemd-detect-virt"]).strip()
        else:
            virt = ""
        return {
            "VBSEnabled": "unknown",      # Linux equivalent isn't a single flag
            "HVCIEnabled": "unknown",
            "CredentialGuard": "unknown",
            "running_in_virt": bool(virt) and virt != "none",
            "virt_type": virt or "none",
        }

    def _lin_bios(self) -> dict:
        """Pull BIOS info from /sys/class/dmi/id (works without dmidecode)."""
        base = Path("/sys/class/dmi/id")
        if not base.exists():
            return {}
        def read(name: str) -> str:
            p = base / name
            return p.read_text(errors="replace").strip() if p.exists() else ""
        return {
            "Manufacturer": read("bios_vendor"),
            "Name": read("bios_version"),
            "Version": read("bios_version"),
            "ReleaseDate": read("bios_date"),
            "SMBIOSBIOSVersion": read("bios_version"),
            "BoardVendor": read("board_vendor"),
            "BoardName": read("board_name"),
            "ProductName": read("product_name"),
        }

    def _lin_kernel_hardening(self) -> dict:
        """Memory-integrity stand-in: kernel hardening features that are on/off."""
        cmdline = self._read_file("/proc/cmdline")
        cpuinfo = self._read_file("/proc/cpuinfo", max_bytes=16384)
        flags = ""
        m = re.search(r"^flags\s*:\s*(.+)$", cpuinfo, re.MULTILINE)
        if m:
            flags = m.group(1)

        kaslr = "nokaslr" not in cmdline  # kaslr is default-on
        # SMEP / SMAP are CPU features the kernel uses if present.
        smep = " smep " in f" {flags} "
        smap = " smap " in f" {flags} "

        # IOMMU
        iommu_on = ("iommu=on" in cmdline) or ("intel_iommu=on" in cmdline) or ("amd_iommu=on" in cmdline)

        # Lockdown mode (set by Secure Boot or kernel.lockdown sysctl):
        lockdown = self._read_file("/sys/kernel/security/lockdown")

        return {
            "Enabled": kaslr and (smep or smap),
            "WasEnabledBy": "kernel-build",
            "kaslr": kaslr,
            "smep": smep,
            "smap": smap,
            "iommu": iommu_on,
            "lockdown_mode": lockdown or "not_set",
            "cmdline": cmdline[:300],
        }

    def _lin_userland_hardening(self) -> dict:
        """ASLR / ptrace_scope / kptr_restrict / dmesg_restrict — the things
        Lynis flags on a Linux box. Maps onto the Windows ASLR/CFG/DEP slot.
        """
        randomize_va = self._read_file("/proc/sys/kernel/randomize_va_space")
        ptrace_scope = self._read_file("/proc/sys/kernel/yama/ptrace_scope")
        kptr = self._read_file("/proc/sys/kernel/kptr_restrict")
        dmesg = self._read_file("/proc/sys/kernel/dmesg_restrict")
        nx = "nx" in self._read_file("/proc/cpuinfo", max_bytes=4096).lower()
        return {
            "DEP_Policy": "Enabled (NX bit)" if nx else "Disabled",
            "ASLR_Enabled": randomize_va == "2",
            "ASLR_value": randomize_va,
            "CFG_Enabled": "not_applicable",
            "SmartScreen": "not_applicable",
            "ptrace_scope": ptrace_scope or "unset",
            "kptr_restrict": kptr or "unset",
            "dmesg_restrict": dmesg or "unset",
        }
