"""Software scanner — installed applications + CVE matching.

Two engines are available (switch via config.yaml under
``scanners.software.engine``):

- ``"kev"`` (default, recommended):
    Reuses the sibling ``cve-matcher`` package. KEV-only matching with a
    strict alias table + optional NVD CPE version-range checking. Each
    finding is classified as ``vulnerable`` / ``patched`` / ``unknown``,
    ransomware-linked entries are flagged separately, and the overall noise
    floor is dramatically lower than naive keyword search.

- ``"keyword"`` (legacy, preserved as opt-in):
    The original NVD-keyword-search behaviour: feed each installed-app
    display name into the NVD search endpoint and take the top N hits.
    High false-positive rate (no version comparison, no CPE matching) but
    requires no extra dependency on the cve-matcher package.

Both engines emit the legacy ``installed_apps`` + ``cve_matches`` shape so
the downstream Claude prompt in ``core.claude_engine`` keeps working
unchanged. The KEV engine additionally exposes ``kev_summary`` and
``kev_findings`` keys for prompts that want the richer structured view.

Cross-platform note
-------------------
Inventory collection is platform-specific:
  Windows : registry walk under HKLM/HKCU Uninstall keys (PowerShell).
  Linux   : ``dpkg-query -W`` (Debian/Ubuntu family). RPM-family support is
            a future task.
The KEV / NVD engines are pure Python and work identically on both.
"""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Any

from .base import BaseScanner, IS_LINUX, IS_WINDOWS


# Path to the sibling cve-matcher project so its ``cve_matcher`` package is
# importable without packaging it. ``host-scanner/`` and ``cve-matcher/``
# are expected to live next to each other under ``project/``.
_HSAI_ROOT = Path(__file__).resolve().parent.parent
_CVE_MATCHER_ROOT = _HSAI_ROOT.parent / "cve-matcher"
if _CVE_MATCHER_ROOT.exists() and str(_CVE_MATCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(_CVE_MATCHER_ROOT))


class SoftwareScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "software"

    # ---------------------------------------------------------------
    # Public entry point — dispatches to the configured engine.
    # ---------------------------------------------------------------

    def run(self) -> dict:
        out = self._run_inner()
        unmanaged = getattr(self, "unmanaged", None)
        if unmanaged and unmanaged.get("enabled"):
            out["unmanaged"] = unmanaged
        if getattr(self, "libraries", None):
            out["libraries"] = self.libraries
        return out

    def _run_inner(self) -> dict:
        engine = (self.scanner_cfg.get("engine") or "kev").lower()
        apps = self._get_installed_apps()
        platform_name = "linux" if IS_LINUX else ("windows" if IS_WINDOWS else "unknown")

        if not self.scanner_cfg.get("cve_lookup", True):
            return {
                "status": "completed",
                "platform": platform_name,
                "engine": engine,
                "installed_count": len(apps),
                "installed_apps": apps,
                "cve_matches": {},
            }

        if engine == "keyword":
            out = self._run_keyword_engine(apps)
            out["platform"] = platform_name
            return out
        if engine == "kev":
            out = self._run_kev_engine(apps)
            out["platform"] = platform_name
            return out

        return {
            "status": "error",
            "platform": platform_name,
            "engine": engine,
            "installed_count": len(apps),
            "installed_apps": apps,
            "cve_matches": {},
            "error": f"Unknown software scanner engine: {engine!r}",
        }

    # ---------------------------------------------------------------
    # Inventory collection (per-platform).
    # ---------------------------------------------------------------

    def _get_installed_apps(self) -> list[dict[str, Any]]:
        if IS_LINUX:
            return self._get_installed_apps_linux()
        if IS_WINDOWS:
            return self._get_installed_apps_windows()
        return []

    def _get_installed_apps_windows(self) -> list[dict[str, Any]]:
        raw = self._ps(r"""
$paths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$apps = Get-ItemProperty $paths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and $_.DisplayName -ne "" } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName
$apps | ConvertTo-Json -Depth 2
""")
        try:
            data = json.loads(raw) if raw else []
            if isinstance(data, dict):
                data = [data]
            return data
        except Exception:
            return []

    def _get_installed_apps_linux(self) -> list[dict[str, Any]]:
        """Collect installed packages via dpkg-query (Debian/Ubuntu family).

        Produces the SAME shape as the Windows registry walk so the KEV
        engine and the legacy keyword engine consume one consistent format.
        """
        if not self._which("dpkg-query"):
            return []
        raw = self._sh(
            "dpkg-query -W -f='${Package}\\t${Version}\\t${Maintainer}\\n' 2>/dev/null"
        )
        apps: list[dict[str, Any]] = []
        for line in raw.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            name = parts[0].strip()
            version = parts[1].strip()
            maintainer = parts[2].strip() if len(parts) >= 3 else ""
            if not name:
                continue
            apps.append({
                "DisplayName": name,
                "DisplayVersion": version,
                "Publisher": maintainer,
                "InstallDate": "",
            })
        apps.extend(self._unmanaged_apps())
        apps.sort(key=lambda a: a["DisplayName"].lower())
        return apps

    def _unmanaged_apps(self) -> list[dict[str, Any]]:
        """Programs outside the package manager (php built from source, /opt, ...).

        Opt-out via ``scanners.software.include_unmanaged: false``. Failures
        never break the dpkg inventory; they are recorded in ``self.unmanaged``.
        """
        self.unmanaged: dict[str, Any] = {"enabled": False}
        if not self.scanner_cfg.get("include_unmanaged", True):
            return []
        try:
            from . import unmanaged
            result = unmanaged.collect(unmanaged.linux_probes())
        except Exception as error:  # never let discovery break the scan
            self.unmanaged = {"enabled": True, "error": f"{type(error).__name__}: {error}"}
            return []
        self.unmanaged = {
            "enabled": True,
            "binaries": result.binaries,
            "running_unmanaged": result.running_unmanaged,
            "notes": result.notes,
        }
        apps = unmanaged.to_installed_apps(result)
        if self.scanner_cfg.get("include_ecosystems", True):
            try:
                from . import ecosystems
                eco = ecosystems.collect(ecosystems.linux_fs())
                apps.extend(eco.apps)
                self.libraries = eco.libraries
                self.unmanaged["ecosystems"] = {"counts": eco.counts, "notes": eco.notes}
            except Exception as error:
                self.unmanaged["ecosystems"] = {"error": f"{type(error).__name__}: {error}"}
        return apps

    # ---------------------------------------------------------------
    # Legacy engine: NVD keyword search per app.
    # ---------------------------------------------------------------

    def _run_keyword_engine(self, apps: list[dict[str, Any]]) -> dict:
        cve_results = self._lookup_cves(apps)
        return {
            "status": "completed",
            "engine": "keyword",
            "installed_count": len(apps),
            "installed_apps": apps,
            "cve_matches": cve_results,
        }

    def _lookup_cves(self, apps: list) -> dict:
        nvd_cfg = self.cfg.get("nvd", {})
        api_url = nvd_cfg.get("api_url", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        api_key = nvd_cfg.get("api_key", "")
        max_per_app = self.scanner_cfg.get("max_cve_per_app", 5)

        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        results: dict[str, list[dict[str, Any]]] = {}
        checkable = [a for a in apps if a.get("DisplayVersion") and a.get("DisplayName")][:30]

        for app in checkable:
            name = app["DisplayName"]
            keyword = re.sub(r"[^\w\s]", " ", name).strip()
            if not keyword:
                continue
            try:
                import httpx
                resp = httpx.get(
                    api_url,
                    params={"keywordSearch": keyword, "resultsPerPage": max_per_app},
                    headers=headers,
                    timeout=15,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        results[name] = []
                        for v in vulns:
                            cve = v["cve"]
                            cvss = cve.get("metrics", {}).get("cvssMetricV31", [{}])
                            severity = (
                                cvss[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                                if cvss and isinstance(cvss, list)
                                else "UNKNOWN"
                            )
                            results[name].append({
                                "cve_id": cve["id"],
                                "description": cve["descriptions"][0]["value"][:300],
                                "severity": severity,
                            })
                time.sleep(0.6 if api_key else 6)
            except Exception:
                continue
        return results

    # ---------------------------------------------------------------
    # KEV engine: cve-matcher / KEV + NVD CPE version check.
    # ---------------------------------------------------------------

    def _run_kev_engine(self, apps: list[dict[str, Any]]) -> dict:
        try:
            from cve_matcher import kev, matcher
            from cve_matcher.inventory import Inventory, Package
        except ImportError as error:
            return {
                "status": "completed",
                "engine": "kev",
                "engine_warning": (
                    f"cve_matcher package not importable ({error}); fell back to keyword engine. "
                    f"Expected at {_CVE_MATCHER_ROOT}."
                ),
                **self._run_keyword_engine(apps),
            }

        # 1. Convert raw apps -> cve_matcher Inventory.
        packages: list[Package] = []
        for app in apps:
            name = (app.get("DisplayName") or "").strip()
            if not name:
                continue
            packages.append(Package(
                name=name,
                version=(app.get("DisplayVersion") or "").strip(),
                vendor=(app.get("Publisher") or "").strip(),
                product=(app.get("Product") or "").strip() or _strip_version_suffix(name),
                source=app.get("Source") or "hsai-inventory",
            ))

        inventory = Inventory(
            scanned_at="",
            host_os="linux" if IS_LINUX else ("windows" if IS_WINDOWS else "unknown"),
            host_version="",
            packages=packages,
        )

        # 2. Load (and refresh if stale) the KEV catalog.
        try:
            catalog = kev.load()
        except Exception as error:
            return {
                "status": "error",
                "engine": "kev",
                "installed_count": len(apps),
                "installed_apps": apps,
                "cve_matches": {},
                "error": f"KEV catalog load failed: {error}",
            }

        # 3. Match. Fuzzy stays off — alias table covers consumer software well.
        match_result = matcher.match(inventory, catalog, fuzzy=False)

        # 4. Optional NVD version-range enrichment (verdict).
        if self.scanner_cfg.get("check_versions", True) and match_result.findings:
            try:
                matcher.enrich_with_versions(match_result.findings)
            except Exception as error:
                for f in match_result.findings:
                    if not f.verdict_detail:
                        f.verdict_detail = f"NVD enrichment failed: {error}"

        # 5. Build the two parallel views.
        show_patched = self.scanner_cfg.get("show_patched", False)
        keep = lambda f: show_patched or f.verdict != "patched"

        cve_matches: dict[str, list[dict[str, Any]]] = {}
        kev_findings: list[dict[str, Any]] = []
        verdict_counts = {"vulnerable": 0, "patched": 0, "unknown": 0}
        ransomware_vulnerable = 0

        for f in match_result.findings:
            verdict_counts[f.verdict] = verdict_counts.get(f.verdict, 0) + 1
            if f.verdict == "vulnerable" and f.entry.ransomware:
                ransomware_vulnerable += 1
            if not keep(f):
                continue

            severity = "RANSOMWARE" if f.entry.ransomware else "EXPLOITED"
            cve_matches.setdefault(f.package.name, []).append({
                "cve_id": f.entry.cve_id,
                "description": (f.entry.description or "")[:300],
                "severity": severity,
                "verdict": f.verdict,
                "kev_required_action": f.entry.required_action,
            })

            kev_findings.append({
                "cve_id": f.entry.cve_id,
                "kev_name": f.entry.name,
                "kev_vendor": f.entry.vendor,
                "kev_product": f.entry.product,
                "kev_description": f.entry.description,
                "kev_required_action": f.entry.required_action,
                "kev_date_added": f.entry.date_added,
                "kev_due_date": f.entry.due_date,
                "ransomware_linked": f.entry.ransomware,
                "cwes": f.entry.cwes,
                "package_name": f.package.name,
                "package_version": f.package.version,
                "package_vendor": f.package.vendor,
                "match_reason": f.match_reason,
                "match_score": f.match_score,
                "verdict": f.verdict,
                "verdict_detail": f.verdict_detail,
            })

        rank = {"vulnerable": 0, "unknown": 1, "patched": 2}
        kev_findings.sort(key=lambda d: (
            rank.get(d["verdict"], 99),
            not d["ransomware_linked"],
            -d["match_score"],
            d["cve_id"],
        ))

        return {
            "status": "completed",
            "engine": "kev",
            "installed_count": len(apps),
            "installed_apps": apps,
            "cve_matches": cve_matches,
            "kev_summary": {
                "kev_version": catalog.catalog_version,
                "kev_released": catalog.date_released,
                "total_findings": len(match_result.findings),
                "vulnerable_count": verdict_counts.get("vulnerable", 0),
                "unknown_count": verdict_counts.get("unknown", 0),
                "patched_count": verdict_counts.get("patched", 0),
                "ransomware_vulnerable_count": ransomware_vulnerable,
                "show_patched": show_patched,
                "version_check_enabled": bool(self.scanner_cfg.get("check_versions", True)),
            },
            "kev_findings": kev_findings,
        }


# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------

_PAREN_RE = re.compile(r"\([^)]*\)")
_DASH_TAIL_RE = re.compile(r"\s+-\s+.*$")
_VERSION_TOKEN_RE = re.compile(r"^\d+[.,]")


def _strip_version_suffix(name: str) -> str:
    """Trim version + arch suffixes from a DisplayName for KEV matching."""
    if not name:
        return ""
    cleaned = _PAREN_RE.sub(" ", name)
    cleaned = _DASH_TAIL_RE.sub("", cleaned).strip()
    out = []
    for token in cleaned.split():
        if _VERSION_TOKEN_RE.match(token):
            break
        out.append(token)
    return " ".join(out).strip()


def _looks_like_version(token: str) -> bool:
    """Legacy alias retained for backwards compatibility."""
    cleaned = token.strip("()")
    if not cleaned:
        return False
    return bool(_VERSION_TOKEN_RE.match(cleaned))
