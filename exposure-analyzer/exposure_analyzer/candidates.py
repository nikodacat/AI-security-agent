"""Banner-sourced CVE candidates (v3-1).

v2's candidate list comes only from the host-scanner's package inventory
(cve-matcher: dpkg/rpm names x CISA KEV). A service built from source (e.g.
Apache in /usr/local/apache2) is invisible to that path even when the
external prober read its exact version off the wire. This module closes
that gap: every reachable `network_state` observation that carries a
`service_guess` (vendor/product/version) is run through the same
cve-matcher KEV match + NVD version check, and the results are emitted in
the same dict shape as `kev_findings`, tagged `source: "banner"`.

The banner version is a claim by the service, not an inventory fact, so
candidates are marked as such and the analyzer still decides each one
(version range, reachability, probes) exactly like a dpkg-sourced one.

cve-matcher is imported lazily from its sibling directory; nothing here
runs unless the caller asks for banner candidates.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Callable, Iterable

_CVE_MATCHER_ROOT = Path(__file__).resolve().parent.parent.parent / "cve-matcher"

# (cve_matcher modules) -> list of finding objects; injectable for tests.
MatchFn = Callable[[list[dict[str, Any]]], list[Any]]
EnrichFn = Callable[[list[Any]], None]


def _ensure_cve_matcher_importable() -> None:
    p = str(_CVE_MATCHER_ROOT)
    if _CVE_MATCHER_ROOT.exists() and p not in sys.path:
        sys.path.insert(0, p)


def banner_services(network_state: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Observations usable as candidate sources.

    Needs a reachable port and a `service_guess` with both a product and a
    version; anything vaguer would match KEV entries by name alone and flood
    the analyzer with version-blind noise.
    """
    out: list[dict[str, Any]] = []
    for obs in network_state:
        guess = obs.get("service_guess") or {}
        if not obs.get("reachable"):
            continue
        if not guess.get("product") or not guess.get("version"):
            continue
        out.append(obs)
    return out


def banner_packages(services: list[dict[str, Any]]) -> list[Any]:
    """Reachable service observations -> cve-matcher Package objects."""
    _ensure_cve_matcher_importable()
    from cve_matcher.inventory import Package  # type: ignore

    return [
        Package(
            name=obs["service_guess"]["product"],
            version=str(obs["service_guess"]["version"]),
            vendor=obs["service_guess"].get("vendor", "") or "",
            product=obs["service_guess"]["product"],
            source=f"banner:{obs.get('port')}/{obs.get('protocol', 'tcp')}",
        )
        for obs in services
    ]


def _default_match(services: list[dict[str, Any]], catalog: Any = None) -> list[Any]:
    _ensure_cve_matcher_importable()
    from cve_matcher import kev as kev_mod  # type: ignore
    from cve_matcher import matcher as matcher_mod  # type: ignore
    from cve_matcher.inventory import Inventory  # type: ignore

    inventory = Inventory(scanned_at="", host_os="banner", host_version="",
                          packages=banner_packages(services))
    cat = catalog if catalog is not None else kev_mod.load()
    return matcher_mod.match(inventory, cat).findings


def _default_enrich(findings: list[Any], api_key: str | None = None) -> None:
    _ensure_cve_matcher_importable()
    from cve_matcher import matcher as matcher_mod  # type: ignore

    matcher_mod.enrich_with_versions(findings, api_key=api_key)


def _port_of(source: str) -> int | None:
    # "banner:8080/tcp" -> 8080
    try:
        return int(source.split(":", 1)[1].split("/", 1)[0])
    except (IndexError, ValueError):
        return None


BANNER_NOT_IN_INVENTORY = "banner (version not in the apt package list)"


def apt_match(banner_version: str, installed_versions: Iterable[str]) -> str:
    """The installed apt package version whose upstream part equals the banner's, or "".

    Compares after dropping the Debian epoch ("1:8.4p1-5" -> "8.4p1-5") and
    requires the banner version to end at a boundary, so "2.4.49" matches
    "2.4.49-1~deb11u1" but not "2.4.499". A version shown on the wire that no
    apt package carries is, in practice, a build from source or a container's
    own binary.
    """
    bv = str(banner_version).strip()
    if not bv:
        return ""
    for v in installed_versions:
        s = re.sub(r"^\d+:", "", str(v).strip())
        if s.startswith(bv) and (len(s) == len(bv) or s[len(bv)] in "-+~_ "):
            return str(v).strip()
    return ""


def apt_has_version(banner_version: str, installed_versions: Iterable[str]) -> bool:
    return bool(apt_match(banner_version, installed_versions))


def finding_to_candidate(finding: Any, banner: str = "",
                         package_source: str | None = None,
                         installed_version: str = "") -> dict[str, Any]:
    """cve-matcher Finding -> kev_findings-shaped dict, tagged as banner-sourced.

    `package_source` records whether apt installed this software ("dpkg") or not
    (BANNER_NOT_IN_INVENTORY); left out when the package inventory is unknown.
    """
    entry = finding.entry
    detail = finding.verdict_detail or ""
    note = "version taken from service banner (not a package inventory)"
    extra = {"package_source": package_source} if package_source is not None else {}
    if installed_version:
        extra["installed_version"] = installed_version  # full apt version, e.g. 2.4.38-3+deb10u4
    return {
        **extra,
        "cve_id": entry.cve_id,
        "kev_name": entry.name,
        "kev_vendor": entry.vendor,
        "kev_product": entry.product,
        "kev_description": entry.description,
        "cwes": [],
        "package_name": finding.package.name,
        "package_version": finding.package.version,
        "package_vendor": finding.package.vendor,
        "match_reason": f"banner+{finding.match_reason}",
        "match_score": finding.match_score,
        "verdict": finding.verdict,
        "verdict_detail": f"{detail}; {note}" if detail else note,
        "ransomware_linked": entry.ransomware,
        "source": "banner",
        "source_port": _port_of(finding.package.source),
        "banner": banner,
    }


def banner_candidates(
    network_state: Iterable[dict[str, Any]],
    *,
    existing_cve_ids: Iterable[str] = (),
    catalog: Any = None,
    enrich: bool = True,
    api_key: str | None = None,
    match_fn: Callable[..., list[Any]] | None = None,
    enrich_fn: Callable[[list[Any]], None] | None = None,
    log: Callable[[str], None] | None = None,
    installed_apt_versions: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Build kev_findings-shaped candidates from banner observations.

    `installed_apt_versions`: versions of the host's apt packages. When given,
    each candidate records whether apt could have installed it (see
    `apt_has_version`), so fix suggestions can avoid apt commands for software
    apt does not manage. None = inventory unknown, nothing is recorded.

    Candidates whose CVE id is already present (from the package-inventory
    path) are skipped, so a Debian-packaged service seen on both paths is
    analysed once. NVD enrichment failures are non-fatal: the matcher marks
    those `unknown` and the analyzer reasons from the banner version itself.
    """
    say = log or (lambda _msg: None)
    services = banner_services(network_state)
    if not services:
        say("banner candidates: no reachable observation with product+version")
        return []

    banner_by_source = {
        f"banner:{s.get('port')}/{s.get('protocol', 'tcp')}": s.get("banner", "")
        for s in services
    }
    findings = match_fn(services) if match_fn else _default_match(services, catalog)
    say(f"banner candidates: {len(services)} service(s) -> {len(findings)} KEV match(es)")

    if findings and enrich:
        try:
            (enrich_fn or (lambda fs: _default_enrich(fs, api_key)))(findings)
        except Exception as e:  # network down, NVD rate limit, ...
            say(f"banner candidates: NVD enrichment failed ({type(e).__name__}: {e}); "
                "continuing with verdict=unknown")

    versions = None if installed_apt_versions is None else list(installed_apt_versions)
    seen = set(existing_cve_ids)
    out: list[dict[str, Any]] = []
    for f in findings:
        cve_id = f.entry.cve_id
        if cve_id in seen:
            say(f"banner candidates: skip {cve_id} (already a candidate)")
            continue
        seen.add(cve_id)
        origin, installed = None, ""
        if versions is not None:
            installed = apt_match(f.package.version, versions)
            origin = "dpkg" if installed else BANNER_NOT_IN_INVENTORY
        out.append(finding_to_candidate(f, banner_by_source.get(f.package.source, ""), origin, installed))
    return out


# --- NVD discovery (v3-2) ----------------------------------------------------

def _nvd_discovery_module():
    _ensure_cve_matcher_importable()
    from cve_matcher import nvd_discovery  # type: ignore
    return nvd_discovery


def nvd_candidate(found: dict[str, Any]) -> dict[str, Any]:
    """cve_matcher.nvd_discovery result -> kev_findings-shaped candidate.

    Not in CISA KEV means there is no known-exploited signal, and the dict
    says so, so the analyzer does not read "candidate" as "being exploited".
    A Debian-revisioned package gets verdict `unknown` rather than
    `vulnerable`: Debian backports fixes without bumping the upstream version.
    """
    pkg = found["package"]
    parts = found["cpe"].split(":")
    vendor, product = (parts[3], parts[4]) if len(parts) > 5 else ("", "")
    score, sev = found["score"], found.get("severity", "")
    base = (f"NVD lists {found['cpe']} as affected (CVSS {score:g}{' ' + sev if sev else ''}). "
            "Not in CISA KEV: no known-exploited signal.")
    if found.get("distro_patched"):
        verdict = "unknown"
        detail = (base + f" Installed '{pkg.version}' carries a Debian revision, and Debian backports "
                  "security fixes without changing the upstream version, so being in NVD's range "
                  "does not show it is unpatched; judge from the distro fix version if you know it.")
    else:
        verdict = "vulnerable"
        detail = base
    desc = found.get("description", "")
    return {
        "cve_id": found["cve_id"],
        "kev_name": f"NVD {found['cve_id']} (not in CISA KEV)",
        "kev_vendor": vendor,
        "kev_product": product,
        "kev_description": desc,
        "cwes": [],
        "package_name": pkg.name,
        "package_version": pkg.version,
        "package_vendor": pkg.vendor,
        "package_source": pkg.source,
        "match_reason": "nvd-cpe",
        "match_score": 100.0,
        "verdict": verdict,
        "verdict_detail": detail,
        "ransomware_linked": False,
        "source": "nvd-cpe",
        "cvss": score,
    }


def nvd_candidates(
    packages: Iterable[Any],
    *,
    existing_cve_ids: Iterable[str] = (),
    min_cvss: float | None = None,
    per_product: int | None = None,
    max_total: int | None = None,
    api_key: str | None = None,
    discover_fn: Callable[..., list[dict[str, Any]]] | None = None,
    log: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Candidates NVD lists for the given packages that are not already known.

    `packages` are cve_matcher.inventory.Package objects (inventory entries
    and banner-derived services alike). CVEs already present from the KEV or
    banner paths are skipped so each is analysed once.
    """
    mod = _nvd_discovery_module()
    kwargs: dict[str, Any] = {"exclude_cve_ids": frozenset(existing_cve_ids), "api_key": api_key, "log": log}
    kwargs["min_cvss"] = mod.DEFAULT_MIN_CVSS if min_cvss is None else min_cvss
    kwargs["per_product"] = mod.DEFAULT_PER_PRODUCT if per_product is None else per_product
    kwargs["max_total"] = mod.DEFAULT_MAX_TOTAL if max_total is None else max_total
    found = (discover_fn or mod.discover)(list(packages), **kwargs)
    return [nvd_candidate(f) for f in found]


# --- OSV discovery (v3-7) ----------------------------------------------------

def _osv_discovery_module():
    _ensure_cve_matcher_importable()
    from cve_matcher import osv_discovery  # type: ignore
    return osv_discovery


def osv_candidate(found: dict[str, Any]) -> dict[str, Any]:
    """cve_matcher.osv_discovery result -> kev_findings-shaped candidate.

    OSV was asked about this exact ecosystem coordinate and version, so the version
    question is already answered; whether the vulnerable code is reachable in this
    deployment is what the analyzer still has to judge.
    """
    score, sev = found["score"], found.get("severity", "")
    where = f" at {found['path']}" if found.get("path") else ""
    detail = (f"OSV lists {found['ecosystem']} package {found['name']} {found['version']}{where} as affected by "
              f"{', '.join(found.get('advisories', []))} (CVSS {score:g}{' ' + sev if sev else ''}). "
              "Not in CISA KEV: no known-exploited signal. A library on disk is not necessarily "
              "loaded or reachable; judge that from the host and network evidence.")
    return {
        "cve_id": found["cve_id"],
        "kev_name": f"OSV {found['cve_id']} (not in CISA KEV)",
        "kev_vendor": found["ecosystem"],
        "kev_product": found["name"],
        "kev_description": found.get("description", ""),
        "cwes": [],
        "package_name": found["name"],
        "package_version": found["version"],
        "package_vendor": found["ecosystem"],
        "package_source": found.get("path", ""),
        "match_reason": "osv",
        "match_score": 100.0,
        "verdict": "vulnerable",
        "verdict_detail": detail,
        "ransomware_linked": False,
        "source": "osv",
        "cvss": score,
    }


def osv_candidates(
    libraries: Iterable[dict[str, Any]],
    *,
    existing_cve_ids: Iterable[str] = (),
    min_cvss: float | None = None,
    per_product: int | None = None,
    max_total: int | None = None,
    discover_fn: Callable[..., list[dict[str, Any]]] | None = None,
    log: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Candidates OSV lists for the scanner's `libraries`, skipping CVEs already known."""
    mod = _osv_discovery_module()
    kwargs: dict[str, Any] = {
        "exclude_cve_ids": frozenset(existing_cve_ids), "log": log,
        "min_cvss": mod.DEFAULT_MIN_CVSS if min_cvss is None else min_cvss,
        "per_product": mod.DEFAULT_PER_PRODUCT if per_product is None else per_product,
        "max_total": mod.DEFAULT_MAX_TOTAL if max_total is None else max_total,
    }
    return [osv_candidate(f) for f in (discover_fn or mod.discover)(list(libraries), **kwargs)]
