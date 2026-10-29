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


def _default_match(services: list[dict[str, Any]], catalog: Any = None) -> list[Any]:
    _ensure_cve_matcher_importable()
    from cve_matcher import kev as kev_mod  # type: ignore
    from cve_matcher import matcher as matcher_mod  # type: ignore
    from cve_matcher.inventory import Inventory, Package  # type: ignore

    packages = []
    for obs in services:
        g = obs["service_guess"]
        packages.append(Package(
            name=g["product"],
            version=str(g["version"]),
            vendor=g.get("vendor", "") or "",
            product=g["product"],
            source=f"banner:{obs.get('port')}/{obs.get('protocol', 'tcp')}",
        ))
    inventory = Inventory(scanned_at="", host_os="banner", host_version="", packages=packages)
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


def finding_to_candidate(finding: Any, banner: str = "") -> dict[str, Any]:
    """cve-matcher Finding -> kev_findings-shaped dict, tagged as banner-sourced."""
    entry = finding.entry
    detail = finding.verdict_detail or ""
    note = "version taken from service banner (not a package inventory)"
    return {
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
) -> list[dict[str, Any]]:
    """Build kev_findings-shaped candidates from banner observations.

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

    seen = set(existing_cve_ids)
    out: list[dict[str, Any]] = []
    for f in findings:
        cve_id = f.entry.cve_id
        if cve_id in seen:
            say(f"banner candidates: skip {cve_id} (already a candidate)")
            continue
        seen.add(cve_id)
        out.append(finding_to_candidate(f, banner_by_source.get(f.package.source, "")))
    return out
