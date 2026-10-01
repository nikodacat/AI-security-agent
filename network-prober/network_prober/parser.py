"""Banner-parser table.

Nmap's ``-sV`` output gives us structured ``product`` / ``version`` fields for
services it recognizes, but the strings are inconsistent across services
("Redis key-value store 6.2.6" vs "Apache httpd 2.4.49 ((Debian))" vs
"OpenSSH 8.9p1 Ubuntu-3ubuntu0.1"). This module normalizes them into the
``service_guess`` shape defined in ``docs/schemas/network_state.schema.json``:
``{vendor, product, version}``.

Adding a new service: append a :class:`BannerRule` to :data:`BANNER_RULES`
with a regex that captures a ``version`` named group. First match wins.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class BannerRule:
    """One row of the parser table.

    ``pattern`` must define a ``(?P<version>...)`` named group; ``vendor`` and
    ``product`` are the normalized names (not pulled from the match).
    """

    pattern: re.Pattern[str]
    vendor: str
    product: str


BANNER_RULES: list[BannerRule] = [
    # Redis: nmap emits "Redis key-value store 6.2.6"
    BannerRule(
        re.compile(r"^Redis key-value store\s+(?P<version>\S+)"),
        vendor="Redis",
        product="Redis",
    ),
    # Apache httpd: nmap emits "Apache httpd 2.4.49 ((Debian))" or similar
    BannerRule(
        re.compile(r"^Apache httpd\s+(?P<version>[\d.]+[\w.-]*)"),
        vendor="Apache",
        product="httpd",
    ),
    # OpenSSH: nmap emits "OpenSSH 8.9p1 Ubuntu-3ubuntu0.1 (Ubuntu Linux; ...)"
    BannerRule(
        re.compile(r"^OpenSSH\s+(?P<version>\S+)"),
        vendor="OpenSSH",
        product="OpenSSH",
    ),
    # nginx: nmap emits "nginx 1.18.0"
    BannerRule(
        re.compile(r"^nginx\s+(?P<version>\S+)"),
        vendor="nginx",
        product="nginx",
    ),
    # MySQL: nmap emits "MySQL 5.7.34" (product string used as vendor too)
    BannerRule(
        re.compile(r"^MySQL\s+(?P<version>\S+)"),
        vendor="MySQL",
        product="MySQL",
    ),
    # WordPress: nmap sometimes surfaces the WP version in the HTTP banner
    # extra-info as "WordPress 5.7" when the site headers leak it.
    BannerRule(
        re.compile(r"\bWordPress\s+(?P<version>\d[\w.-]*)"),
        vendor="WordPress",
        product="WordPress",
    ),
]


def parse_banner(banner: str) -> dict | None:
    """Return ``{vendor, product, version}`` for the first matching rule, or None.

    An empty / whitespace-only banner always returns None. The analyzer
    prompt is expected to fall back to the raw banner in that case.
    """
    if not banner or not banner.strip():
        return None
    for rule in BANNER_RULES:
        m = rule.pattern.search(banner)
        if m and (version := m.group("version")):
            return {
                "vendor": rule.vendor,
                "product": rule.product,
                "version": version,
            }
    return None
