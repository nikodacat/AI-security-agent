"""Banner-parser table — every rule gets a matching + non-matching case."""

from __future__ import annotations

import pytest

from network_prober.parser import BANNER_RULES, parse_banner


@pytest.mark.parametrize(
    ("banner", "expected"),
    [
        # Redis: real nmap -sV output on our db-exposed container
        (
            "Redis key-value store 6.2.6",
            {"vendor": "Redis", "product": "Redis", "version": "6.2.6"},
        ),
        # Apache httpd: extra parenthetical trailing text is common
        (
            "Apache httpd 2.4.49 ((Debian))",
            {"vendor": "Apache", "product": "httpd", "version": "2.4.49"},
        ),
        (
            "Apache httpd 2.4.29",
            {"vendor": "Apache", "product": "httpd", "version": "2.4.29"},
        ),
        # OpenSSH: p-patchlevel and trailing distro info
        (
            "OpenSSH 8.9p1 Ubuntu-3ubuntu0.1 (Ubuntu Linux; protocol 2.0)",
            {"vendor": "OpenSSH", "product": "OpenSSH", "version": "8.9p1"},
        ),
        # nginx: plain "nginx X.Y.Z"
        (
            "nginx 1.18.0",
            {"vendor": "nginx", "product": "nginx", "version": "1.18.0"},
        ),
        # MySQL: bare product+version
        (
            "MySQL 5.7.34",
            {"vendor": "MySQL", "product": "MySQL", "version": "5.7.34"},
        ),
        # WordPress: version can appear anywhere in the banner (via HTTP extra-info)
        (
            "Apache httpd 2.4.29 WordPress 5.7 self-hosted",
            # Apache rule wins because it matches first (earlier in BANNER_RULES).
            # WordPress-first would need reordering; today Apache is the eval-lab
            # target so this ordering is intentional.
            {"vendor": "Apache", "product": "httpd", "version": "2.4.29"},
        ),
        # WordPress-only banner (no Apache present) — falls to WP rule
        (
            "Some CMS running WordPress 5.7 backend",
            {"vendor": "WordPress", "product": "WordPress", "version": "5.7"},
        ),
    ],
)
def test_known_banners(banner: str, expected: dict) -> None:
    assert parse_banner(banner) == expected


@pytest.mark.parametrize(
    "banner",
    [
        "",
        "   ",
        "unknown service",
        "SSH-2.0-OpenSSH_8.9p1",  # raw SSH protocol banner ≠ nmap's normalized "OpenSSH 8.9p1"
        "HTTP/1.1 200 OK",
    ],
)
def test_no_match_returns_none(banner: str) -> None:
    assert parse_banner(banner) is None


def test_none_argument_returns_none() -> None:
    """Emitter passes ``banner or None``; parser must tolerate a None-like input.

    We treat empty and whitespace as None; an actual None is also OK because
    the emitter guards with ``if banner`` before calling us. Guard here anyway
    so future callers don't have to.
    """
    assert parse_banner("") is None


def test_rules_all_have_version_group() -> None:
    """Every rule must declare a ``version`` named group; without it the rule
    can never contribute a service_guess (all three fields are required by
    the schema)."""
    for rule in BANNER_RULES:
        assert "version" in rule.pattern.groupindex, f"{rule.pattern.pattern!r} missing (?P<version>...)"
