"""Compact host-scanner facts for the analyzer's host_state.

host-scanner's `services` scanner reports listening sockets and web/PHP
configuration. The analyzer prompt has a hard size cap on host_state, so this
keeps the decision-relevant parts (which module is loaded, which process owns
which port, key php.ini flags) and drops bulk (full module lists are kept,
config-file path lists are not).
"""

from __future__ import annotations

from typing import Any

MAX_DIRECTIVES = 40


def summarize_services(services: dict[str, Any] | None) -> dict[str, Any]:
    """Compact view of the host-scanner `services` scanner output. {} if absent."""
    if not services or services.get("status") not in (None, "completed"):
        return {}
    out: dict[str, Any] = {}
    listening = services.get("listening") or []
    if listening:
        out["listening"] = [
            {k: s.get(k) for k in ("port", "bind", "loopback_only", "exe", "cmdline")}
            for s in listening
        ]
    apache = services.get("apache") or {}
    if apache:
        out["apache"] = {
            "modules_loaded": apache.get("modules", []),
            "mod_proxy_loaded": apache.get("has_mod_proxy"),
            "mod_cgi_loaded": apache.get("has_mod_cgi"),
            "mod_php_loaded": apache.get("has_mod_php"),
            "mod_rewrite_loaded": apache.get("has_mod_rewrite"),
            "directives": (apache.get("directives") or [])[:MAX_DIRECTIVES],
        }
    nginx = services.get("nginx") or {}
    if nginx:
        out["nginx"] = {"directives": (nginx.get("directives") or [])[:MAX_DIRECTIVES]}
    php = services.get("php") or {}
    if php:
        out["php_ini"] = php.get("settings", {})
    return out
