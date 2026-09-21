"""python-nmap wrapper.

Runs an ``nmap -sV --top-ports N -Pn`` scan against each target and returns
per-target results in a stable shape the emitter can iterate. This module
NEVER decides what a port observation means — it just surfaces what nmap
reported, including per-target errors as data (not exceptions), so a single
unreachable target does not abort a multi-target run.

The eval-attacker container has the nmap binary + python-nmap wheel
pre-installed (see ``eval-lab/dockerfiles/attacker.Dockerfile``). On a
developer laptop without nmap, importing this module still works —
:func:`scan_targets` raises :class:`ProberDependencyError` only at call
time. That keeps ``pytest`` runs green without a system-wide nmap install
(unit tests inject a fake PortScanner).
"""

from __future__ import annotations

from typing import Any


class ProberDependencyError(RuntimeError):
    """Raised when nmap or python-nmap is missing on the coordinator host."""


class ProberResult(dict):
    """Alias for ``dict[str, {"tcp":..., "udp":..., "error":...}]``.

    Not a subclass with logic — just a name to make signatures readable.
    """


def _build_arguments(top_ports: int, timeout: int) -> str:
    """Compose the ``arguments=`` string handed to python-nmap.

    - ``-sV``           : service/version detection (populates product/version)
    - ``--top-ports N`` : scan the N most common TCP ports
    - ``-Pn``           : skip host discovery (containers on evallab often
                          don't reply to pings, and we're on a controlled
                          network anyway)
    - ``--host-timeout``: cap per-target wall time, so one dead target
                          can't hang a multi-target run.
    """
    return f"-sV --top-ports {int(top_ports)} -Pn --host-timeout {int(timeout)}s"


def scan_targets(
    targets: list[str],
    top_ports: int = 100,
    timeout: int = 60,
    _scanner_factory: Any = None,
) -> dict:
    """Scan each target once; return ``{target: {tcp, udp, error}}``.

    ``_scanner_factory`` is a test seam: pass a callable returning a
    fake ``nmap.PortScanner`` to unit-test wiring without a real nmap
    binary. Production callers leave it None and let us import lazily.
    """
    if _scanner_factory is None:
        try:
            import nmap  # type: ignore[import-not-found]
        except ImportError as e:  # pragma: no cover — exercised in the container
            raise ProberDependencyError(
                "python-nmap not installed. On the coordinator: "
                "`pip install python-nmap`. Locally: run inside "
                "the eval-attacker container."
            ) from e
        scanner_factory = nmap.PortScanner
        scanner_error = nmap.PortScannerError  # type: ignore[attr-defined]
    else:
        scanner_factory = _scanner_factory
        # In tests, the fake raises RuntimeError; treat any exception as scan failure.
        scanner_error = Exception

    args = _build_arguments(top_ports=top_ports, timeout=timeout)
    per_target: dict[str, dict] = {}

    for target in targets:
        scanner = scanner_factory()
        try:
            scanner.scan(hosts=target, arguments=args)
        except scanner_error as e:
            per_target[target] = {"tcp": {}, "udp": {}, "error": str(e)}
            continue

        if target not in scanner.all_hosts():
            per_target[target] = {
                "tcp": {},
                "udp": {},
                "error": "no scan output (target unreachable or filtered)",
            }
            continue

        host_data = scanner[target]
        per_target[target] = {
            "tcp": {int(p): dict(host_data["tcp"][p]) for p in host_data.get("tcp", {})},
            "udp": {int(p): dict(host_data["udp"][p]) for p in host_data.get("udp", {})},
            "error": None,
        }

    return per_target
