"""python-nmap wrapper — tested via ``_scanner_factory`` injection.

We don't require nmap on the developer laptop; the eval-attacker container
has it. Real end-to-end validation is a docker-exec integration run, not a
unit test.
"""

from __future__ import annotations

import pytest

from network_prober.prober import (
    ProberDependencyError,
    _build_arguments,
    scan_targets,
)


class _FakeScanner:
    """Bare-minimum stand-in for ``nmap.PortScanner``.

    - ``scan(hosts, arguments)`` records the args and stashes a canned result
    - ``all_hosts()`` returns the hosts we canned for
    - ``__getitem__`` returns the per-host dict
    """

    def __init__(self, canned: dict, raise_on_hosts: set[str] | None = None) -> None:
        self._canned = canned
        self._raise_on = raise_on_hosts or set()
        self.calls: list[dict] = []
        self._hosts_scanned: list[str] = []

    def scan(self, hosts: str, arguments: str) -> None:
        self.calls.append({"hosts": hosts, "arguments": arguments})
        if hosts in self._raise_on:
            raise RuntimeError("simulated nmap failure")
        if hosts in self._canned:
            self._hosts_scanned.append(hosts)

    def all_hosts(self) -> list[str]:
        return list(self._hosts_scanned)

    def __getitem__(self, host: str) -> dict:
        return self._canned[host]


def _make_factory(canned: dict, raise_on: set[str] | None = None):
    """Return a factory that hands out fresh FakeScanner instances sharing
    the same canned data — matching python-nmap's own per-scan pattern."""
    def factory() -> _FakeScanner:
        return _FakeScanner(canned, raise_on_hosts=raise_on)
    return factory


# --- argument construction ----------------------------------------------------


def test_build_arguments_includes_all_flags() -> None:
    args = _build_arguments(top_ports=50, timeout=30)
    assert "-sV" in args
    assert "--top-ports 50" in args
    assert "-Pn" in args
    assert "--host-timeout 30s" in args


def test_build_arguments_coerces_ints() -> None:
    """Guard against a caller passing a str via argparse mis-config."""
    args = _build_arguments(top_ports=100, timeout=60)
    assert "--top-ports 100" in args


# --- scan_targets happy path --------------------------------------------------


def test_scan_single_target_returns_normalized_result() -> None:
    canned = {
        "db-exposed": {
            "tcp": {
                6379: {"state": "open", "product": "Redis key-value store", "version": "6.2.6"},
            },
            "udp": {},
        }
    }
    factory = _make_factory(canned)

    result = scan_targets(["db-exposed"], top_ports=100, timeout=60, _scanner_factory=factory)

    assert set(result) == {"db-exposed"}
    assert result["db-exposed"]["error"] is None
    assert result["db-exposed"]["tcp"][6379]["product"] == "Redis key-value store"
    assert result["db-exposed"]["udp"] == {}


def test_scan_multiple_targets_all_present() -> None:
    canned = {
        "a": {"tcp": {80: {"state": "open"}}, "udp": {}},
        "b": {"tcp": {}, "udp": {}},
    }
    result = scan_targets(["a", "b"], _scanner_factory=_make_factory(canned))
    assert set(result) == {"a", "b"}


# --- scan_targets failure paths (as data, not exceptions) ---------------------


def test_scan_failure_recorded_as_error_field() -> None:
    canned = {"good": {"tcp": {}, "udp": {}}}
    factory = _make_factory(canned, raise_on={"bad"})
    result = scan_targets(["good", "bad"], _scanner_factory=factory)
    assert result["good"]["error"] is None
    assert "simulated nmap failure" in result["bad"]["error"]
    # Failing target still has empty tcp/udp for the emitter to iterate safely
    assert result["bad"]["tcp"] == {}


def test_target_not_in_scanner_output_becomes_error_row() -> None:
    """When nmap returns no data for a host (target unreachable / -Pn miss),
    the wrapper must NOT raise KeyError; it emits an error-row instead."""
    factory = _make_factory({})  # empty canned dict → no hosts scanned
    result = scan_targets(["ghost"], _scanner_factory=factory)
    assert result["ghost"]["tcp"] == {}
    assert "no scan output" in result["ghost"]["error"]


def test_missing_python_nmap_raises_prober_dependency_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Users on a machine without python-nmap should get a clear error, not
    an opaque ImportError from deep inside a scan call."""
    import builtins

    real_import = builtins.__import__

    def _fake_import(name: str, *args, **kwargs):
        if name == "nmap":
            raise ImportError("no module named 'nmap'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    with pytest.raises(ProberDependencyError, match="python-nmap not installed"):
        scan_targets(["anything"])  # no _scanner_factory → hits the real import path
