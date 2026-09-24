"""CLI — argparse wiring + end-to-end pipeline test with mocks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from network_prober import __version__
from network_prober.cli import build_parser, main


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "docs" / "schemas" / "network_state.schema.json"


# --- argparse skeleton --------------------------------------------------------


def test_parser_builds() -> None:
    assert build_parser() is not None


def test_version_matches() -> None:
    assert __version__ == "0.0.1-scaffold"


def test_scan_requires_target_and_output() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["scan"])
    with pytest.raises(SystemExit):
        parser.parse_args(["scan", "--target", "x"])  # missing --output


def test_scan_parses_full_arg_set(tmp_path: Path) -> None:
    parser = build_parser()
    out = tmp_path / "out.json"
    args = parser.parse_args(
        [
            "scan",
            "--target", "a",
            "--target", "b",
            "--output", str(out),
            "--top-ports", "50",
            "--timeout", "30",
        ]
    )
    assert args.targets == ["a", "b"]
    assert args.output == out
    assert args.top_ports == 50
    assert args.timeout == 30


# --- end-to-end main() with mocked prober -------------------------------------


def test_main_end_to_end_writes_valid_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Full CLI run: mock scan_targets, let the real emitter validate against
    the real schema, confirm the file lands and validates."""
    canned = {
        "db-exposed": {
            "tcp": {
                6379: {"state": "open", "product": "Redis key-value store", "version": "6.2.6", "extrainfo": ""},
                22: {"state": "closed", "product": "", "version": "", "extrainfo": ""},
            },
            "udp": {},
            "error": None,
        }
    }

    def fake_scan_targets(targets, top_ports=100, timeout=60, ports=None, _scanner_factory=None):
        return canned

    # Patch the symbol *at its import site inside cli*, not at the source module,
    # because cli.py does a local `from .prober import scan_targets`.
    import network_prober.prober as prober_mod
    monkeypatch.setattr(prober_mod, "scan_targets", fake_scan_targets)

    out = tmp_path / "network_state.json"
    rc = main([
        "scan",
        "--target", "db-exposed",
        "--output", str(out),
        "--schema", str(SCHEMA_PATH),
    ])

    assert rc == 0
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data) == 2
    open_row = next(o for o in data if o["reachable"])
    assert open_row["port"] == 6379
    assert open_row["service_guess"] == {"vendor": "Redis", "product": "Redis", "version": "6.2.6"}


def test_main_reports_prober_dependency_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """python-nmap missing → exit 3 with a legible message on stderr."""
    from network_prober.prober import ProberDependencyError
    import network_prober.prober as prober_mod

    def raise_it(*args, **kwargs):
        raise ProberDependencyError("python-nmap not installed. hint: pip install python-nmap")

    monkeypatch.setattr(prober_mod, "scan_targets", raise_it)

    rc = main([
        "scan",
        "--target", "x",
        "--output", str(tmp_path / "x.json"),
        "--schema", "",  # skip validation, we won't get that far
    ])
    assert rc == 3
