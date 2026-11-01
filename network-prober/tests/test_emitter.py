"""Emitter — schema compliance + round-trip against the v2-2 fixture."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from network_prober.emitter import (
    build_port_observation,
    emit_network_state,
    observations_from_scan,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "docs" / "schemas" / "network_state.schema.json"
FIXTURE_PATH = REPO_ROOT / "eval-lab" / "fixtures" / "network_state.eval-db-exposed.json"


# --- build_port_observation ---------------------------------------------------


def test_build_port_observation_minimum_fields() -> None:
    obs = build_port_observation("db-exposed", 22, "tcp", reachable=False)
    assert obs == {"target": "db-exposed", "port": 22, "protocol": "tcp", "reachable": False}
    # Optional fields must be OMITTED, not set to None
    assert "banner" not in obs
    assert "service_guess" not in obs


def test_build_port_observation_full() -> None:
    obs = build_port_observation(
        "db-exposed", 6379, "tcp", reachable=True,
        banner="Redis key-value store 6.2.6",
        service_guess={"vendor": "Redis", "product": "Redis", "version": "6.2.6"},
    )
    assert obs["banner"] == "Redis key-value store 6.2.6"
    assert obs["service_guess"]["version"] == "6.2.6"


def test_build_port_observation_drops_empty_banner() -> None:
    """Passing ``banner=""`` should NOT land an empty-string field — the schema
    requires ``minLength: 1`` on any banner-adjacent value in service_guess, and
    an empty banner is more useful absent than serialized as ``""``."""
    obs = build_port_observation("t", 1, "tcp", reachable=True, banner="")
    assert "banner" not in obs


# --- service_guess fallback from nmap's own fields ----------------------------


def _scan_with(info: dict) -> dict:
    return {"t": {"tcp": {8080: dict({"state": "open", "product": "", "version": "", "extrainfo": ""}, **info)},
                  "udp": {}, "error": None}}


def test_service_without_a_parser_rule_uses_nmaps_product_and_version() -> None:
    obs = observations_from_scan(_scan_with({"product": "Apache Tomcat", "version": "9.0.30"}))[0]
    assert obs["service_guess"] == {"vendor": "Apache Tomcat", "product": "Apache Tomcat", "version": "9.0.30"}


def test_parser_rule_still_wins_over_the_nmap_fallback() -> None:
    obs = observations_from_scan(_scan_with({"product": "nginx", "version": "1.18.0"}))[0]
    assert obs["service_guess"] == {"vendor": "nginx", "product": "nginx", "version": "1.18.0"}


@pytest.mark.parametrize("info", [
    {"product": "Apache Jserv", "version": ""},                 # no version
    {"product": "", "version": "1.2"},                           # no product
    {"product": "Jetty", "version": "unknown"},                  # not a version
    {"product": "Jetty", "version": "x.y"},
])
def test_no_service_guess_when_nmap_gives_no_usable_version(info: dict) -> None:
    assert "service_guess" not in observations_from_scan(_scan_with(info))[0]


# --- observations_from_scan (fixture round-trip) ------------------------------


@pytest.fixture(scope="module")
def eval_db_exposed_fixture() -> list[dict]:
    with FIXTURE_PATH.open(encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def schema() -> dict:
    with SCHEMA_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def _mock_scan_matching_fixture() -> dict:
    """Construct a ``scan_targets`` output shaped so that ``observations_from_scan``
    reproduces the eval-db-exposed fixture.

    This is the CONTRACT test between prober output and fixture — if a future
    prober change breaks this, either the emitter or the fixture is wrong.
    """
    empty = {"state": "closed", "product": "", "version": "", "extrainfo": ""}
    return {
        "db-exposed": {
            "tcp": {
                22: empty,
                80: empty,
                443: empty,
                6379: {
                    "state": "open",
                    "product": "Redis key-value store",
                    "version": "6.2.6",
                    "extrainfo": "",
                },
            },
            "udp": {},
            "error": None,
        }
    }


def test_emitter_reproduces_fixture_semantically(eval_db_exposed_fixture: list[dict]) -> None:
    """Each fixture row must appear in the emitter's output, matching on all
    fields. Order-independent: schema doesn't constrain order and the analyzer
    shouldn't either.
    """
    produced = observations_from_scan(_mock_scan_matching_fixture())

    def key(o: dict) -> tuple:
        return (o["target"], o["port"], o["protocol"])

    produced_by_key = {key(o): o for o in produced}
    for expected in eval_db_exposed_fixture:
        got = produced_by_key.get(key(expected))
        assert got is not None, f"missing observation for {key(expected)}"
        assert got == expected, f"mismatch on {key(expected)}:\n  expected {expected}\n  got {got}"

    # And no extras beyond what the fixture describes
    assert len(produced) == len(eval_db_exposed_fixture)


def test_emitter_output_validates_against_schema(schema: dict) -> None:
    produced = observations_from_scan(_mock_scan_matching_fixture())
    Draft202012Validator(schema).validate(produced)


# --- emit_network_state (writes file + validates) -----------------------------


def test_emit_writes_file_and_validates(tmp_path: Path, schema: dict) -> None:
    out = tmp_path / "network_state.json"
    obs = emit_network_state(_mock_scan_matching_fixture(), out, schema_path=SCHEMA_PATH)
    assert out.exists()
    on_disk = json.loads(out.read_text(encoding="utf-8"))
    assert on_disk == obs
    Draft202012Validator(schema).validate(on_disk)


def test_emit_skips_validation_when_schema_is_none(tmp_path: Path) -> None:
    """Passing ``schema_path=None`` writes without touching jsonschema — useful
    when the caller pre-validates or wants a raw dump for debugging."""
    out = tmp_path / "raw.json"
    obs = emit_network_state({"t": {"tcp": {}, "udp": {}, "error": None}}, out, schema_path=None)
    assert obs == []
    assert json.loads(out.read_text(encoding="utf-8")) == []
