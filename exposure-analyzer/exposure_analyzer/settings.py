"""Every tunable of a scan in one place, described well enough for a GUI to draw a form from it.

`FIELDS` is the single source of truth: name, type, default, bounds, group and a one-line
description. `Settings` is the validated value object the stages read. A settings file is a
JSON object holding any subset of the names; anything left out takes the default, and an
unknown name is an error rather than silently ignored.

    s = settings.load("scan.json", overrides={"max_calls": 30})
    settings.describe()      # list of dicts: what a GUI renders (label, type, default, min, max, choices)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, fields as dc_fields
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Field:
    name: str
    kind: type            # bool | int | float | str
    default: Any
    group: str            # "discovery" | "model" | "probes"
    help: str
    min: float | None = None
    max: float | None = None
    choices: tuple[str, ...] | None = None


FIELDS: tuple[Field, ...] = (
    # --- which candidates are looked for --------------------------------------------------
    Field("use_banner", bool, False, "discovery", "Also analyse CVEs matched from service banners (needs the network probe)."),
    Field("use_nvd", bool, False, "discovery", "Also analyse CVEs NVD lists for the detected software, beyond CISA KEV."),
    Field("use_osv", bool, False, "discovery", "Also analyse CVEs OSV.dev lists for every library the scanner found."),
    Field("min_cvss", float, 7.0, "discovery", "Discovery sources keep only CVEs at or above this CVSS base score.", 0.0, 10.0),
    Field("per_product", int, 15, "discovery", "At most this many candidates per product or library.", 1, 500),
    Field("max_per_source", int, 60, "discovery", "Safety cap on candidates from each discovery source.", 1, 5000),
    # --- the model stage ------------------------------------------------------------------
    Field("engine", str, "claude", "model", "Verdict engine.", choices=("claude", "openai", "fake")),
    Field("model", str, "", "model", "Model name for the openai-compatible engine (empty for claude)."),
    Field("base_url", str, "", "model", "Endpoint of the openai-compatible engine."),
    Field("max_calls", int, 60, "model", "Hard cap on model calls per run; 0 means no cap. Each candidate costs one call.", 0, 100000),
    Field("max_cost_usd", float, 2.0, "model", "Hard cap on spend per run as reported by the SDK; 0 means no cap.", 0.0, 10000.0),
    Field("prioritize", bool, True, "model", "When the budget cannot cover every candidate, judge KEV first, then the other sources in rotation by CVSS."),
    # --- probes against the target --------------------------------------------------------
    Field("run_probes", bool, True, "probes", "Run read-only probes in the target to back up a verdict."),
    Field("probe_timeout_sec", float, 10.0, "probes", "Wall-clock cap for one probe.", 1.0, 600.0),
    Field("max_output_chars", int, 4000, "probes", "Cap on probe output handed to the model.", 200, 100000),
)

_BY_NAME = {f.name: f for f in FIELDS}


class SettingsError(ValueError):
    """A settings file or override is not valid."""


def _make_settings() -> type:
    ns: dict[str, Any] = {"__annotations__": {f.name: f.kind for f in FIELDS}}
    for f in FIELDS:
        ns[f.name] = f.default
    return dataclass(frozen=True)(type("Settings", (), ns))


Settings = _make_settings()


def _coerce(f: Field, value: Any) -> Any:
    if f.kind is bool:
        if not isinstance(value, bool):
            raise SettingsError(f"{f.name}: expected true/false, got {value!r}")
        return value
    if f.kind in (int, float):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SettingsError(f"{f.name}: expected a number, got {value!r}")
        if f.kind is int and value != int(value):
            raise SettingsError(f"{f.name}: expected a whole number, got {value!r}")
        value = f.kind(value)
        if f.min is not None and value < f.min or f.max is not None and value > f.max:
            raise SettingsError(f"{f.name}: {value} is outside {f.min}..{f.max}")
        return value
    if not isinstance(value, str):
        raise SettingsError(f"{f.name}: expected text, got {value!r}")
    if f.choices and value not in f.choices:
        raise SettingsError(f"{f.name}: {value!r} is not one of {', '.join(f.choices)}")
    return value


def build(values: dict[str, Any] | None = None) -> "Settings":
    """Validate `values` (any subset of the names) and fill the rest with defaults."""
    values = values or {}
    unknown = sorted(set(values) - set(_BY_NAME))
    if unknown:
        raise SettingsError(f"unknown setting(s): {', '.join(unknown)}")
    return Settings(**{name: _coerce(_BY_NAME[name], v) for name, v in values.items()})


def load(path: str | Path | None = None, overrides: dict[str, Any] | None = None) -> "Settings":
    """Defaults, then the JSON file at `path`, then `overrides` (None values in overrides are skipped)."""
    merged: dict[str, Any] = {}
    if path is not None:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise SettingsError(f"cannot read settings file {path}: {e}") from e
        if not isinstance(data, dict):
            raise SettingsError(f"{path}: expected a JSON object")
        merged.update(data)
    merged.update({k: v for k, v in (overrides or {}).items() if v is not None})
    return build(merged)


def to_dict(s: "Settings") -> dict[str, Any]:
    return {f.name: getattr(s, f.name) for f in dc_fields(s)}


def dump(s: "Settings", path: str | Path) -> None:
    Path(path).write_text(json.dumps(to_dict(s), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def describe() -> list[dict[str, Any]]:
    """One dict per setting, in display order: what a GUI needs to draw a control for it."""
    return [{"name": f.name, "type": f.kind.__name__, "default": f.default, "group": f.group,
             "help": f.help, "min": f.min, "max": f.max,
             "choices": list(f.choices) if f.choices else None} for f in FIELDS]
