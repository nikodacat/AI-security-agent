"""attack-simulator CLI.

Usage:
    python -m attack_simulator narrate \\
        --verdicts path/to/verdicts.json \\
        --output   path/to/attack_narratives.json \\
        [--markdown path/to/attack_narratives.md] \\
        [--target  eval-db-exposed] \\
        [--engine  fake|claude] \\
        [--model   sonnet]

`--engine=fake` runs the canned narrator for offline development and tests.
`--engine=claude` requires `claude-agent-sdk` installed + the `claude` CLI
on PATH (or CLAUDE_CLI_PATH set). Deferred SDK import — passing --engine=fake
never touches the SDK.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__


EXIT_OK = 0
EXIT_USAGE = 2
EXIT_INPUT_ERROR = 3
EXIT_ENGINE_ERROR = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attack_simulator",
        description="Per-CONFIRMED-verdict attack-path narrative generator.",
    )
    parser.add_argument("--version", action="version", version=f"attack-simulator {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    narrate = subparsers.add_parser("narrate", help="Generate narratives from a verdicts.json file.")
    narrate.add_argument("--verdicts", required=True,
                         help="Path to verdicts.json from exposure-analyzer.")
    narrate.add_argument("--output", required=True,
                         help="Path to write attack_narratives.json.")
    narrate.add_argument("--markdown", default=None,
                         help="Optional path to also write a human-readable Markdown companion.")
    narrate.add_argument("--target", default="",
                         help="Target host / container label (recorded in each narrative).")
    narrate.add_argument("--engine", choices=("fake", "claude"), default="fake",
                         help="Narrator backend (default: fake).")
    narrate.add_argument("--model", default="sonnet",
                         help="Claude model when --engine=claude (default: sonnet).")

    return parser


def _load_verdicts(path: str) -> list[dict]:
    text = Path(path).read_text(encoding="utf-8")
    data = json.loads(text)
    if isinstance(data, dict) and "verdicts" in data:
        entries = data["verdicts"]
    elif isinstance(data, list):
        entries = data
    else:
        raise ValueError(
            f"{path}: unrecognized JSON shape (expected {{'verdicts': [...]}} or a bare list)"
        )
    if not isinstance(entries, list):
        raise ValueError(f"{path}: 'verdicts' is not a list")
    return entries


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _print_summary(narratives: list, engine_label: str) -> None:
    print(f"attack-simulator {__version__} -- engine: {engine_label}", file=sys.stderr)
    print(f"  wrote {len(narratives)} narrative(s)", file=sys.stderr)
    for n in narratives:
        heading = f"  {n.cve_id}"
        if n.target:
            heading += f" ({n.target})"
        # First non-empty line of the narrative as a hint
        first_line = next(
            (ln.strip().lstrip("#").strip() for ln in n.narrative.splitlines() if ln.strip()),
            "",
        )
        if first_line:
            heading += f"  →  {first_line[:80]}"
        print(heading, file=sys.stderr)


def _cmd_narrate(args: argparse.Namespace) -> int:
    from .narrator import AttackSimulator, fake_narrator_fn

    try:
        verdicts = _load_verdicts(args.verdicts)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        print(f"error: failed to read verdicts: {e}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    engine_label = f"{args.engine} (no AI)" if args.engine == "fake" else f"claude ({args.model})"

    if args.engine == "fake":
        narrator_fn = fake_narrator_fn
        model_tag = "fake"
    else:
        try:
            from .narrator import build_claude_narrator_fn
            narrator_fn = build_claude_narrator_fn(model=args.model)
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return EXIT_ENGINE_ERROR
        model_tag = f"claude-{args.model}"

    sim = AttackSimulator(narrator_fn, target=args.target, model=model_tag)
    narratives = sim.narrate_all(verdicts)

    from .narratives import dump_narratives, render_markdown

    generated_at = _now_iso()
    dump_narratives(narratives, args.output, generated_at=generated_at)

    if args.markdown:
        md_path = Path(args.markdown)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(render_markdown(narratives, generated_at=generated_at), encoding="utf-8")

    _print_summary(narratives, engine_label)
    print(f"  → JSON: {args.output}", file=sys.stderr)
    if args.markdown:
        print(f"  → Markdown: {args.markdown}", file=sys.stderr)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return EXIT_USAGE

    if args.command == "narrate":
        return _cmd_narrate(args)

    parser.print_help()
    return EXIT_USAGE
