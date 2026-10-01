"""fix-publisher CLI.

Usage:
    python -m fix_publisher publish \\
        --verdicts path/to/verdicts.json \\
        --output   path/to/remediations.json \\
        [--markdown path/to/remediations.md] \\
        [--target   eval-cms-plugin] \\
        [--engine   fake|claude] \\
        [--model    sonnet]

`--engine=fake` runs the canned publisher for offline development.
`--engine=claude` requires `claude-agent-sdk` installed + the `claude`
CLI on PATH. Deferred SDK import — passing --engine=fake never touches
the SDK.
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
        prog="fix_publisher",
        description="Per-CONFIRMED-verdict remediation drafter.",
    )
    parser.add_argument("--version", action="version", version=f"fix-publisher {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    publish = subparsers.add_parser(
        "publish",
        help="Generate remediation drafts from a verdicts.json file.",
    )
    publish.add_argument("--verdicts", required=True,
                         help="Path to verdicts.json from exposure-analyzer.")
    publish.add_argument("--output", required=True,
                         help="Path to write remediations.json.")
    publish.add_argument("--markdown", default=None,
                         help="Optional path to also write a human-readable Markdown companion.")
    publish.add_argument("--target", default="",
                         help="Target host / container label (recorded in each remediation).")
    publish.add_argument("--engine", choices=("fake", "claude"), default="fake",
                         help="Publisher backend (default: fake).")
    publish.add_argument("--model", default="sonnet",
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


def _print_summary(rems: list, engine_label: str) -> None:
    print(f"fix-publisher {__version__} -- engine: {engine_label}", file=sys.stderr)
    print(f"  wrote {len(rems)} remediation(s)", file=sys.stderr)
    for r in rems:
        heading = f"  {r.cve_id}"
        if r.target:
            heading += f" ({r.target})"
        cmd = (r.apt_command or "").splitlines()[0] if r.apt_command else "(no apt command)"
        heading += f"  →  {cmd[:80]}"
        print(heading, file=sys.stderr)


def _cmd_publish(args: argparse.Namespace) -> int:
    from .publisher import FixPublisher, fake_publisher_fn

    try:
        verdicts = _load_verdicts(args.verdicts)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        print(f"error: failed to read verdicts: {e}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    engine_label = f"{args.engine} (no AI)" if args.engine == "fake" else f"claude ({args.model})"

    if args.engine == "fake":
        publisher_fn = fake_publisher_fn
        model_tag = "fake"
    else:
        try:
            from .publisher import build_claude_publisher_fn
            publisher_fn = build_claude_publisher_fn(model=args.model)
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return EXIT_ENGINE_ERROR
        model_tag = f"claude-{args.model}"

    pub = FixPublisher(publisher_fn, target=args.target, model=model_tag)
    rems = pub.publish_all(verdicts)

    from .remediations import dump_remediations, render_markdown

    generated_at = _now_iso()
    dump_remediations(rems, args.output, generated_at=generated_at)

    if args.markdown:
        md_path = Path(args.markdown)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(render_markdown(rems, generated_at=generated_at), encoding="utf-8")

    _print_summary(rems, engine_label)
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

    if args.command == "publish":
        return _cmd_publish(args)

    parser.print_help()
    return EXIT_USAGE
