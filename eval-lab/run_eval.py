"""Iterate run_full_scan.py across every container in ground_truth.yaml,
diff verdicts against expected values, write eval_results.csv.

Row types in the output (honest coverage picture, not just match rate):

  1. `both`         : GT expects this CVE + pipeline produced a verdict.
                      `match` is True/False.
  2. `gt_only`      : GT expects this CVE but pipeline did not surface it.
                      `actual` is empty, `match` is False.
                      -> coverage gap (scanner or matcher couldn't see it).
  3. `pipeline_only`: Pipeline produced a verdict for a CVE not in GT.
                      `expected` is empty, `match` is empty (not scored).
                      -> either a valid extra finding or a false positive.

Usage:
    python eval-lab/run_eval.py [--containers a,b,c] [--reuse-existing]
                                [--engine claude|fake]

Emits:
    eval-lab/reports/eval_results.csv
    eval-lab/reports/eval_summary.md   (human-readable roll-up)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
REPORTS_DIR = HERE / "reports"


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    gt = yaml.safe_load((HERE / "ground_truth.yaml").read_text(encoding="utf-8"))
    all_containers = list(gt["containers"].keys())
    containers = args.containers.split(",") if args.containers else all_containers
    print(f"Ground truth v{gt['version']} committed {gt['committed_at']}")
    print(f"Evaluating {len(containers)} container(s): {containers}")
    print()

    # Per-container: run the full chain (or reuse cached), collect timing.
    timings: dict[str, float] = {}
    for c in containers:
        if args.reuse_existing and (REPORTS_DIR / c / "verdicts.json").exists():
            print(f"[reuse]   {c}: using cached {REPORTS_DIR / c / 'verdicts.json'}")
            timings[c] = 0.0
            continue

        print(f"[run]     {c}: full chain with engine={args.engine} ...")
        t0 = time.monotonic()
        rc = _run_full_scan(c, args.engine, check_versions=True)
        elapsed = time.monotonic() - t0
        timings[c] = elapsed
        if rc != 0:
            print(f"          FAILED (rc={rc}); skipping this container's rows")
            continue
        print(f"          done in {elapsed:.1f}s")

    print()
    print(f"Diffing verdicts against ground truth ...")
    rows: list[dict[str, Any]] = []
    for c in containers:
        expected_by_cve = {e["cve_id"]: e for e in gt["containers"].get(c, [])}
        actual_by_cve = _load_verdicts(c)

        for cve_id, gt_entry in expected_by_cve.items():
            actual = actual_by_cve.pop(cve_id, None)
            if actual is None:
                rows.append({
                    "container": c,
                    "cve_id": cve_id,
                    "expected_verdict": gt_entry["expected"],
                    "actual_verdict": "",
                    "match": "False",
                    "row_type": "gt_only",
                    "time_seconds": f"{timings.get(c, 0):.2f}",
                    "reason": "",
                })
            else:
                match = actual["verdict"] == gt_entry["expected"]
                rows.append({
                    "container": c,
                    "cve_id": cve_id,
                    "expected_verdict": gt_entry["expected"],
                    "actual_verdict": actual["verdict"],
                    "match": str(match),
                    "row_type": "both",
                    "time_seconds": f"{timings.get(c, 0):.2f}",
                    "reason": actual["reason"][:200],
                })

        # Anything left in actual_by_cve is pipeline_only.
        for cve_id, actual in actual_by_cve.items():
            rows.append({
                "container": c,
                "cve_id": cve_id,
                "expected_verdict": "",
                "actual_verdict": actual["verdict"],
                "match": "",
                "row_type": "pipeline_only",
                "time_seconds": f"{timings.get(c, 0):.2f}",
                "reason": actual["reason"][:200],
            })

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = REPORTS_DIR / "eval_results.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "container", "cve_id", "expected_verdict", "actual_verdict",
            "match", "row_type", "time_seconds", "reason",
        ])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows -> {csv_path}")

    summary = _summarize(rows, timings, gt)
    summary_path = REPORTS_DIR / "eval_summary.md"
    summary_path.write_text(summary, encoding="utf-8")
    print(f"Wrote human summary -> {summary_path}")
    print()
    print(summary)

    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="run_eval.py",
                                description="Iterate the full chain over ground-truth containers and diff.")
    p.add_argument("--containers", default=None,
                   help="Comma-separated subset (default: everything in ground_truth.yaml)")
    p.add_argument("--engine", default="claude", choices=("fake", "claude"),
                   help="Verdict engine (default: claude)")
    p.add_argument("--reuse-existing", action="store_true",
                   help="Skip re-running the pipeline where verdicts.json already exists.")
    return p


def _run_full_scan(container: str, engine: str, check_versions: bool) -> int:
    env = dict(os.environ)
    env["MSYS_NO_PATHCONV"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    argv = [
        sys.executable, str(HERE / "run_full_scan.py"),
        "--container", container,
        "--engine", engine,
    ]
    if check_versions:
        argv.append("--check-versions")
    proc = subprocess.run(argv, env=env)
    return proc.returncode


def _load_verdicts(container: str) -> dict[str, dict[str, Any]]:
    path = REPORTS_DIR / container / "verdicts.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {v["cve_id"]: v for v in data.get("verdicts", [])}


def _summarize(rows, timings, gt) -> str:
    lines: list[str] = []
    lines.append(f"# eval_results.csv summary")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    lines.append(f"Ground truth: v{gt['version']} committed {gt['committed_at']}")
    lines.append("")

    # Bucket counts
    both_rows = [r for r in rows if r["row_type"] == "both"]
    gt_only = [r for r in rows if r["row_type"] == "gt_only"]
    pl_only = [r for r in rows if r["row_type"] == "pipeline_only"]
    matches = [r for r in both_rows if r["match"] == "True"]

    total_gt = len(both_rows) + len(gt_only)
    lines.append("## Coverage")
    lines.append("")
    lines.append(f"| Bucket                          | Count |")
    lines.append(f"|---------------------------------|------:|")
    lines.append(f"| Ground truth entries total      | {total_gt} |")
    lines.append(f"| ...covered by pipeline (both)   | {len(both_rows)} |")
    lines.append(f"| ...missed by pipeline (gt_only) | {len(gt_only)} |")
    lines.append(f"| Pipeline-only findings          | {len(pl_only)} |")
    lines.append("")
    covered = len(both_rows) / total_gt * 100 if total_gt else 0
    lines.append(f"**Ground-truth coverage rate:** {covered:.0f}% ({len(both_rows)}/{total_gt})")
    if both_rows:
        acc = len(matches) / len(both_rows) * 100
        lines.append(f"**Accuracy on covered entries:** {acc:.0f}% ({len(matches)}/{len(both_rows)})")
    lines.append("")

    # Per-container roll-up
    lines.append("## Per-container")
    lines.append("")
    lines.append("| Container | GT | Covered | Matched | Missed | Extra | Time (s) |")
    lines.append("|-----------|---:|--------:|--------:|-------:|------:|---------:|")
    per_c: dict[str, dict[str, int]] = {}
    for r in rows:
        c = r["container"]
        d = per_c.setdefault(c, {"gt": 0, "both": 0, "match": 0, "gt_only": 0, "pl_only": 0})
        if r["row_type"] == "both":
            d["both"] += 1
            d["gt"] += 1
            if r["match"] == "True":
                d["match"] += 1
        elif r["row_type"] == "gt_only":
            d["gt_only"] += 1
            d["gt"] += 1
        elif r["row_type"] == "pipeline_only":
            d["pl_only"] += 1
    for c, d in per_c.items():
        lines.append(
            f"| {c} | {d['gt']} | {d['both']} | {d['match']} | {d['gt_only']} | {d['pl_only']} | {timings.get(c, 0):.1f} |"
        )
    lines.append("")

    # Mismatch detail (both rows where match=False)
    misses = [r for r in both_rows if r["match"] == "False"]
    if misses:
        lines.append("## Mismatches (both sides present, verdict differed)")
        lines.append("")
        lines.append("| Container | CVE | Expected | Actual | Reason (excerpt) |")
        lines.append("|-----------|-----|----------|--------|------------------|")
        for r in misses:
            lines.append(
                f"| {r['container']} | {r['cve_id']} | {r['expected_verdict']} | "
                f"{r['actual_verdict']} | {r['reason'][:120]} |"
            )
        lines.append("")

    if gt_only:
        lines.append("## Coverage gaps (GT expected, pipeline never saw)")
        lines.append("")
        lines.append("| Container | CVE | Expected |")
        lines.append("|-----------|-----|----------|")
        for r in gt_only:
            lines.append(
                f"| {r['container']} | {r['cve_id']} | {r['expected_verdict']} |"
            )
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
