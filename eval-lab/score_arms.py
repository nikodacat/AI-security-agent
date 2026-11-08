"""Score compare_arms.py results against eval-lab/ground_truth.yaml.

Reads <root>/<container>/<engine>.<arm>.r<N>/result.json and prints markdown.

Metrics per (arm, engine), averaged over runs (min-max in brackets):
  recall      GT entries expected CONFIRMED that the system labelled CONFIRMED
  gt_correct  GT entries (all expected verdicts) whose verdict matched; a CVE
              the system never surfaced counts as wrong
  no_false_alarm  GT entries expected non-CONFIRMED that were either judged
              correctly or never raised (silence is a correct outcome there);
              GT entries expected CONFIRMED count only if CONFIRMED
  surfaced    GT CVEs that appeared as candidates at all
  false_conf  CONFIRMED on a GT entry whose expected verdict is NOT CONFIRMED
  unlisted    CONFIRMED on a CVE absent from the ground truth (GT is not
              exhaustive, so this is "unverified", not "wrong"); split by
              adjudicated_confirmed.yaml into true / false / unreviewed
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
_RUN_DIR = re.compile(r"(\w+)\.(\w+)\.r(\d+)")  # <engine>.<arm>.r<N>


def score_one(result: dict, gt: list[dict]) -> dict:
    verdict = {c["cve_id"]: c["verdict"] for c in result["candidates"]}
    expected = {e["cve_id"]: e["expected"] for e in gt}
    conf_expected = [c for c, v in expected.items() if v == "CONFIRMED"]
    return {
        "recall": sum(verdict.get(c) == "CONFIRMED" for c in conf_expected),
        "recall_total": len(conf_expected),
        "gt_correct": sum(verdict.get(c) == v for c, v in expected.items()),
        "gt_total": len(expected),
        "surfaced": sum(c in verdict for c in expected),
        "no_false_alarm": sum(verdict.get(c) == v or (c not in verdict and v != "CONFIRMED")
                              for c, v in expected.items()),
        "false_conf": sum(verdict.get(c) == "CONFIRMED" and v != "CONFIRMED" for c, v in expected.items()),
        "unlisted": sorted(c for c, v in verdict.items() if v == "CONFIRMED" and c not in expected),
        "n_candidates": result["n_candidates"],
        "missing_verdicts": sum(1 for c in result["candidates"] if c["verdict"] is None),
    }


def fmt(vals: list[int]) -> str:
    if not vals:
        return "-"
    mean = sum(vals) / len(vals)
    return f"{mean:.1f} [{min(vals)}-{max(vals)}]" if min(vals) != max(vals) else f"{vals[0]}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--gt", type=Path, default=HERE / "ground_truth.yaml")
    ap.add_argument("--adjudicated", type=Path, default=HERE / "adjudicated_confirmed.yaml",
                    help="Post-hoc verdicts on CVEs outside the GT; used for precision only.")
    a = ap.parse_args()
    gt_all = yaml.safe_load(a.gt.read_text(encoding="utf-8"))["containers"]
    adj_all: dict[str, dict[str, bool]] = {}
    if a.adjudicated.exists():
        raw = yaml.safe_load(a.adjudicated.read_text(encoding="utf-8")).get("containers", {})
        adj_all = {c: {e["cve_id"]: bool(e["adjudicated"]) for e in lst} for c, lst in raw.items()}

    rows = defaultdict(list)  # (container, engine, arm) -> [score dicts]
    for rj in sorted(a.root.glob("*/*.r*/result.json")):
        container = rj.parent.parent.name
        m = _RUN_DIR.fullmatch(rj.parent.name)
        if not m:  # archived or hand-renamed runs; not part of the scored matrix
            continue
        engine, arm = m.group(1), m.group(2)
        res = json.loads(rj.read_text(encoding="utf-8"))
        if container in gt_all and not res.get("error"):
            rows[(container, engine, arm)].append(score_one(res, gt_all[container]))

    def agg(key_filter):
        out = defaultdict(lambda: defaultdict(list))
        for (c, e, arm), lst in rows.items():
            if not key_filter(c):
                continue
            # sum across containers per run index
            for i, s in enumerate(lst):
                for m in ("recall", "recall_total", "gt_correct", "gt_total", "surfaced", "no_false_alarm", "false_conf"):
                    while len(out[(e, arm)][m]) <= i:
                        out[(e, arm)][m].append(0)
                    out[(e, arm)][m][i] += s[m]
        return out

    print("## Overall (3 containers, summed per run; mean [min-max] over runs)\n")
    print("| model | version | real vulns found (CONFIRMED) | GT entries correct | no false alarm (silent or correct) | GT CVEs surfaced | false CONFIRMED |")
    print("|---|---|---|---|---|---|---|")
    tot = agg(lambda c: True)
    for (e, arm), m in sorted(tot.items()):
        rt, gtt = m["recall_total"][0], m["gt_total"][0]
        print(f"| {e} | {arm} | {fmt(m['recall'])} / {rt} | {fmt(m['gt_correct'])} / {gtt} | "
              f"{fmt(m['no_false_alarm'])} / {gtt} | {fmt(m['surfaced'])} / {gtt} | {fmt(m['false_conf'])} |")

    print("\n## Per container\n")
    print("| container | model | version | real vulns found | GT correct | surfaced | candidates | unlisted CONFIRMED: true / false / unreviewed |")
    print("|---|---|---|---|---|---|---|---|")
    for (c, e, arm), lst in sorted(rows.items()):
        rt, gtt = lst[0]["recall_total"], lst[0]["gt_total"]
        unl = sorted({u for s in lst for u in s["unlisted"]})
        adj = adj_all.get(c, {})
        t, f = sum(adj.get(u) is True for u in unl), sum(adj.get(u) is False for u in unl)
        print(f"| {c} | {e} | {arm} | {fmt([s['recall'] for s in lst])}/{rt} | {fmt([s['gt_correct'] for s in lst])}/{gtt} | "
              f"{fmt([s['surfaced'] for s in lst])}/{gtt} | {fmt([s['n_candidates'] for s in lst])} | "
              f"{t} / {f} / {len(unl) - t - f} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
