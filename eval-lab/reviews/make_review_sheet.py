"""Build the human-review sheet for model-stage CONFIRMED verdicts.

Draws a seeded random sample of the CONFIRMED verdicts of one run (the expected-CVE rows are left out:
they are scored separately) and writes a markdown table with the CVE description, the component, and the
model's reason, plus an empty answer column.

    python make_review_sheet.py <rows.json> --n 20 --seed 20261104 --out heldout3_confirmed_review.md
"""
import argparse
import glob
import json
import random
import time
import urllib.request
from pathlib import Path

CACHE = Path(__file__).resolve().parents[1] / "cve-matcher" / "cache" / "osv" / "vulns"


def _alias_index() -> dict[str, dict]:
    idx = {}
    for f in glob.glob(str(CACHE / "*.json")):
        try:
            d = json.load(open(f, encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for k in [d.get("id"), *d.get("aliases", [])]:
            if k:
                idx[k] = d
    return idx


def _get(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "ai-security-agent-eval"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def describe(cve: str, idx: dict) -> tuple[str, str]:
    if cve in idx:
        return (idx[cve].get("details") or idx[cve].get("summary") or "").strip(), "osv cache"
    try:
        d = _get(f"https://api.osv.dev/v1/vulns/{cve}")
        return (d.get("details") or d.get("summary") or "").strip(), "osv.dev"
    except Exception:
        pass
    try:
        time.sleep(6)  # NVD without a key: be slow
        d = _get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}")
        ds = d["vulnerabilities"][0]["cve"]["descriptions"]
        return next((x["value"] for x in ds if x["lang"] == "en"), ""), "nvd"
    except Exception:
        return "(description not found)", "none"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("rows")
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    rows = json.load(open(a.rows, encoding="utf-8"))
    pool = sorted((r for r in rows if r["verdict"] == "CONFIRMED" and not r["forced"]), key=lambda r: (r["sc"], r["cve"]))
    pick = random.Random(a.seed).sample(pool, min(a.n, len(pool)))
    idx = _alias_index()
    lines = [f"# Review sheet: {len(pick)} of {len(pool)} CONFIRMED verdicts (seed {a.seed})", "",
             "For each row answer: **is the vulnerable code reachable through the service that is exposed on this host?**",
             "`Y` = yes, an attacker reaching the exposed port could plausibly hit it; `N` = the component is there but nothing",
             "network-facing uses it (or the CVE needs something the host does not have); `?` = cannot tell from this sheet.",
             "Column A is answerable from this sheet alone: does the model's reason state a link between the vulnerable component",
             "and the exposed service (e.g. 'loaded by the running process'), or only that it is installed and a port is open?",
             "Write `yes` / `no` in A. Column B is the question above; `?` is expected for most rows.", "",
             "| # | Scenario | CVE | Component (source) | What the CVE is | Model's reason | A: reason links component to service? | B: Answer |", "|---|---|---|---|---|---|---|---|"]
    for i, r in enumerate(pick, 1):
        desc, how = describe(r["cve"], idx)
        cell = lambda s, n: " ".join(s.split())[:n].replace("|", "/")
        lines.append(f"| {i} | {r['sc']} | {r['cve']} | {cell(r['pkg'], 80)} ({r['src']}) | {cell(desc, 320)} | {cell(r['reason'], 300)} |  |  |")
    a.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {a.out} ({len(pick)} rows)")


if __name__ == "__main__":
    main()
