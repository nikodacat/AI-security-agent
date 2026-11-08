"""Check the facts quoted in CONFIRMED verdict reasons against the evidence the model was given.

A reason such as "Druid 0.20.0 ... listening on 0.0.0.0 ports 8081, 8082 ... externally reachable"
makes claims that can be checked without a human: does the host really listen on 8081, is it
bound to all interfaces, did the network probe reach it, does version 0.20.0 appear in the
inventory. This measures whether the reasons are *grounded*, not whether the verdict is *right*:
a reason can quote true facts and still reach a wrong conclusion.

Claim types
  port        a port the reason names must be listening on the host or seen by the probe
  external    a port the reason calls externally reachable must have `reachable: true` in network_state
  bind        a port the reason says is bound to all interfaces must have a non-loopback listener
  version     a version number the reason states as installed/running must occur in the host scan,
              the network state or the candidate record. Versions that follow a range word
              ("before", "fixed in", "through", ...) come from the advisory, not the host, and are skipped.

The checker is a set of regular expressions, so it can miss claims and, rarely, misread one.
`--show` prints every unsupported claim so they can be read by hand.

Usage:
  python eval-lab/check_evidence.py --root <dir with one folder per scenario> --run agy.osv.r3
Each scenario folder holds host.json, network_state.json and <run>/result.json.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_SENT_SPLIT = re.compile(r"(?<=[.;])\s+(?=[A-Z(])")
_PORTS_AFTER_WORD = re.compile(r"(?i)\bports?\s+((?:\d{1,5}\b(?:\s*(?:,|and|&|/|or)\s*)*)+)")
_PORT_SLASH_PROTO = re.compile(r"\b(\d{1,5})/(?:tcp|udp)\b", re.I)
_PORT_AFTER_COLON = re.compile(r"(?<![:\d.]):(\d{2,5})\b")
_PORT_AFTER_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}:(\d{2,5})\b")
_NUM = re.compile(r"\d{1,5}")

_EXTERNAL_WORDS = re.compile(r"(?i)extern|reachab|network[_ ]state|nmap|from outside|probe[sd]? (?:reach|confirm)|remote")
_WILDCARD_WORDS = re.compile(r"(?i)0\.0\.0\.0|all interfaces|wildcard|\[::\]|(?<![\w.])::(?![\w:])|publicly|non-?loopback")

_VERSION = re.compile(r"(?<![\w.\-])(\d+\.\d+(?:\.\d+){0,3})(?![\w]|\.\d)")
# Numbers that look like versions but are advisory data, not facts about the host:
# range ends ("before 2.4.50", "7.33.0 through 7.82.0"), fix versions, CVSS scores.
_SKIP_WINDOW = re.compile(
    r"(?i)\b(?:before|prior to|fix(?:ed|es)?|patched|through|up to|earlier than|below|older than|since|until|"
    r"introduced|cvss|score|range)\b|>=|<=|≥|≤|[<>]"
)
_SKIP_AFTER = re.compile(r"(?i)^\W{0,3}(?:through\b|to\b|and (?:later|earlier|above|below)|or (?:later|earlier)|\+)")
_NOT_VERSIONS = {"0.0.0.0", "127.0.0.1"}


def is_loopback(bind: str) -> bool:
    b = (bind or "").lower()
    return b.startswith("127.") or b == "::1" or b.startswith("::ffff:127.")


def is_wildcard(bind: str) -> bool:
    return (bind or "") in ("0.0.0.0", "::", "[::]", "*")


def split_sentences(text: str) -> list[str]:
    return [s for s in _SENT_SPLIT.split(text.strip()) if s]


def ports_in(sentence: str) -> list[int]:
    found: list[int] = []
    for m in _PORTS_AFTER_WORD.finditer(sentence):
        found += [int(n) for n in _NUM.findall(m.group(1))]
    found += [int(m.group(1)) for m in _PORT_SLASH_PROTO.finditer(sentence)]
    found += [int(m.group(1)) for m in _PORT_AFTER_COLON.finditer(sentence)]
    found += [int(m.group(1)) for m in _PORT_AFTER_IPV4.finditer(sentence)]
    return sorted({p for p in found if 1 <= p <= 65535})


def installed_versions_in(sentence: str) -> list[str]:
    """Version-looking numbers the sentence states as facts about the host (not advisory ranges)."""
    out = []
    for m in _VERSION.finditer(sentence):
        v = m.group(1)
        if v in _NOT_VERSIONS or re.fullmatch(r"\d+\.\d+\.\d+\.\d+", v):
            continue
        before = sentence[max(0, m.start() - 30):m.start()]
        after = sentence[m.end():m.end() + 14]
        if _SKIP_WINDOW.search(before) or _SKIP_AFTER.search(after):
            continue
        out.append(v)
    return out


class Evidence:
    """What a scenario's model could see: listeners, probe results, and a text corpus."""

    def __init__(self, host: dict, network: list | dict | None, candidate_text: str = "") -> None:
        scanners = (host or {}).get("scanners", {})
        listening = (scanners.get("services") or {}).get("listening") or []
        self.listeners: dict[int, list[str]] = {}
        for l in listening:
            self.listeners.setdefault(int(l["port"]), []).append(str(l.get("bind", "")))
        rows = network if isinstance(network, list) else (network or {}).get("results", []) if network else []
        self.has_network = bool(rows)
        self.probed_ports = {int(r["port"]) for r in rows if "port" in r}
        self.reachable = {int(r["port"]) for r in rows if r.get("reachable")}
        self.corpus = json.dumps(host, ensure_ascii=False) + json.dumps(network, ensure_ascii=False) + candidate_text

    def knows_port(self, p: int) -> bool:
        return p in self.listeners or p in self.probed_ports

    def wildcard_bound(self, p: int) -> bool:
        return any(is_wildcard(b) or (not is_loopback(b) and b) for b in self.listeners.get(p, []))

    def has_version(self, v: str) -> bool:
        return re.search(rf"(?<![\d.]){re.escape(v)}(?![\d])", self.corpus) is not None


def check_reason(reason: str, ev: Evidence) -> list[dict[str, Any]]:
    """Every checkable claim in `reason`, each with `ok` True/False."""
    claims: list[dict[str, Any]] = []
    for sent in split_sentences(reason):
        ports = ports_in(sent)
        for p in ports:
            claims.append({"type": "port", "value": p, "ok": ev.knows_port(p), "sentence": sent})
            if ev.has_network and _EXTERNAL_WORDS.search(sent):
                claims.append({"type": "external", "value": p, "ok": p in ev.reachable, "sentence": sent})
            if _WILDCARD_WORDS.search(sent) and p in ev.listeners:
                claims.append({"type": "bind", "value": p, "ok": ev.wildcard_bound(p), "sentence": sent})
        for v in installed_versions_in(sent):
            claims.append({"type": "version", "value": v, "ok": ev.has_version(v), "sentence": sent})
    return claims


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def run(root: Path, run_name: str, only: str = "CONFIRMED") -> tuple[list[dict], dict]:
    rows: list[dict] = []
    for sc in sorted(p for p in root.iterdir() if p.is_dir()):
        result_path = sc / run_name / "result.json"
        if not result_path.is_file() or not (sc / "host.json").is_file():
            continue
        net_path = sc / "network_state.json"
        ev_cache: dict[str, Evidence] = {}
        res = load_json(result_path)
        host = load_json(sc / "host.json")
        net = load_json(net_path) if net_path.is_file() else None
        pkgs = {c["cve_id"]: str(c.get("package", "")) for c in res.get("candidates", []) if "cve_id" in c}
        for v in res.get("verdicts", []):
            if v.get("verdict") != only:
                continue
            key = pkgs.get(v["cve_id"], "")
            ev = ev_cache.setdefault(key, Evidence(host, net, key))
            claims = check_reason(v.get("reason", ""), ev)
            rows.append({"scenario": sc.name, "cve": v["cve_id"], "reason": v.get("reason", ""), "claims": claims})
    c = Counter()
    for r in rows:
        for cl in r["claims"]:
            c[(cl["type"], cl["ok"])] += 1
    summary = {
        "run": run_name, "verdicts": len(rows),
        "no_checkable_claim": sum(1 for r in rows if not r["claims"]),
        "all_claims_supported": sum(1 for r in rows if r["claims"] and all(cl["ok"] for cl in r["claims"])),
        "some_claim_unsupported": sum(1 for r in rows if any(not cl["ok"] for cl in r["claims"])),
        "by_type": {t: {"claims": c[(t, True)] + c[(t, False)], "unsupported": c[(t, False)]}
                    for t in ("port", "external", "bind", "version")},
    }
    return rows, summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--run", action="append", required=True, help="run folder name; repeatable")
    ap.add_argument("--show", action="store_true", help="print every unsupported claim")
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    for name in args.run:
        rows, s = run(args.root, name)
        print(f"== {name}: {s['verdicts']} CONFIRMED verdicts")
        print(f"   all claims supported {s['all_claims_supported']}, some unsupported {s['some_claim_unsupported']}, "
              f"nothing checkable {s['no_checkable_claim']}")
        for t, d in s["by_type"].items():
            print(f"   {t:9s} claims {d['claims']:4d}  unsupported {d['unsupported']:3d}")
        if args.show:
            for r in rows:
                for cl in r["claims"]:
                    if not cl["ok"]:
                        print(f"   [{r['scenario']} {r['cve']}] {cl['type']} {cl['value']}: {cl['sentence'][:170]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
