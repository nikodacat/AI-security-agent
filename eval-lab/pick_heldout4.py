"""Held-out set 4 selection. Same rule as pick_heldout3.py, new seed, sets 1-3 now excluded:
  pool   = Vulhub dirs named CVE-*, pinned image(s), no `build:`, product family not used in sets 1-3
  order  = random.Random(20261105).shuffle(pool)
  take   = first 10 with a distinct product family and every vulhub/* image <= 1000 MB compressed
The Vulhub clone is NOT pulled between sets 3 and 4 (HEAD 8fd6391), so the pool only shrinks.
"""
import json, pathlib, random, re, subprocess, os, yaml
ROOT = pathlib.Path("C:/Users/ideal/vulhub")
used = {s["dir"].split("/")[0] for s in yaml.safe_load(open("vulhub_scenarios.yaml", encoding="utf-8"))["scenarios"]}
pool = []
for comp in sorted(ROOT.glob("*/CVE-*/docker-compose.yml")):
    prod = comp.parent.parent.name
    if prod in used: continue
    t = comp.read_text(encoding="utf-8", errors="replace")
    if "build:" in t: continue
    imgs = re.findall(r"^\s*image:\s*(\S+)", t, re.M)
    if imgs: pool.append((prod, comp.parent.name, imgs))
print("pool", len(pool), "dirs,", len({p[0] for p in pool}), "products")
random.Random(20261105).shuffle(pool)
env = dict(os.environ, MSYS_NO_PATHCONV="1")
def size(img):
    r = subprocess.run(["docker", "manifest", "inspect", img], capture_output=True, text=True, env=env, timeout=60)
    try:
        d = json.loads(r.stdout)
    except Exception:
        return None
    if d.get("manifests"):
        return -1
    return round((d["config"]["size"] + sum(l["size"] for l in d["layers"])) / 1e6)
chosen, seen, skipped = [], set(), []
for prod, d, imgs in pool:
    if prod in seen: continue
    sizes = {i: size(i) for i in dict.fromkeys(imgs) if i.startswith("vulhub/")}
    if any(v is None for v in sizes.values()):
        skipped.append((prod, d, "size unknown")); continue
    if any(v > 1000 for v in sizes.values()):
        skipped.append((prod, d, f"too big {sizes}")); seen.add(prod); continue
    seen.add(prod)
    chosen.append((prod, d, list(dict.fromkeys(imgs)), sizes))
    if len(chosen) == 10: break
for c in chosen: print(c)
print("skipped:", skipped)
