"""Redraw docs/poster/results.png from the numbers in numbers.md (sections 3 and 1). Run: python docs/poster/make_results.py"""
from math import sqrt
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

INK, GREY, LIGHT, DARK = "#1f2933", "#9aa5b1", "#3d7edb", "#0c5293"
plt.rcParams.update({"font.size": 13, "axes.edgecolor": "#e4e7eb", "text.color": INK,
                     "axes.labelcolor": INK, "xtick.color": INK, "ytick.color": INK})


def wilson(k, n, z=1.96):
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


fig, (a, b) = plt.subplots(1, 2, figsize=(17, 6.2), gridspec_kw={"width_ratios": [1, 1.5]})

# left: answer key written by the author (numbers.md section 3)
labels = ["Week 9\n(KEV on package\ninventory)", "+ richer scanner\n+ service banners", "+ NVD discovery\n(experimental)"]
correct, real = [7, 11, 13], [0, 2, 3]
x = range(3)
a.bar([i - 0.2 for i in x], correct, 0.38, color=[GREY, LIGHT, DARK])
a.bar([i + 0.2 for i in x], real, 0.38, color="white", edgecolor=INK, hatch="//")
for i in x:
    a.text(i - 0.2, correct[i] + 0.4, correct[i], ha="center", weight="bold")
    a.text(i + 0.2, real[i] + 0.4, real[i], ha="center", weight="bold")
a.set_xticks(list(x), labels)
a.set_ylim(0, 27)
a.set_ylabel("Entries correct (of 24)  |  hatched: real vulns found (of 6)")
a.set_title("Key written by the author (3 containers)\n0 false CONFIRMED in every version", loc="left", fontsize=13)

# right: blind Vulhub sets, candidate recall (numbers.md section 1)
sets = [("Held-out 2\n(first run)", 10, 3, 3, 5), ("Held-out 3", 10, 3, 2, 2), ("Held-out 4", 10, 4, 2, 5),
        ("Pooled blind", 30, 10, 7, 12)]
cols = [("This tool", DARK), ("Trivy", GREY), ("Grype", "#cbd2d9")]
w = 0.26
for j, (name, col) in enumerate(cols):
    for i, s in enumerate(sets):
        k, n = s[2 + j], s[1]
        lo, hi = wilson(k, n)
        xx = i + (j - 1) * w
        b.bar(xx, k / n, w * 0.92, color=col, label=name if i == 0 else None)
        b.errorbar(xx, k / n, yerr=[[k / n - lo], [hi - k / n]], color=INK, capsize=3, lw=1.2)
        b.text(xx, hi + 0.02, f"{k}/{n}", ha="center", fontsize=11, weight="bold")
b.set_xticks(range(len(sets)), [s[0] for s in sets])
b.set_ylim(0, 1.08)
b.set_yticks([0, .25, .5, .75, 1], ["0%", "25%", "50%", "75%", "100%"])
b.set_ylabel("Expected CVE appears in the tool's list")
b.legend(frameon=False, loc="upper left", ncol=3)
b.set_title("Vulhub, 30 scenarios never seen during tuning (key: the CVE each directory demonstrates)\nbars: found / scenarios, lines: 95% Wilson interval", loc="left", fontsize=13)

for ax in (a, b):
    ax.spines[["top", "right"]].set_visible(False)
fig.text(0.01, 0.01, "Candidate recall, not a verdict: 'the tool listed it'. Intervals overlap: complementary, not better. "
         "Left: Claude engine, rows 1-2 mean of 2 runs, NVD row 1 run; small sample.", fontsize=10, color="#52606d")
fig.tight_layout(rect=(0, 0.04, 1, 1))
fig.savefig("docs/poster/results.png", dpi=150)
