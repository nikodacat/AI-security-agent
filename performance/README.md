# performance/

Measured numbers and the material behind them. None of it is needed to run the tool.

| File | What it is |
|---|---|
| `numbers.md` | All evaluation numbers in one place: candidate recall on the blind sets, the answer-key results, cost, and the misses with their causes. |
| `results.png` | The results figure, drawn from `numbers.md` by `make_results.py` (`python performance/make_results.py`). |
| `reviews/` | The author's manual review of 20 sampled CONFIRMED verdicts from held-out set 3 (English sheet, a Chinese translation, and the script that draws the sample). |

The answer key and the raw scan and report files used by these numbers stay in `eval-lab/`.
