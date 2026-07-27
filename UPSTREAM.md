# Upstream fork provenance

This file records every fork I cloned for thesis evaluation, the exact
upstream URL, and the commit SHA at the time of forking. None of these
forks are tracked in this repo — they live on disk for local research
only. See `SETUP-FORKS.md` for clone-back instructions.

| Fork | Upstream | Commit | License | Notes |
|---|---|---|---|---|
| PentestGPT | https://github.com/GreyDGL/PentestGPT | `6e84be8` | see fork's `LICENSE` | 1.6 GB; demo videos + bundled venv |
| auto-pen-bench | https://github.com/lucagioacchini/auto-pen-bench | `9c4890a` | see fork's `LICENSE` | Lightweight; Docker-based eval harness |
| VulnBot | https://github.com/KHenryAegis/VulnBot | `951cbcc` | see fork's `LICENSE` | Lightweight |
| genai-pentest-paper | https://github.com/lucagioacchini/genai-pentest-paper | `40e01e5` | see fork's `LICENSE` | PDFs / dataset reference |

## Local modifications

The thesis evaluation made minimal modifications to each fork (mostly
config tweaks and one or two patches per project). Diff against the
upstream commit recorded above to see them. If you want those diffs in
this repo, the cleanest path is to add a `patches/` directory and store
them as `*.patch` files alongside the upstream SHA — that keeps the repo
small while preserving the changes.

## Why not track the forks here?

- **Size:** PentestGPT alone is 1.6 GB.
- **License hygiene:** Upstream code in this repo would conflate the MIT
  licensing of my own work with the various other licenses upstream
  carries. Keeping forks separate lets each license stand on its own.
- **Update path:** Forks have their own git history. Tracking them as
  plain folders here would silently lose that history.
