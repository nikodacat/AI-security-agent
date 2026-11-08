# Cloning the excluded forks

This repo tracks only the project's own packages. The four forks evaluated during the thesis
are intentionally not tracked here (see `UPSTREAM.md` for why).

If you need any of them locally — e.g. to re-run an evaluation or to
make the in-repo references resolvable — clone them as siblings of
`host-scanner/` at the exact commit recorded in `UPSTREAM.md`.

## All-in-one bootstrap (from the repo root)

```bash
# small forks — quick, useful for evaluation runs
git clone https://github.com/lucagioacchini/auto-pen-bench.git    && (cd auto-pen-bench    && git checkout 9c4890a)
git clone https://github.com/KHenryAegis/VulnBot.git              && (cd VulnBot           && git checkout 951cbcc)
git clone https://github.com/lucagioacchini/genai-pentest-paper.git && (cd genai-pentest-paper && git checkout 40e01e5)

# heavy: only if you actually need PentestGPT
git clone https://github.com/GreyDGL/PentestGPT.git               && (cd PentestGPT        && git checkout 6e84be8)
```

The repo's `.gitignore` already lists all four folders, so these clones
will not be picked up by `git status` in the outer repo.

## Shrinking PentestGPT (optional)

PentestGPT ships large demo videos. If you only need the source:

```bash
git clone --depth=1 https://github.com/GreyDGL/PentestGPT.git
rm -rf PentestGPT/demo PentestGPT/legacy/resources
```

That drops it from ~1.6 GB to under 100 MB.

## I want the local fork mods I made on my own machine

The earlier version of this repo had the small forks tracked as plain
folders. If you've kept those folders on your dev machine and want to
extract your mods as patches:

```bash
cd auto-pen-bench
# if the original .git is still here, just diff against the upstream commit
git diff 9c4890a -- . > ../my-auto-pen-bench-mods.patch
```

Then commit the `.patch` file into the outer repo (e.g. under a `patches/`
folder) — that keeps the repo small while preserving your changes.
