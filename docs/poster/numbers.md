# Poster numbers

Every figure below is already recorded in README.md (Results) or PROJECT_STATE.md (v3-6b).
`results.png` is drawn from these; no new measurement.

| Claim | Number | Caveat to print next to it |
|---|---|---|
| Answer-key entries correct, week 9 -> banners -> NVD | 7 -> 11 -> 13 of 24 | 3 containers, key written by the author, corrected once (CVE-2022-0543) |
| Real vulns found | 0 -> 2 -> 3 of 6 | week 9 and banners are the mean of 2 runs, NVD is 1 run |
| False CONFIRMED | 0 in all three | same sample |
| Vulhub (key we did not write) | 3 of 5 with KEV + banners; 4 of 5 with NVD on nginx and bash | 1 run each; NVD not run on php, struts2, solr; bash is still wrong |
| NVD discovery cost | about 1000 s per container vs about 90 s | adds 30-40 candidates per container |
| Unlisted CONFIRMED from NVD | 28; 9 checked (Redis), all 9 hold; 19 unreviewed | "hold" = version affected and feature reachable; nothing exploited |
| Model cost per verdict call | 33.5k -> 3.3k input tokens, $0.207 -> $0.025 | text-only SDK options; one measurement |
| Local model | Qwen3.5-9B scored 11 of 24, same as Claude on the first two rows | not completed for the NVD row |

Do not print "complete assessment". Print: "tells you which matching CVEs are exploitable *on this host*",
and list the known gaps: KEV-only default coverage, Debian backports unverified,
dpkg-vs-binary mismatch (bash), posture findings not in the report, Linux only.
