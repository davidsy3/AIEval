# Baseline runs

Three reference runs of the pipeline over the 30-case dataset, kept so results are
comparable as the stages change. Everyday runs land in `../results/`, which is
git-ignored; these are the ones we cite.

| File | Mode | Stage 1 | FN | FP | Regression |
|---|---|---|---|---|---|
| `live_30cases_20261016-204922.json` | live, claude-sonnet-5, 115 calls | bandit | 38.2% | 19.2% | 0% (0 of 17) |
| `offline_bandit_30cases_20261015-195244.json` | offline, no API calls | bandit | 38.2% | 76.1% | 0% (0 of 23) |
| `offline_bandit_ast_30cases_20261015-195037.json` | offline, no API calls | bandit + `--ast` | 32.4% | 86.2% | 0% (0 of 26) |

What each one is for:

- **live** is the real result. Triage cleared 62 of 67 false positives without
  clearing a single real vulnerability; 11 cases auto-applied with the security
  oracle agreeing on all 11. All 5 surviving false positives are `B404
  import subprocess`.
- **offline bandit** is the "before" for the false-positive number: same detection,
  no triage. The 76.1% -> 19.2% gap is stage 2's contribution, measured.
- **offline bandit + ast** shows the CWE-22 trade-off: the AST supplement recovers
  2 of the 7 path-traversal cases (FN 100% -> 71% for CWE-22) and costs 10 points
  of overall precision.

An offline regression rate of 0% is not a result: offline repair returns the code
unchanged, so there is nothing to break. Only the live run's 0% means anything.

Each file holds the full run: every finding, every triage verdict with its
reasoning, every repair attempt, and the pytest output stage 4 judged it on.
