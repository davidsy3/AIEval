# AI Evaluator Engine v1 -- pipeline shell

A five-stage pipeline that **detects, explains, and repairs** security
vulnerabilities in Python code, then **proves** the repair with tests instead of
asking a model whether it worked.

This is a **shell**: every stage runs end to end, but each one is the simplest
version that works. Each stage is one file with a fixed signature and one owner,
so five people can work at once without touching each other's code.

```
                                       feedback from a failed attempt
                                    +-------------------------------+
                                    v                               |
  case -> [1 detect] -> [2 triage] -> [3 repair] -> [4 safety net] --+-> [5 decide]
           bandit        LLM          LLM           pytest + rescan      + report
           over-flags    real or      whole-file    NEVER asks the       3 numbers
           on purpose    false alarm  rewrite       model                per CWE
```

The v0 engine in `../Engine/` is untouched and still works. This folder reuses
its repair prompt, its A-E report format and its untrusted-input rules, and
reads the dataset and ground truth your teammate built in `../dataset/`
**read-only**. Nothing here writes to either folder.

---

## Setup

```bash
cd engine2
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Stage 4 runs each case's tests in a Docker container (no network, read-only
case files, memory/CPU/process caps). Install Docker Desktop, start it, and
build the sandbox image once:

```bash
docker build -t aieval-sandbox sandbox
```

Without Docker, `run.py` stops before running anything. To run anyway, as
**you** and with **no isolation**, pass `--allow-unisolated` (or set
`AIEVAL_ALLOW_UNISOLATED=1`) -- only on cases you have read. `pytest` opts in
by itself (`tests/conftest.py`), so the test suite runs without Docker.

For live runs, add a key (the file is git-ignored):

```bash
echo 'ANTHROPIC_API_KEY=sk-ant-...' > .env
```

## How to run

```bash
# the free one: no API key needed, no API calls, nothing to pay for
.venv/bin/python run.py ../dataset --offline

# the real one: needs ANTHROPIC_API_KEY
.venv/bin/python run.py ../dataset

# one case while you iterate on your stage
.venv/bin/python run.py ../dataset --case case_01_inventory_lookup

# with the stage-1 AST supplement (adds the CWE-22 coverage bandit lacks)
.venv/bin/python run.py ../dataset --offline --ast

# the tests -- run these from this folder, always
.venv/bin/python -m pytest
```

Every run prints the three numbers and saves everything (findings,
explanations, fixes, per-test results, pytest output, decisions) to
`results/run_<timestamp>.json`.

**Offline mode** is the thing that makes parallel work possible. With
`--offline` (or no API key) stage 2 keeps every finding and stage 3 returns the
code unchanged at High risk, so stages 1, 4 and 5 are exercised for real, for
free. The numbers from an offline run are a plumbing check, not a result.

## File layout

```
engine2/
  run.py              CLI: prints the three numbers, saves results/run_<ts>.json
  config.py           shared knobs: target CWEs, aliases, model, timeouts, tolerance
  models.py           THE CONTRACT between stages -- shared dataclasses
  llm.py              the one Anthropic wrapper + OFFLINE mode + injection rules
  dataset_loader.py   all knowledge of the dataset's on-disk format
  orchestrator.py     stages 1-5 per case + the repair -> safety retry loop
  stages/detect.py    stage 1
  stages/triage.py    stage 2
  stages/repair.py    stage 3
  stages/safety.py    stage 4   <-- runs untrusted code, read the warning
  stages/decide.py    stage 5
  sandbox/Dockerfile  the image stage 4 runs each case's tests in
  tests/              one group per stage + fakes.py (FakeLLM and hand-made cases)
  pytest.ini          collects tests/ only, never the dataset's own test files
  results/            run output (git-ignored)
```

## Ownership

| Stage | File | Contract (fixed signature) | Owns this number | First task |
|---|---|---|---|---|
| **1 Detect** | `stages/detect.py` | `detect(case, cfg) -> list[Finding]` | **false-negative rate** | Add CWE-22 detection. Bandit has no path-traversal rule, so all 7 CWE-22 vulns are invisible and that rate is 100%. Start from `_ast_findings` (behind `--ast`), then move to Semgrep rules. |
| **2 Triage + explain** | `stages/triage.py` | `triage(case, findings, llm, cfg) -> list[TriagedFinding]` | **false-positive rate** | Kill the noise. Offline, 76% of reported findings have no matching annotation; 16 land on annotated decoys. Batch a file's findings into one call while you are there. |
| **3 Repair** | `stages/repair.py` | `repair(case, confirmed, llm, cfg, feedback, attempt) -> Fix` | shares **regression rate** with stage 4 | Move from whole-file rewrite to a patch that touches only the vulnerable lines. Whole-file rewriting is where regressions come from. |
| **4 Safety net** | `stages/safety.py` | `verify(case, fix, cfg) -> SafetyResult` | **regression rate** | Make the re-scan fix-aware (see below). Test execution already runs in a Docker sandbox (`sandbox/Dockerfile`). |
| **5 Decide + report** | `stages/decide.py` | `decide(case, triaged, fix, safety, cfg) -> Decision` and `score(results, cases, cfg) -> dict` | **the report** | Per-case and per-subtlety breakdowns, and a CSV/markdown export so results go straight into the write-up. |

Shared files (`models.py`, `config.py`, `llm.py`, `dataset_loader.py`,
`orchestrator.py`, `run.py`) have no single owner -- see the rules below.

### The data that crosses each boundary

All of these live in `models.py`. Do not invent a parallel type in your stage.

| Boundary | Type | Carries |
|---|---|---|
| loader -> all | `Case` | `case_id`, `code`, `vulns[]`, `decoys[]`, `has_functional_tests` |
| 1 -> 2 | `Finding` | `cwe`, `line_start/end`, `detector`, `rule_id`, `severity`, `message` |
| 2 -> 3 | `TriagedFinding` | the `Finding`, `verdict` (`real` / `false_alarm`), `Explanation`, `notes` |
| 3 -> 4 | `Fix` | `fixed_code`, `risk`, `no_fix_possible`, `addressed_cwes`, `attempt` |
| 4 -> 5 | `SafetyResult` | 3x `TestRun` (per-test pass/fail), `regressions[]`, `decoy_breaks[]`, `vuln_gone`, `feedback_for_repair` |
| 5 | `Decision`, `CaseResult` | `action` (`auto_apply` / `propose_to_human` / `no_action`), `reason` |

## Rules for working in parallel

1. **Only edit your own stage file.** Your stage's internals are yours; nobody
   reviews how you do the work inside it.
2. **Changing a shared file needs a reviewed PR.** `models.py`, `config.py`,
   `llm.py`, `dataset_loader.py`, `orchestrator.py` and `run.py` are everyone's.
   Changing a field in `models.py` changes everyone's code: say so in the PR,
   and tag whoever is downstream of you.
3. **Never change another stage's signature** to make your stage easier. If you
   need different inputs, that is a PR against the contract, not a local edit.
4. **Keep `pytest` green and keep the offline run green.** Both before you push:
   ```bash
   .venv/bin/python -m pytest
   .venv/bin/python run.py ../dataset --offline
   ```
   The offline run needs no key, so "it needs an API key" is never a reason to
   skip it.
5. **Test your stage with hand-made inputs and `FakeLLM`.** `tests/fakes.py`
   gives you canned model replies and a dataset-shaped case in `tmp_path`. Your
   tests must not need the other four stages to be finished, and must not need
   an API key.
6. **Never touch `../Engine/` or `../dataset/`.** The v0 engine and the dataset
   are someone else's work. We read the dataset; we do not write to it.
7. **Run pytest from this folder.** `pytest.ini` keeps us from collecting the
   dataset's `test_functional.py` / `test_security.py` files, which are oracles
   and only run inside stage 4.
8. **The two escape hatches and the fail-safe are contract, not style.** Triage
   keeps a finding when there is no usable verdict; repair may say
   `NO FIX POSSIBLE`; stage 4 never asks a model whether the fix worked. Do not
   "simplify" any of those away.

## Baseline: the offline run, today

30 cases, 34 annotated vulns, bandit only, no API calls:

| | overall | CWE-89 | CWE-78 | CWE-22 | CWE-798 | CWE-327 |
|---|---|---|---|---|---|---|
| false-negative rate | **38.2%** | 0% | 0% | **100%** | 60% | 43% |
| false-positive rate | **76.1%** | 87% | 67% | n/a | 0% | 0% |
| regression rate | 0% (0 of 23) | - | - | - | - | - |

Read it as: stage 1 finds every SQL and command-injection flaw and drowns them
in noise (61 CWE-89 findings for 8 real ones), cannot see path traversal at all,
and misses most hard-coded credentials. The 0% regression rate is not a result:
offline repair changes nothing, so there is nothing to break. With `--ast`,
false negatives fall to 32.4% and false positives rise to 86.2%.

## Where the numbers come from

- **false-negative rate** = annotated vulns not reported / all annotated vulns
- **false-positive rate** = reported findings with no matching annotation / all reported
- **regression rate** = fixes that break previously passing tests / fixes judged

"Reported" means a finding that survived stage 2. A finding **matches** an
annotation when the CWE is equal and its line range overlaps the annotation's
primary span or any of its `related_lines`, widened by +/-3 lines
(`cfg.line_tolerance`). Matching is **one to one**: one finding accounts for at
most one annotated vulnerability. This is the dataset's own rule
(`../dataset/README.md`).

A fix is **judged** when stage 4 actually ran the functional tests on it, and it
**regressed** when a test that passed on the original file fails on the fix
(including a decoy security test, which passing-before is exactly the point).

## Known gaps, in one place

Each stage file's docstring lists its own. The ones that show up in the numbers:

- **Bandit has no CWE-22 rule.** CWE-22 false-negative rate is 100%. The `--ast`
  supplement recovers 2 of the 7 cases (FN 100% -> 71%), but it costs a lot of
  noise: overall false positives go from 76% to 86%, because it re-flags every
  f-stringed query bandit already reported. That trade is stage 1's and stage 2's
  problem to solve together.
- **B404 flags `import subprocess` as CWE-78**, on the import line, which can
  never match an annotation. Guaranteed false positives.
- **B608 flags parameterized queries too.** Bandit reports the same CWE-89 count
  on a vulnerable file and on a correct fix, so the stage-4 re-scan cannot verify
  a SQL fix at all. Stage 4 therefore trusts the dataset's `test_v*` oracle first
  and falls back to the re-scan only when a case has no security tests.
- **Bandit matches syntax, not data flow**, so the dataset's subtle cases are
  missed or reported on the wrong line.
- **CWE-798 depends on bandit's name wordlist.** `B105`/`B106` look for
  password-ish names, so a literal named `SYNC_TOKEN` or a key inside a dict
  default is missed.
- **Stage 4's sandbox needs Docker.** With `--allow-unisolated` it falls back to
  running untrusted code as you, with no isolation. The real-container test is
  skipped on machines without Docker, so the container path is only exercised
  where Docker is installed.

## Not here yet, on purpose

These are first tasks, not missing pieces:

- **Semgrep** as a second detector next to Bandit (stage 1).
- **RAG** over CWE/CVE text and project docs to ground explanations (stage 2).
- Patch-level repair instead of whole-file rewrite (stage 3).
- Parallel case execution, and resume for interrupted runs (orchestrator).
- Wiring the pipeline back into the VS Code extension (`../src/extension.ts`
  currently shells out to `../Engine/fixer.py`).
