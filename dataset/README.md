# Dev dataset (v0.1)

30 single-file Python programs with planted, annotated vulnerabilities and executable oracles,
for measuring an automated fixer: does it fix the real flaw, leave the safe look-alikes alone,
and keep the program working?

**The fixer only ever sees `app.py`.** Everything else is the answer key.

## Layout

```
dataset/
  case_NN_<name>/
    app.py              # the program under test: the only file a fixer sees
    reference_fix.py    # app.py with the planted vulnerabilities fixed, nothing else changed
    test_functional.py  # behaviour oracle: must pass before and after a fix
    test_security.py    # security oracle: vuln tests fail on app.py, pass on reference_fix.py
    conftest.py         # identical in every case: the `mod`, `secret_env`, `empty_env` fixtures
  ground_truth.json     # per-case annotations: CWE, location, subtlety, oracle, fix risk
  tools/validate.py     # checks the cases, the oracles and the dataset composition
  tools/build_sheet.py  # writes dataset_sheet.xlsx (or csv) from ground_truth.json
  PLAN.md               # the design this dataset was built to
```

## Composition

| | Count |
|---|---|
| Cases | 30 (16 single · 8 multi · 6 clean) |
| Real vulnerabilities | 34 |
| Decoys (safe look-alikes) | 27 |

Primary CWEs, four single-vulnerability cases each: **CWE-89** (SQL injection),
**CWE-78** (OS command injection), **CWE-22** (path traversal), **CWE-327**
(broken/weak crypto). **CWE-798** (hardcoded credentials) appears only in multi cases.

Subtlety is annotated per vulnerability as `obvious`, `moderate` or `subtle`:
11 / 13 / 10 across the 34. The subtle ones are the point of the dataset — a blocklist that
misses `&&`, a `shlex.quote` neutered by surrounding double quotes, a single `../` strip pass,
a prefix check with no separator, pbkdf2 with a constant salt and 1000 iterations.

Categories:

- **single** — exactly one real vulnerability, from one primary CWE.
- **multi** — two or three real vulnerabilities with different CWEs.
- **clean** — no real vulnerability at all, and two or three decoys. A fixer that "fixes"
  these is producing false positives; the security tests fail if it breaks the safe code.

## Running the oracles

```bash
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
```

Validate everything (oracles on both targets, ground-truth line numbers, composition):

```bash
.venv/bin/python tools/validate.py
```

Validate a subset while iterating, skipping the 16/8/6 composition rule:

```bash
.venv/bin/python tools/validate.py --partial case_01_inventory_lookup case_17_note_sync
```

Run one case's tests by hand. `TARGET_MODULE` picks which module the `mod` fixture imports,
so the same test files run against `app.py`, against `reference_fix.py`, or against a
candidate fix you drop in beside them:

```bash
cd case_13_member_login
TARGET_MODULE=app            ../.venv/bin/python -m pytest -q     # security tests fail here
TARGET_MODULE=reference_fix  ../.venv/bin/python -m pytest -q     # everything passes here
```

Build the summary workbook:

```bash
.venv/bin/python tools/build_sheet.py
```

## Scoring a fixer

For each case, hand the fixer `app.py` alone, then on its output run:

1. **`test_functional.py`** — regression check. A fix that breaks behaviour is not a fix,
   however secure the result is. Several cases exist mainly to catch this: case 13 seeds
   members migrated from an old system whose rows hold bare MD5 digests, so a fix that only
   understands its own new format locks them out.
2. **`test_security.py`** — did the planted flaws actually go? Tests named `test_vN_…` fail on
   `app.py` by construction and must pass after a real fix. Tests named `test_dN_…` cover the
   decoys and pass on `app.py` already; they fail if the fixer rewrites safe code into
   something broken.
3. **`ground_truth.json`** — for detection scoring, compare reported findings against the
   `vulnerabilities` entries. A finding matches when the CWE is equal and its line range
   overlaps `[line_start-3, line_end+3]` of the primary location or of any entry in
   `related_lines`. Anything overlapping a `decoys` entry is a false positive.

`expected_fix_risk` (Low/Medium/High) flags how much a fix is likely to disturb behaviour, and
`regression_note` spells out the specific trap where there is one.

## Oracle conventions worth knowing

- **Rejecting bad input counts as secure.** Security tests wrap calls in a helper that treats a
  raised exception as an acceptable outcome, so a fix may validate and refuse rather than
  sanitise, as long as legitimate input still works (the functional oracle enforces that).
- **CWE-798 tests are name-agnostic.** A fixer may pick any environment variable name. The
  `secret_env` fixture in `conftest.py` makes every secret-looking lookup resolve to a value the
  test chose; `empty_env` removes them all. Each 798 test then checks three things: the planted
  literal is gone from the source (AST scan), signing or login follows the environment, and with
  the variable unset the program **fails closed** rather than falling back to `""` or a default.
- **CWE-327 password tests don't pin an algorithm.** They require the stored value to differ from
  the fast digests of the password, two accounts with the same password to store different values,
  and a stretching KDF to run with at least 100k iterations. The spy patches `hashlib.pbkdf2_hmac`
  and `scrypt` both on `hashlib` and on the module under test, so `from hashlib import pbkdf2_hmac`
  is detected too.
- **CWE-78 tests assert a marker file was never created**, using `;`, `&&`, `` ` `` or `$(…)`
  depending on which bypass the case plants. Legitimate commands (`du`, `ls`, `grep`, `tar`, `wc`,
  `cp`, `gzip`, `echo`, `uname`, `df`, `date`, `id`) only ever touch paths under `tmp_path`.
  Nothing in the dataset touches the network.
- **Everything is stdlib only**, in both `app.py` and `reference_fix.py`; `validate.py` enforces
  that, along with an `app.py` length of 40–150 lines and the absence of words that would give the
  answer away (`vuln`, `unsafe`, `insecure`, `inject`, `sanitize`, `todo`, `fixme`, `exploit`).

## Known limitations

- Two cases plant a hardcoded *salt* (`SITE_SALT` in case 15, `STAFF_SALT` in case 22) as part of
  their CWE-327 finding. A scanner may report those as CWE-798; ground truth does not list them
  as such, so under the matching rule above that scores as a false positive.
- `reference_fix.py` is one correct fix, not the only one. Use the oracles to judge a candidate,
  not a diff against the reference.
- Oracles were developed and run on macOS with CPython 3.14. They rely on POSIX tools being
  present; `case_07`'s `list_archive` also filters the AppleDouble entries macOS `tar` writes.
