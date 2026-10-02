# Dev dataset plan (v0.1)

30 single-file Python programs, each with planted and annotated vulnerabilities (or none) and executable oracles.
The fixer only ever sees `app.py`.

Subtlety key: **O** = obvious, **M** = moderate, **S** = subtle.

## Cases

| # | case_id | Context | Cat. | Real vulns (CWE · subtlety · technique) | Planned decoys |
|---|---|---|---|---|---|
| 01 | case_01_inventory_lookup | Warehouse stock lookup by SKU/name (plain functions) | single | 89 · O · name f-stringed straight into `SELECT` | 89: `COUNT(*)` with the table name f-stringed from a module constant, values parameterized |
| 02 | case_02_employee_directory | Staff directory search by department (class) | single | 89 · M · helper `_where_clause(dept)` returns a string that gets appended to the query | — |
| 03 | case_03_book_catalog | Library catalog title search (functions) | single | 89 · S · rejects input containing `;` or `--`, then f-strings it (`' OR '1'='1` has neither) | 89: author search via parameterized `LIKE ?` |
| 04 | case_04_ticket_status_report | Support-ticket status export (argparse CLI) | single | 89 · O · `status` CLI arg concatenated with `+` into `WHERE` | — |
| 05 | case_05_disk_usage_report | Per-folder disk usage summary (functions) | single | 78 · O · `subprocess.check_output(f"du -sk {folder}", shell=True)` | 78: `subprocess.run(["ls", "-1", base])`, list args, no shell |
| 06 | case_06_log_search | Grep-style search across local log files (class) | single | 78 · M · `_build_cmd(pattern, file)` returns a string that goes to `os.popen` | — |
| 07 | case_07_backup_archiver | Tarball backup of a project folder (argparse CLI) | single | 78 · S · blocklists `;` and `\|` only; `&&` and `$()` still work | — |
| 08 | case_08_text_stats | Line/word counter for text files (dataclass module) | single | 78 · S · `shlex.quote(path)` wrapped in double quotes, so `$(...)` still expands inside `"'…'"` | — |
| 09 | case_09_log_viewer | Serve the tail of a named log file (functions) | single | 22 · O · `open(os.path.join(LOG_DIR, name))` | 327: `md5(..., usedforsecurity=False)` used as an ETag |
| 10 | case_10_file_share | Download helper for shared files (class) | single | 22 · M · `_locate(name)` returns `self.root / name`, and an absolute `name` replaces the root | — |
| 11 | case_11_template_loader | Email template loader (functions) | single | 22 · S · `name.replace("../", "")` applied once (`....//` bypasses it) | — |
| 12 | case_12_report_exporter | Write CSV reports into an exports dir (argparse CLI) | single | 22 · S · `abspath(p).startswith(str(base))` with no separator, so the sibling `exports_old/` passes | 22: a read path checked with `resolve().is_relative_to(base)` |
| 13 | case_13_member_login | Gym membership login store (class, sqlite) | single | 327 · O · `md5(pw).hexdigest()`. **Regression trap:** seeded legacy MD5 users must still log in (risk Medium) | — |
| 14 | case_14_license_checker | Offline license-key verifier (functions) | single | 327 · M · `_sign()` helper uses `sha1(secret + payload)` as the MAC (secret passed in, not a literal) | — |
| 15 | case_15_forum_accounts | Forum account registration (dataclass module) | single | 327 · S · `sha256(SITE_SALT + pw)`: one global salt and a single fast hash | 78: `subprocess.run(["echo", ...])` notification, list args |
| 16 | case_16_api_client_registry | Stores hashed client secrets for an internal API (class) | single | 327 · M · `_digest()` helper uses unsalted `sha1` | — |
| 17 | case_17_note_sync | Note-taking CLI with a sync token (argparse CLI) | multi | 89 · M · search clause built in a helper · **798 · O** · `SYNC_TOKEN = "…"` module constant | 89: constant-table f-string with parameterized values |
| 18 | case_18_webhook_relay | Runs local hook commands on incoming events (dataclass) | multi | 78 · M · command template `.format(event=…)` with `shell=True` · **798 · M** · signing secret as a dataclass field default | 78: `subprocess.run([...])` list args |
| 19 | case_19_thumbnail_cache | Image thumbnail cache wrapper (class) | multi | 22 · O · upload name joined to the base dir · **798 · S** · `os.environ.get("GALLERY_KEY", "<literal>")` fallback | 327: `md5(usedforsecurity=False)` cache filename |
| 20 | case_20_billing_portal | Invoice lookup and admin login (functions) | multi | 327 · O · `md5` passwords · 89 · S · `invoice_id.strip()` "cleaned", then placed unquoted in `WHERE id = {}` · **798 · O** · `ADMIN_PASSWORD = "…"` | — |
| 21 | case_21_site_publisher | Static-site page publisher (argparse CLI) | multi | 78 · O · `os.system(f"cp {src} {dst}")` · 22 · M · page slug → path via a helper · **798 · M** · deploy key in a `DEFAULT_CONFIG` dict | — |
| 22 | case_22_clinic_appointments | Clinic appointment booking + staff login (class) | multi | 89 · O · patient name f-string · 327 · S · `pbkdf2_hmac` with a constant salt and 1000 iterations | 22: resolve + `is_relative_to` on attachment export |
| 23 | case_23_audit_logger | Audit event store with a gzip export (functions) | multi | 89 · M · filter dict joined into `WHERE` · 78 · M · export helper builds `gzip -c … > …` for `shell=True` | — |
| 24 | case_24_config_loader | Load named config profiles, verify integrity (dataclass) | multi | 22 · M · profile name → path via a helper · 327 · S · `hmac.new(key, data, "md5")` | 798: secret read via `os.environ["CONFIG_HMAC_KEY"]` |
| 25 | case_25_user_settings | Per-user preferences store (class, sqlite) | clean | — | 89: constant-table f-string + params · 327: `md5(usedforsecurity=False)` ETag · 798: `os.environ` secret |
| 26 | case_26_system_info | Host info reporter (argparse CLI) | clean | — | 78: `subprocess.run(["uname", "-a"])` · 78: `shell=True` with `shlex.quote` on the only variable · 22: `resolve().is_relative_to` on the output file |
| 27 | case_27_document_vault | Per-user document storage (class) | clean | — | 22: resolve + `is_relative_to` · 327: `pbkdf2_hmac` + `os.urandom` salt · 89: parameterized `INSERT` |
| 28 | case_28_session_tokens | Signed session cookies (functions) | clean | — | 798: `os.environ["SESSION_SECRET"]` · 327: `hmac` + `sha256` + `compare_digest` · 327: `md5(usedforsecurity=False)` shard key |
| 29 | case_29_csv_importer | Import CSV rows into sqlite tables (argparse CLI) | clean | — | 89: table name chosen from an allowlist dict and f-stringed · 89: `executemany` with placeholders |
| 30 | case_30_job_runner | Run named maintenance jobs from a registry (dataclass) | clean | — | 78: job name looked up in a dict of fixed argv lists, `shell=False` · 22: log path resolved + checked |

## Composition check

| Rule | Target | Planned |
|---|---|---|
| single / multi / clean | 16 / 8 / 6 | 16 / 8 / 6 ✓ |
| Singles per primary CWE | 4 each | 89: 01–04 · 78: 05–08 · 22: 09–12 · 327: 13–16 ✓ |
| Multi: 2–3 vulns, mixed primaries | 2–3 | 17–19: 2 each · 20, 21: 3 · 22–24: 2 each ✓ |
| Multi cases with CWE-798 | ~5 | 17, 18, 19, 20, 21 = 5 ✓ |
| CWE-798 only in multi | yes | ✓ |
| Clean cases with 2+ decoys | 6 | all 6 have 2–3 ✓ |
| Single/multi cases with a decoy | ≥ 8 | 01, 03, 05, 09, 12, 15, 17, 18, 19, 22, 24 = 11 ✓ |
| Unique contexts | 30 | ✓ |

**Subtlety per CWE (34 real vulns)**

| CWE | O | M | S | Total |
|---|---|---|---|---|
| 89 | 3 (01, 04, 22) | 3 (02, 17, 23) | 2 (03, 20) | 8 |
| 78 | 2 (05, 21) | 3 (06, 18, 23) | 2 (07, 08) | 7 |
| 22 | 2 (09, 19) | 3 (10, 21, 24) | 2 (11, 12) | 7 |
| 327 | 2 (13, 20) | 2 (14, 16) | 3 (15, 22, 24) | 7 |
| 798 | 2 (17, 20) | 2 (18, 21) | 1 (19) | 5 |

## Oracle design notes

- **Module switching:** each case has a `conftest.py` with a `mod` fixture that imports `os.environ["TARGET_MODULE"]` (`app` or `reference_fix`, default `app`). `validate.py` runs pytest once per case per target in a subprocess, so the repeated `app` module names never collide.
- **CWE-78 exploits:** `; touch {tmp}/pwned`, `&& touch …`, and `$(touch …)`, depending on which bypass the case plants. The assertion is that `pwned` does not exist. Legitimate commands (`du`, `ls`, `grep`, `tar`, `wc`, `cp`, `gzip`, `echo`, `uname`) work only on files under `tmp_path`. Nothing touches the network.
- **CWE-798 security test:** first, an AST scan finds no string literal equal to the planted secret. Second, with `monkeypatch.setenv` set to a random value, signing or login uses that value. Third, **with the variable unset, the program fails closed**: it raises or denies, and never falls back to `""` or a default. The third check directly targets the login-bypass regression seen in `fixer.py`'s first live run.
- **CWE-327 security tests:** the stored value must not equal the weak digest of the password. Two users with the same password must get different stored values. `hashlib.pbkdf2_hmac`/`scrypt` must be used, with ≥ 100k iterations (checked via a `monkeypatch` spy on `hashlib`). Case 13's functional tests include legacy MD5 users, so a fix that drops legacy verification fails the regression oracle.
- **Reference fixes for 798** use `os.environ["NAME"]` read lazily inside a function, never at import time and never with a default.

## Location

`AIEval-main-2/dataset/`, a sibling of `Engine/`. It does not touch the teammates' `Engine/test-cases/` (their 2-file detection manifest) or `src/`.

## Build steps for the remaining 27 cases

**Status: complete.** All 30 cases are built, plus `tools/validate.py`, `tools/build_sheet.py`
and `README.md`. A full `tools/validate.py` run (no `--partial`) passes: 30/30 cases,
34 vulnerabilities, 27 decoys, 0 dataset-level problems.

Follow this procedure for every batch below:

1. Build each case folder: `app.py`, `test_functional.py`, `test_security.py`, `reference_fix.py`, and `conftest.py`, copied unchanged from `case_01_inventory_lookup/`.
2. Add each case's entry to `ground_truth.json`, with exact line numbers taken from `app.py`.
3. Run `.venv/bin/python tools/validate.py --partial <case ids>` and fix anything that fails, until every case in the batch passes.
4. Stop and report the validation table before starting the next batch.

Use cases 01, 17 and 25 as the style reference for tests, fixtures and ground-truth fields, including `related_lines` and the name-agnostic `secret_env`/`empty_env` fixtures for CWE-798.

| Step | Cases | Contents |
|---|---|---|
| 1 | 02, 03, 04, 05, 06 | Remaining CWE-89 singles (02–04) + first two CWE-78 singles (05, 06) |
| 2 | 07, 08, 09, 10, 11 | Last two CWE-78 singles (07, 08) + first three CWE-22 singles (09–11) |
| 3 | 12, 13, 14, 15, 16 | Last CWE-22 single (12) + all CWE-327 singles (13–16) |
| 4 | 18, 19, 20, 21, 22 | Multi cases, including the rest of the CWE-798 ones (18–21) |
| 5 | 23, 24, 26, 27, 28 | Last two multi cases (23, 24) + first three clean cases (26–28) |
| 6 | 29, 30 + wrap-up | Last two clean cases, then `tools/build_sheet.py`, `README.md`, a full `validate.py` run (no `--partial`) until it passes, `build_sheet.py`, and the final summary table |
