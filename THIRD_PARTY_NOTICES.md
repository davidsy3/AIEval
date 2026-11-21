# Third-party components, data boundary and ethics

AI Evaluator (NerdGoose) — inventory audited 2026-11-20 against branch `david-detect-gif`
(commit `46feedd`), covering all 222 tracked files plus the installed `node_modules/` and
`Engine/.venv/`.

**Status key.** **Verified**: checked against the named source on the audit date.
**Local**: read from the package's own metadata or licence file in this repository.
**OPEN**: not cleared. The team must resolve it before release.

> **Release blockers (2).**
> 1. `media/nerdGoose.gif` has no recorded source or licence (see §4).
> 2. `Engine/.env` holds a live API key. It is git-ignored but sits in the working tree, so it
>    must be excluded from any archive built from this folder (see §8).

---

## 1. Shipped with the VS Code extension (npm)

All four are `devDependencies`. They are needed to compile the extension, and none is bundled
into `out/*.js`. Versions come from `package-lock.json`.

| Component | Version | Source | Licence | Status |
|---|---|---|---|---|
| TypeScript | 5.9.3 | registry.npmjs.org/typescript | Apache-2.0 | Local (`node_modules/typescript/LICENSE.txt`; its `ThirdPartyNoticeText.txt` must stay with it if redistributed) |
| @types/node | 20.19.43 | registry.npmjs.org/@types/node (DefinitelyTyped) | MIT | Local |
| @types/vscode | 1.146.0 | registry.npmjs.org/@types/vscode (DefinitelyTyped) | MIT | Local |
| undici-types | 6.21.0 | registry.npmjs.org/undici-types (transitive, via @types/node) | MIT | Local |

Runtime prerequisites, **not redistributed**:

| Component | Licence | Status |
|---|---|---|
| Visual Studio Code (extension host, `vscode` API, ≥ 1.85) | Microsoft product licence. The source repo (microsoft/vscode) is MIT. | Verified: code.visualstudio.com/license |
| Node.js (`path`, `fs`, `child_process`, `crypto` built-ins) | MIT-style licence | Verified: github.com/nodejs/node/blob/main/LICENSE |

Original code: `src/diff.ts` is a textbook longest-common-subsequence line diff written in
the repo. Nothing in it is copied from a library.

## 2. Python dependencies

### Engine (v0) — `Engine/requirements.txt` (unpinned: `anthropic`, `python-dotenv`)

Installed versions are from `Engine/.venv`. Licences come from each package's `METADATA`
(**Local**).

| Package | Installed | Licence | Role |
|---|---|---|---|
| anthropic | 2.9.0 | Apache-2.0 | Anthropic API client |
| python-dotenv | 1.2.4 | BSD-3-Clause | loads `Engine/.env` |
| annotated-types | 0.8.0 | MIT | transitive |
| anyio | 4.16.0 | MIT | transitive |
| docstring_parser | 0.18.0 | MIT | transitive |
| h11 | 0.16.0 | MIT | transitive |
| httpcore2 | 2.16.2 | BSD-3-Clause | transitive |
| httpx2 | 2.16.2 | BSD-3-Clause | transitive |
| idna | 3.20 | BSD-3-Clause | transitive |
| jiter | 0.19.0 | MIT | transitive |
| opentelemetry-api | 1.45.2 | Apache-2.0 | transitive |
| pydantic | 2.14.3 | MIT | transitive |
| pydantic_core | 2.50.4 | MIT | transitive |
| sniffio | 1.3.1 | MIT OR Apache-2.0 | transitive |
| truststore | 0.10.5 | MIT | transitive |
| typing_extensions | 4.16.0 | PSF-2.0 | transitive |
| typing-inspection | 0.4.5 | MIT | transitive |
| pip | 25.3 | MIT | venv tooling only |

### Engine2 — `Engine2/requirements.txt` (no venv is present in the repo, so licences were checked on PyPI)

| Package | Constraint | Licence | Status |
|---|---|---|---|
| anthropic | ≥ 0.40 | Apache-2.0 at 2.9.0 (older releases were published under MIT; check the version you lock) | Local (2.9.0) |
| bandit | ≥ 1.7.5 | Apache-2.0 | Verified: pypi.org/pypi/bandit/json (latest 1.9.4) |
| pytest | ≥ 8 | MIT | Verified: pypi.org/pypi/pytest/json |

### Dataset tooling — `dataset/requirements-dev.txt`

| Package | Constraint | Licence | Status |
|---|---|---|---|
| pytest | ≥ 8 | MIT | Verified (above) |
| openpyxl | ≥ 3.1 | MIT | Verified: pypi.org/pypi/openpyxl/json (latest 3.1.5) |

Everything else imported anywhere in the repo is the Python standard library (PSF License
Version 2; verified at docs.python.org/3/license.html). The dataset's own README states it is
stdlib-only, and `tools/validate.py` enforces that.

**Imported but never installed or run.** `Engine/testfile.py` imports `flask` and `requests`.
The file is a scan target: the engine reads it and never executes it. Neither package is a
dependency.

## 3. Sandbox image — `Engine2/sandbox/Dockerfile`

| Component | Source | Licence | Status |
|---|---|---|---|
| `python:3.12-slim` base image | Docker Hub Official Image | Python is PSF-2.0. The image also contains Debian packages under their own licences. Docker Hub states that "it is the image user's responsibility" to comply with all of them. | Verified: hub.docker.com/_/python |
| pytest 8.3.5 (pinned) | PyPI | MIT | Verified: pypi.org/pypi/pytest/8.3.5/json. On the audit date PyPI listed a vulnerability advisory against pytest ≤ 9.0.2, so consider bumping the pin. |
| Docker Engine / Docker Desktop | docker.com | Not redistributed. Docker Desktop has its own subscription terms, which were not reviewed. | Prerequisite only |

The image is built locally and is not published. Building it does not redistribute it.

## 4. Media assets

| File | Provenance | Licence / rights | Status |
|---|---|---|---|
| `media/logoSide.png` (1254×1254) | **AI-generated.** The file carries a C2PA content-credential manifest. It names `ChatGPT` / `gpt-image` as the generator, with `digitalSourceType = trainedAlgorithmicMedia` (IPTC), a signature by OpenAI OpCo, LLC, and the date 2026-10-05. It was committed by Pedro Re on 2026-10-05 (`14f3d07`). | Under OpenAI's Terms of Use (effective 1 Jan 2026), the user owns the Output "to the extent permitted by applicable law", and the terms forbid representing Output as human-generated. Copyright protection for purely AI-generated images may be limited, so the logo may not be exclusively protectable. | Verified (embedded manifest, openai.com/policies/terms-of-use). **Cleared, with disclosure.** Keep the C2PA metadata and do not describe the logo as hand-drawn. |
| `media/nerdGoose.gif` (383×480, animated, 144 KB) | **Unknown.** The file has no comment block, XMP, C2PA data or download-origin attribute. It was committed by David Sypioe on 2026-11-17 (`41b4306`). It is a hand-drawn-style walking-goose sticker. | **Unknown.** If it came from a GIF or sticker site (GIPHY, Tenor and similar), those sites' terms generally do not grant a licence to bundle the file in a distributed product. | **OPEN, release blocker.** Record its source and licence here, or replace it with an original or AI-generated asset. |

## 5. Models and external services

| Component | Where | Terms | Status |
|---|---|---|---|
| Claude Sonnet 5 (`claude-sonnet-5`) via the Anthropic Messages API | `Engine/fixer.py`, `Engine2/config.py` (`DEFAULT_MODEL`, overridable with `AIEVAL_MODEL`) | Anthropic commercial terms and usage policy apply to API use. No model weights ship. Model outputs are stored in `Engine2/baseline/live_*.json`. | Verified: the model ID is current and the price ($2 / $10 per MTok input/output, as quoted in `Engine/README.md`) matches Anthropic's model table. |
| `claude-opus-5`, `claude-haiku-4-5` | Suggested alternatives in `Engine/README.md` | as above | Verified: both are valid model IDs. |
| OpenAI ChatGPT image generation | Used once, to make the logo (§4) | OpenAI Terms of Use | Verified (§4) |

API behaviour claimed in `Engine2/config.py` and `Engine2/llm.py` was checked against
Anthropic's current API reference:
- Sampling parameters (`temperature` and others) are removed on Claude Sonnet 5 (a 400 if
  sent). **Verified.**
- `output_config={"effort": ...}` is the supported way to set reasoning depth, and `high` is
  the default for Claude Sonnet 5. **Verified.**
- The `llm.py` error text says API keys start with `sk-ant-api03-`. **Not verified.** It is
  harmless as guidance, but it is not sourced.

## 6. Standards and reference material

| Item | Where used | Licence | Status |
|---|---|---|---|
| MITRE CWE identifiers and names | `config.py`, `Engine2/references/CWE-*.md`, prompts, dataset annotations | CWE Terms of Use: free for any use, but copies of CWE content must reproduce MITRE's copyright designation and the licence. "CWE is a trademark of The MITRE Corporation." | Verified: cwe.mitre.org/about/termsofuse.html |

The project uses CWE **IDs and names only**. The five `Engine2/references/CWE-*.md` files are
original text adapted from `Engine/local_analyzer.py` (their README says so). They do not copy
MITRE descriptions, so the reproduction clause is not triggered. A one-line acknowledgement is
still good practice: "CWE™ is a trademark of The MITRE Corporation."

Every CWE ID and name in the code was checked against cwe.mitre.org and is correct:

| ID | Official name (MITRE) | Role in project |
|---|---|---|
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | target |
| CWE-23 | Relative Path Traversal | alias → 22 |
| CWE-36 | Absolute Path Traversal | alias → 22 |
| CWE-77 | Improper Neutralization of Special Elements used in a Command ('Command Injection') | alias → 78 |
| CWE-78 | Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | target |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') | target |
| CWE-259 | Use of Hard-coded Password | alias → 798 |
| CWE-321 | Use of Hard-coded Cryptographic Key | alias → 798 |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | target |
| CWE-328 | Use of Weak Hash | alias → 327 |
| CWE-798 | Use of Hard-coded Credentials | target |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort | alias → 327 |

## 7. Citation check: every external claim in the code and docs

Each claim that points at an outside source was looked up at that source.

| # | Claim (location) | Finding | Verdict |
|---|---|---|---|
| C1 | "100k is the published floor (OWASP ASVS for PBKDF2-HMAC-SHA256)" (`Engine2/stages/detect.py:511-512`) | ASVS **4.0.3** V2.4.3 says PBKDF2 iterations "SHOULD be as large as verification server performance will allow, typically at least 100,000". It is not specific to SHA-256. The current OWASP Password Storage Cheat Sheet recommends **600,000** for PBKDF2-HMAC-SHA256. | **Partly correct. Fix the comment** to: "OWASP ASVS 4.0.3 V2.4.3: 'typically at least 100,000'; the OWASP Password Storage Cheat Sheet now recommends 600,000 for PBKDF2-HMAC-SHA256." |
| C2 | "These 5 are the CWEs LLMs are documented to repair *well*" (`Engine/fixer.py:51`) | No source is cited anywhere in the repo. | **Unsupported. Add a real citation or reword it** (for example, "chosen because their fixes are well-defined and testable"). |
| C3 | Bandit B404 reports `import subprocess` as CWE-78 (`detect.py`, `triage.py`, `Engine2/README.md`) | The Bandit source assigns `issue.Cwe.OS_COMMAND_INJECTION` to B404. | Verified (github.com/PyCQA/bandit, `bandit/blacklists/imports.py`) |
| C4 | "B608 flags parameterized queries too" (`Engine2/README.md`) | B608 flags any SQL-like string *built* with `%`, `+`, `.format()`, f-strings or `.replace()`. A parameterized query that still builds its string (for example, an f-stringed table name) is flagged. A constant parameterized query is not. | **Overstated. Reword** to "flags string-built queries even when the values are bound". |
| C5 | B105/B106 match a wordlist of assignment-target names (`detect.py`) | The Bandit regex is `(pas+wo?r?d\|pass(phrase)?\|pwd\|token\|secrete?)`, matched against names. It reports CWE-259. | Verified (`bandit/plugins/general_hardcoded_password.py`) |
| C6 | "B324 flags md5/sha1 by call name only" (`detect.py`) | B324 also checks the `hashlib.new("md5")` argument and honours `usedforsecurity=False`. It does not inspect `hmac.new(..., "md5")`, so the code's conclusion still holds. | **Imprecise. Reword** to "by hashlib call name or `hashlib.new` argument; `hmac.new` digests are not checked". |
| C7 | Credential prefixes are "formats that are documented" (`detect.py:526-546`) | Vendor docs confirm AWS `AKIA` and `ASIA`; GitHub `ghp_ gho_ ghu_ ghs_ ghr_` and `github_pat_`; GitLab `glpat-`; Stripe `sk_live/test_` and `rk_live/test_`; Slack `xoxb-` and `xoxp-`. **AWS's prefix table does not list `A3T`.** Slack's current docs do not list `xoxa-`, `xoxr-` or `xoxs-`. `whsec_`, `sk-ant-`, `sk-proj-`, `AIza` and `SG.` were not checked against vendor docs. | **Mostly correct.** Either drop `A3T` or relabel it "community secret-scanner pattern, not AWS-documented", and do the same for the unchecked entries. |
| C8 | `AKIAIOSFODNN7EXAMPLE` and `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` (`Engine/testfile.py`) | These are AWS's published placeholder example credentials, not real keys. | Fine. Optionally note their origin in the docstring. |
| C9 | Model IDs and pricing (`Engine/README.md`, `config.py`) | See §5. | Verified |
| C10 | `Engine/README.md` points to `benchmark/run_benchmark.py`, `benchmark/manifest.json`, `benchmark/test_cases/` and `../sample/vulnerable_sample.py` | **None of these exist.** The real files are `Engine/benchmark.py` and `Engine/test-cases/manifest.json`. No `sample/` folder exists. | **Broken internal references. Fix the README.** |
| C11 | Root `README.md` lists "Vulnerable dependencies" as supported | Nothing in either engine scans dependencies. `detect.py` already says this. The README also omits CWE-327, which is implemented. | **Inaccurate. Fix the README.** |

## 8. Data boundary

**What the project works on.**
- **Dataset** (`dataset/`, 30 cases, by rembertoS, first committed 2026-10-01): synthetic
  programs written by the team. They are stdlib-only, 40–150 lines each, and contain planted
  flaws. No third-party benchmark (Juliet/SARD, SecurityEval, CyberSecEval and similar),
  scraped code, real user data or personal data was used. The dataset contains no licence or
  source marker for outside material, and its README says nothing in it touches the network.
- **Engine test cases** (`Engine/test-cases/`, `Engine/testfile.py`): hand-written fixtures.
  Every credential in them is fake or an AWS-documented placeholder.
- **Oracle separation**: the fixer only ever sees `app.py`. `reference_fix.py`, the tests and
  `ground_truth.json` are the answer key. `Engine2/references/README.md` forbids encoding
  oracle specifics in the prompt material.

**What leaves the machine.**
- With `ANTHROPIC_API_KEY` set, the **full source of the analyzed file** is sent to Anthropic's
  API. This covers the VS Code extension on the user's active file, `Engine/fixer.py`, and
  Engine2 stages 2–3. Without a key, both engines run fully offline (AST checks, Bandit).
- Nothing else is transmitted. The extension shells out to the local Python engine.

**Execution boundary.**
- Stage 4 runs candidate fixes in Docker with no network, read-only case files and
  memory/CPU/PID caps. `--allow-unisolated` removes that isolation and runs as the user.

**Package hygiene (exclude from the shipped archive).**
- `Engine/.env` (a live API key, git-ignored but present on disk), `Engine/output/`,
  `Engine/.venv/`, `node_modules/`, `__pycache__/` and `.pytest_cache/`.
- The tracked `.DS_Store` files (5) leak local directory names. Remove them from git.
- `Engine2/baseline/*.json` embeds a teammate's local path
  (`/Users/<username>/Downloads/...`). Redact it if the baselines ship.

## 9. Ethics considerations

1. **User code goes to a third party.** In API mode, proprietary code is sent to Anthropic.
   Users should be told this before the first run, and local mode should remain available.
2. **Over-reliance on automated fixes.** LLM repairs can be wrong or can change behaviour.
   Mitigations already in place: fixes are never applied without an explicit **Apply** click,
   there is a compatibility-risk rating, success is judged by tests rather than by asking the
   model, and there is a "propose to human" escape hatch.
3. **Dual-use content.** The dataset contains deliberately vulnerable code and exploit tests.
   The exploits are benign: they create a marker file under `tmp_path`, never touch the network,
   and work only against the planted cases.
4. **Running untrusted code.** Stage 4 executes model-written code, so the Docker sandbox is a
   safety control, not a convenience. `--allow-unisolated` should stay opt-in and clearly
   warned about.
5. **Prompt injection.** The analyzed files are treated as untrusted input, using nonce fencing
   and explicit injection rules in both engines.
6. **Measurement validity.** The engine was tuned on the same 30 files it is scored on
   (`detect.py` says so). Report the results as development-set numbers, not as
   generalisation. Live results vary from run to run (sampling cannot be fixed on Claude
   Sonnet 5).
7. **AI-generated assets and AI assistance.** The logo is AI-generated, and OpenAI's terms
   forbid presenting it as human-made. If AI assistants were used to write code or
   documentation (this audit was prepared with Claude Code), say so in the submission.
8. **Unverified third-party asset.** Shipping `nerdGoose.gif` without known rights would
   infringe on someone else's work (§4).

## 10. Project licence

The repository has no `LICENSE` file and `package.json` has no `license` field. Choose a
licence before distribution. Every dependency above is permissive (MIT, BSD-3-Clause,
Apache-2.0 or PSF-2.0), so any common licence is compatible. If you redistribute
TypeScript's or any Apache-2.0 package's files, include their licence and NOTICE files.
