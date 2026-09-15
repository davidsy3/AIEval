# AI Evaluator Engine (Backend Test)

A standalone Python backend, separate from the VS Code extension, for testing the vulnerability fixer on its own.

`fixer.py` sends a Python source file to Claude (`claude-sonnet-5`) in a single API call. It asks Claude to find and fix these vulnerability classes:

* CWE-89: SQL injection
* CWE-78: OS command injection
* CWE-22: Path traversal
* CWE-798: Hard-coded credentials
* CWE-327: Broken or weak cryptography

The output has five sections:

* **A. Findings:** each vulnerability found, with its CWE ID and line
* **B. Explanations:** what each one is, why it matters, and how it could be exploited
* **C. Compatibility risk:** Low, Medium, or High chance that the fix changes behavior
* **D. Fixed code:** the full corrected file
* **E. Propose to human:** anything the model chose not to fix automatically

## Prerequisites

* Python 3.10 or newer
* An Anthropic API key from [console.anthropic.com](https://console.anthropic.com/)

## Setup

Run all commands from the `engine/` folder.

1. Create a virtual environment and install dependencies:

   macOS / Linux:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

   Windows (PowerShell):

   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. Add your API key:

   ```bash
   cp .env.example .env
   ```

   Open `.env` and replace the placeholder:

   ```
   ANTHROPIC_API_KEY=sk-ant-...
   ```

   `.env` is git-ignored, so your key is never committed. Only `.env.example` is pushed.

## Running

With the virtual environment activated:

```bash
python fixer.py <path-to-python-file>
```

Example:

```bash
python fixer.py testfile.py
```

A run usually takes 30 seconds to a couple of minutes, depending on file size.

### Output files

**The input file is never modified**, so the same test file can be reused for every run. Each run prints the report and also saves two new files in `engine/output/`:

* `<name>_report_<timestamp>.txt`: the full A–E report
* `<name>_fixed_<timestamp>.py`: the fixed code from section D, ready to diff or run

For example, running `python fixer.py testfile.py` creates:

```
output/testfile_report_20260915-120301.txt
output/testfile_fixed_20260915-120301.py
```

The timestamp means earlier runs are never overwritten, so you can compare results over time. If the model reports `NO CHANGES`, only the report is saved.

To see exactly what the fix changed:

```bash
diff testfile.py output/testfile_fixed_<timestamp>.py
```

## Testing With a Vulnerable File

`testfile.py` (used in the example above) already contains real, unfixed vulnerabilities, so `python fixer.py testfile.py` is the quickest way to see a full report. `../sample/vulnerable_sample.py` has already been mostly fixed, so the model may report few or no findings there. To construct a different test file with every target vulnerability:

```bash
cat > test_vulnerable.py << 'EOF'
import hashlib
import os
import sqlite3
import subprocess

API_KEY = "sk-live-1234567890abcdef"


def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")
    return cursor.fetchone()


def ping(host):
    return subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)


def read_upload(filename):
    with open(os.path.join("/uploads", filename)) as f:
        return f.read()


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
EOF
python fixer.py test_vulnerable.py
```

Expected result: about five findings (SQL injection, command injection, path traversal, hard-coded key, MD5), a compatibility-risk rating, and a fixed version of the file.

To check for false positives, run it on a file with none of these issues. Section A should say `NO TARGET VULNERABILITIES FOUND`.

## Troubleshooting

| Message | Fix |
|---|---|
| `ANTHROPIC_API_KEY is not set` | Create `engine/.env` from `.env.example` and paste your key. |
| `Invalid or missing API key` | The key in `.env` is wrong or revoked. Generate a new one in the console. |
| `ModuleNotFoundError: No module named 'anthropic'` | Activate the virtual environment, then run `pip install -r requirements.txt`. |
| `Output was cut off at max_tokens` | The file is too large for one response. Raise `max_tokens` in `fixer.py` or test a smaller file. |
| `FileNotFoundError` | Check the path. It's relative to where you run the command. |

## Tuning

All the detection and repair logic lives in `SYSTEM_PROMPT` in `fixer.py`. To change the vulnerability list, edit `TARGET_VULNERABILITIES`. To switch models, change the `model=` line: `claude-opus-5` for harder cases, `claude-haiku-4-5` for faster and cheaper runs.

Each run is a paid API call. Sonnet 5 costs $2 per million input tokens and $10 per million output tokens, so a typical small file costs a few cents.
