"""
Shared configuration for the AI Evaluator pipeline.
=================================================

Job
---
One place for every knob the five stages share, so no stage hard-codes a
constant another stage also needs. Import `CONFIG` for the defaults, or build a
variant with `dataclasses.replace(CONFIG, offline=True)`.

Contract
--------
    CONFIG: Config                     # the frozen defaults
    Config.resolved_cwe(raw) -> str|None   # alias map + target filter

Owner: ____ (shared file -- changes need a reviewed PR)

Known gaps
----------
- The alias map is hand-written. Any detector that reports a CWE outside
  TARGET_CWES or CWE_ALIASES is silently dropped by stage 1; add new aliases
  here rather than in a stage.
- There is no per-case override. Every case runs with the same timeout and
  retry limit, so one pathological case can eat `test_timeout` three times.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# The five classes this project targets. Everything else a detector reports is
# dropped by stage 1 -- scope control, not a judgement about other CWEs.
TARGET_CWES: tuple[str, ...] = (
    "CWE-89",   # SQL injection
    "CWE-78",   # OS command injection
    "CWE-22",   # Path traversal
    "CWE-798",  # Hard-coded credentials
    "CWE-327",  # Broken / weak cryptography
)

# Detectors use neighbouring CWE ids for the same underlying flaw. Normalise
# them onto our five so scoring against ground truth lines up.
CWE_ALIASES: dict[str, str] = {
    "CWE-259": "CWE-798",   # hard-coded password  -> hard-coded credentials
    "CWE-321": "CWE-798",   # hard-coded crypto key -> hard-coded credentials
    "CWE-798": "CWE-798",
    "CWE-328": "CWE-327",   # weak hash            -> broken crypto
    "CWE-327": "CWE-327",
    "CWE-916": "CWE-327",   # insufficient password hash effort -> broken crypto
    "CWE-89": "CWE-89",
    "CWE-78": "CWE-78",
    "CWE-77": "CWE-78",     # command injection    -> OS command injection
    "CWE-22": "CWE-22",
    "CWE-23": "CWE-22",     # relative path traversal -> path traversal
    "CWE-36": "CWE-22",     # absolute path traversal -> path traversal
}

DEFAULT_MODEL = "claude-sonnet-5"


@dataclass(frozen=True)
class Config:
    """Every shared knob. Frozen: build variants with dataclasses.replace()."""

    target_cwes: tuple[str, ...] = TARGET_CWES
    cwe_aliases: dict[str, str] = field(default_factory=lambda: dict(CWE_ALIASES))

    # --- LLM (stages 2 and 3) -------------------------------------------------
    model: str = os.environ.get("AIEVAL_MODEL", DEFAULT_MODEL)
    max_tokens: int = 16000
    offline: bool = False          # no API key, or --offline

    # Reasoning depth, and our stand-in for the determinism we wanted.
    # There is NO `temperature` on current Claude models: the sampling
    # parameters were removed from the API, and passing one is an error. So
    # "temperature 0" is not available to us. `effort` is the knob that exists;
    # it trades token spend for thoroughness. "high" is the default for this
    # model family. Raise to "xhigh"/"max" for the subtle cases, drop to "low"
    # to make a cheap pass over many cases.
    effort: str = os.environ.get("AIEVAL_EFFORT", "high")

    # --- stage 1 --------------------------------------------------------------
    bandit_timeout: int = 60
    use_ast_supplement: bool = False   # --ast: adds the v0 AST checks

    # --- stage 3 / 4 loop -----------------------------------------------------
    max_repair_attempts: int = 3
    test_timeout: int = 120            # seconds per pytest subprocess

    # --- stage 4 --------------------------------------------------------------
    # The dataset names its security tests `test_vN_...` (must FAIL on app.py and
    # pass after a real fix) and `test_dN_...` (decoys: already pass, and fail if
    # the fixer rewrote safe code). See dataset/README.md.
    vuln_test_prefix: str = "test_v"
    decoy_test_prefix: str = "test_d"

    # --- stage 5 --------------------------------------------------------------
    line_tolerance: int = 3            # a finding matches an annotation within +/- this

    def resolved_cwe(self, raw: str | None) -> str | None:
        """Normalise a detector's CWE id, or None if it is not one of ours."""
        if not raw:
            return None
        raw = raw.strip().upper()
        if not raw.startswith("CWE-"):
            raw = f"CWE-{raw}"
        mapped = self.cwe_aliases.get(raw, raw)
        return mapped if mapped in self.target_cwes else None


CONFIG = Config()
