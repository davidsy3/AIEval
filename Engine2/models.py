"""
Shared data types: THE CONTRACT BETWEEN STAGES.
==============================================

Job
---
Every value that crosses a stage boundary is defined here and nowhere else.
A stage owner may change the inside of their stage freely; changing a type in
this file changes everyone's code, so it needs a reviewed PR.

Contract
--------
    stage 1 -> 2   Finding
    stage 2 -> 3   TriagedFinding
    stage 3 -> 4   Fix
    stage 4 -> 5   SafetyResult   (holds TestRun x3)
    stage 5        Decision, and CaseResult for the report
    loader -> all  Case, Annotation

Owner: ____ (shared file -- changes need a reviewed PR)

Known gaps
----------
- Everything is a plain dataclass with no validation. A stage that puts a
  wrong-shaped value in a field will only break at the next stage.
- `raw_llm` fields keep the whole model reply so the results JSON is auditable.
  That makes run files large; nobody prunes them yet.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

Risk = Literal["Low", "Medium", "High"]
Verdict = Literal["real", "false_alarm"]
Action = Literal["auto_apply", "propose_to_human", "no_action"]


# --- from the dataset loader -------------------------------------------------

@dataclass
class Annotation:
    """One ground-truth entry: a real vulnerability, or a decoy (a safe look-alike)."""

    ann_id: str
    cwe: str                       # for a decoy this is its `looks_like`
    line_start: int
    line_end: int
    is_decoy: bool = False
    function: str = ""
    description: str = ""
    subtlety: str = ""
    expected_fix_risk: str = ""
    regression_note: str = ""
    security_test: str = ""
    # (start, end) pairs for helper functions that are part of the same flaw
    related_lines: list[tuple[int, int]] = field(default_factory=list)

    def spans(self, tolerance: int = 0) -> list[tuple[int, int]]:
        """Every line range this annotation can be matched against, widened by `tolerance`."""
        raw = [(self.line_start, self.line_end), *self.related_lines]
        return [(max(1, s - tolerance), e + tolerance) for s, e in raw]


@dataclass
class Case:
    """One dataset case folder. `code` is the only thing a detector or the LLM sees."""

    case_id: str
    path: Path
    app_path: Path
    code: str
    category: str = ""             # single | multi | clean
    context: str = ""
    vulns: list[Annotation] = field(default_factory=list)
    decoys: list[Annotation] = field(default_factory=list)
    has_functional_tests: bool = False
    has_security_tests: bool = False


# --- stage 1 -> 2 ------------------------------------------------------------

@dataclass
class Finding:
    """One raw detector hit, after CWE mapping and target filtering."""

    case_id: str
    cwe: str
    line_start: int
    line_end: int
    detector: str = "bandit"       # bandit | ast
    rule_id: str = ""              # e.g. B608
    severity: str = ""             # LOW | MEDIUM | HIGH
    confidence: str = ""
    message: str = ""
    snippet: str = ""

    @property
    def finding_id(self) -> str:
        return f"{self.case_id}:{self.cwe}:{self.line_start}:{self.rule_id or self.detector}"

    def spans(self, tolerance: int = 0) -> tuple[int, int]:
        return (max(1, self.line_start - tolerance), self.line_end + tolerance)


# --- stage 2 -> 3 ------------------------------------------------------------

@dataclass
class Explanation:
    what: str = ""
    why: str = ""
    how_exploited: str = ""


@dataclass
class TriagedFinding:
    """A finding plus the triage verdict. `verdict == "real"` means it is reported."""

    finding: Finding
    verdict: Verdict = "real"
    explanation: Explanation = field(default_factory=Explanation)
    notes: str = ""                # why we defaulted, parse problems, offline marker
    raw_llm: str = ""

    @property
    def is_real(self) -> bool:
        return self.verdict == "real"


# --- stage 3 -> 4 ------------------------------------------------------------

@dataclass
class Fix:
    """One repair attempt over the whole file."""

    case_id: str
    attempt: int = 1
    fixed_code: Optional[str] = None       # None = nothing to apply
    risk: Risk = "High"
    no_fix_possible: bool = False
    addressed_cwes: list[str] = field(default_factory=list)
    notes: str = ""
    raw_llm: str = ""

    @property
    def has_code(self) -> bool:
        return bool(self.fixed_code and self.fixed_code.strip())


# --- stage 4 -> 5 ------------------------------------------------------------

@dataclass
class TestRun:
    """One pytest subprocess. `per_test` is what makes 'passed before, fails after' computable."""

    __test__ = False      # not a test class: stop pytest collecting the name "TestRun"

    ran: bool = False
    passed: bool = False
    returncode: int = -1
    timed_out: bool = False
    per_test: dict[str, bool] = field(default_factory=dict)
    output: str = ""

    @property
    def passing_names(self) -> set[str]:
        return {name for name, ok in self.per_test.items() if ok}


@dataclass
class SafetyResult:
    """Stage 4's verdict. NEVER contains a model's opinion about its own fix."""

    case_id: str
    attempt: int = 1
    applied: bool = False                  # was there any code to test?
    syntax_ok: bool = True
    functional_baseline: TestRun = field(default_factory=TestRun)
    functional_after: TestRun = field(default_factory=TestRun)
    security_after: Optional[TestRun] = None
    rescan_findings: list[Finding] = field(default_factory=list)
    rescan_clear: bool = False             # stage 1 reports fewer of each addressed CWE
    security_verdict: Optional[bool] = None  # every test_v* passes; None = no oracle
    decoy_breaks: list[str] = field(default_factory=list)  # test_d* broken by the fix
    vuln_gone: bool = False                # security_verdict when it exists, else rescan_clear
    regressions: list[str] = field(default_factory=list)   # passed before, fail after
    feedback_for_repair: str = ""

    @property
    def tests_pass(self) -> bool:
        """No regression, the functional suite is green, and no safe code was broken."""
        return (self.functional_after.ran
                and self.functional_after.passed
                and not self.regressions
                and not self.decoy_breaks)

    @property
    def ok(self) -> bool:
        return self.syntax_ok and self.tests_pass and self.vuln_gone


# --- stage 5 -----------------------------------------------------------------

@dataclass
class Decision:
    action: Action = "propose_to_human"
    reason: str = ""
    risk: Risk = "High"
    attempt_used: int = 0


@dataclass
class CaseResult:
    """Everything the pipeline learned about one case, and what the report scores."""

    case_id: str
    category: str = ""
    findings: list[Finding] = field(default_factory=list)
    triaged: list[TriagedFinding] = field(default_factory=list)
    fixes: list[Fix] = field(default_factory=list)
    safety: list[SafetyResult] = field(default_factory=list)
    decision: Decision = field(default_factory=Decision)
    error: str = ""

    @property
    def reported(self) -> list[Finding]:
        """Findings that survived triage. These are what stage 5 scores."""
        return [t.finding for t in self.triaged if t.is_real]

    @property
    def final_safety(self) -> Optional[SafetyResult]:
        return self.safety[-1] if self.safety else None
