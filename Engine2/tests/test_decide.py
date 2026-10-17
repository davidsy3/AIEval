"""Stage 5 tests. Owner: ____

Pure functions over hand-made inputs: no bandit, no pytest-in-pytest, no model.
"""

import pytest

from config import CONFIG, Config
from models import (Annotation, Case, CaseResult, Decision, Explanation, Finding,
                    Fix, SafetyResult, TestRun, TriagedFinding)
from stages.decide import decide, match, score
from fakes import make_case


def finding(cwe="CWE-89", line=20, case_id="case_99_fake", **kw):
    return Finding(case_id=case_id, cwe=cwe, line_start=line,
                   line_end=kw.pop("line_end", line), **kw)


def annotation(cwe="CWE-89", line=20, ann_id="v1", **kw):
    return Annotation(ann_id=ann_id, cwe=cwe, line_start=line,
                      line_end=kw.pop("line_end", line), **kw)


def triaged(findings, verdict="real"):
    return [TriagedFinding(finding=f, verdict=verdict) for f in findings]


# --- the matching rule: same CWE, +/-3 lines, one to one ---------------------

@pytest.mark.parametrize("line,matched", [
    (20, True), (17, True), (23, True),      # exact and both edges of +/-3
    (16, False), (24, False),                # just outside
])
def test_line_tolerance_is_three(line, matched):
    pairs, _, _ = match([finding(line=line)], [annotation(line=20)], CONFIG)
    assert bool(pairs) is matched


def test_tolerance_is_configurable():
    pairs, _, _ = match([finding(line=30)], [annotation(line=20)], Config(line_tolerance=10))
    assert len(pairs) == 1


def test_a_different_cwe_on_the_same_line_does_not_match():
    pairs, spurious, missed = match([finding(cwe="CWE-78")], [annotation(cwe="CWE-89")], CONFIG)
    assert pairs == [] and len(spurious) == 1 and len(missed) == 1


def test_related_lines_also_match():
    ann = annotation(line=20, related_lines=[(40, 42)])
    pairs, _, _ = match([finding(line=41)], [ann], CONFIG)
    assert len(pairs) == 1


def test_matching_is_one_to_one():
    """Two findings on one annotation: one match, one false positive."""
    pairs, spurious, missed = match([finding(line=20), finding(line=21)],
                                    [annotation(line=20)], CONFIG)
    assert len(pairs) == 1 and len(spurious) == 1 and missed == []


def test_one_finding_cannot_cover_two_annotations():
    pairs, spurious, missed = match([finding(line=20)],
                                    [annotation(line=20, ann_id="v1"),
                                     annotation(line=21, ann_id="v2")], CONFIG)
    assert len(pairs) == 1 and spurious == [] and len(missed) == 1


def test_the_closest_annotation_wins():
    pairs, _, _ = match([finding(line=20)],
                        [annotation(line=23, ann_id="far"),
                         annotation(line=20, ann_id="near")], CONFIG)
    assert pairs[0][1].ann_id == "near"


# --- the auto-apply gate -----------------------------------------------------

def green_safety(**kw):
    base = dict(
        case_id="case_99_fake", applied=True, syntax_ok=True,
        functional_baseline=TestRun(ran=True, passed=True, per_test={"t": True}),
        functional_after=TestRun(ran=True, passed=True, per_test={"t": True}),
        vuln_gone=True,
    )
    base.update(kw)
    return SafetyResult(**base)


def test_auto_apply_needs_all_three_conditions(tmp_path):
    case = make_case(tmp_path)
    decision = decide(case, triaged([finding()]),
                      Fix(case_id=case.case_id, fixed_code="x = 1", risk="Low"),
                      green_safety(), CONFIG)
    assert decision.action == "auto_apply"


@pytest.mark.parametrize("risk", ["Medium", "High"])
def test_non_low_risk_goes_to_a_human(tmp_path, risk):
    case = make_case(tmp_path)
    decision = decide(case, triaged([finding()]),
                      Fix(case_id=case.case_id, fixed_code="x = 1", risk=risk),
                      green_safety(), CONFIG)
    assert decision.action == "propose_to_human"
    assert f"risk is {risk}" in decision.reason


def test_a_regression_goes_to_a_human(tmp_path):
    case = make_case(tmp_path)
    decision = decide(case, triaged([finding()]),
                      Fix(case_id=case.case_id, fixed_code="x = 1", risk="Low"),
                      green_safety(regressions=["test_find_existing"]), CONFIG)
    assert decision.action == "propose_to_human" and "regressed" in decision.reason


def test_a_vuln_still_present_goes_to_a_human(tmp_path):
    case = make_case(tmp_path)
    decision = decide(case, triaged([finding()]),
                      Fix(case_id=case.case_id, fixed_code="x = 1", risk="Low"),
                      green_safety(vuln_gone=False), CONFIG)
    assert decision.action == "propose_to_human" and "still reported" in decision.reason


def test_no_fix_possible_goes_to_a_human(tmp_path):
    case = make_case(tmp_path)
    decision = decide(case, triaged([finding()]),
                      Fix(case_id=case.case_id, no_fix_possible=True, risk="High"),
                      green_safety(), CONFIG)
    assert decision.action == "propose_to_human" and "NO FIX POSSIBLE" in decision.reason


def test_nothing_confirmed_means_no_action(tmp_path):
    case = make_case(tmp_path)
    decision = decide(case, triaged([finding()], verdict="false_alarm"), None, None, CONFIG)
    assert decision.action == "no_action"


# --- the three numbers -------------------------------------------------------

def result_for(case, reported_lines, cwe="CWE-89", safety=None, fix=None):
    return CaseResult(
        case_id=case.case_id, category=case.category,
        findings=[finding(cwe=cwe, line=n, case_id=case.case_id) for n in reported_lines],
        triaged=triaged([finding(cwe=cwe, line=n, case_id=case.case_id)
                         for n in reported_lines]),
        fixes=[fix] if fix else [],
        safety=[safety] if safety else [],
        decision=Decision(action="no_action"),
    )


def test_a_perfect_run_scores_zero_and_zero(tmp_path):
    case = make_case(tmp_path)                      # one vuln at line 20
    report = score([result_for(case, [20])], [case], CONFIG)
    assert report["overall"]["false_negative_rate"] == 0.0
    assert report["overall"]["false_positive_rate"] == 0.0


def test_a_missed_vuln_is_a_false_negative(tmp_path):
    case = make_case(tmp_path)
    report = score([result_for(case, [])], [case], CONFIG)
    assert report["overall"]["false_negative_rate"] == 1.0
    assert report["overall"]["false_positive_rate"] is None      # nothing reported
    assert report["per_case"][0]["missed"][0]["cwe"] == "CWE-89"


def test_an_unmatched_finding_is_a_false_positive(tmp_path):
    case = make_case(tmp_path)
    report = score([result_for(case, [20, 15])], [case], CONFIG)   # 15 is the decoy
    assert report["overall"]["false_negative_rate"] == 0.0
    assert report["overall"]["false_positive_rate"] == 0.5


def test_a_finding_on_an_annotated_decoy_is_flagged(tmp_path):
    case = make_case(tmp_path)
    report = score([result_for(case, [15])], [case], CONFIG)
    assert report["overall"]["counts"]["decoy_hits"] == 1
    assert report["per_case"][0]["spurious"][0]["on_decoy"] is True


def test_false_alarms_are_not_counted_as_reported(tmp_path):
    case = make_case(tmp_path)
    result = result_for(case, [20, 15])
    for t in result.triaged:
        if t.finding.line_start == 15:
            t.verdict = "false_alarm"              # stage 2 cleared the decoy
    report = score([result], [case], CONFIG)
    assert report["overall"]["counts"]["reported"] == 1
    assert report["overall"]["false_positive_rate"] == 0.0


def test_regression_rate_counts_judged_fixes(tmp_path):
    case = make_case(tmp_path)
    fix = Fix(case_id=case.case_id, fixed_code="x = 1", risk="Low",
              addressed_cwes=["CWE-89"])
    good = result_for(case, [20], safety=green_safety(), fix=fix)
    bad = result_for(case, [20], fix=fix,
                     safety=green_safety(regressions=["test_find_existing"]))
    report = score([good, bad], [case, case], CONFIG)
    assert report["overall"]["counts"]["fixes_judged"] == 2
    assert report["overall"]["regression_rate"] == 0.5


def test_an_untested_fix_is_not_in_the_regression_denominator(tmp_path):
    case = make_case(tmp_path)
    fix = Fix(case_id=case.case_id, fixed_code=None, risk="High")
    report = score([result_for(case, [20], fix=fix)], [case], CONFIG)
    assert report["overall"]["counts"]["fixes_judged"] == 0
    assert report["overall"]["regression_rate"] is None


def test_per_cwe_split(tmp_path):
    case = make_case(tmp_path)
    case.vulns.append(annotation(cwe="CWE-78", line=40, ann_id="v2"))
    report = score([result_for(case, [20])], [case], CONFIG)     # CWE-78 missed
    assert report["per_cwe"]["CWE-89"]["false_negative_rate"] == 0.0
    assert report["per_cwe"]["CWE-78"]["false_negative_rate"] == 1.0


def test_broken_decoy_tests_count_as_a_regression(tmp_path):
    case = make_case(tmp_path)
    fix = Fix(case_id=case.case_id, fixed_code="x = 1", risk="Low", addressed_cwes=["CWE-89"])
    report = score([result_for(case, [20], fix=fix,
                               safety=green_safety(decoy_breaks=["test_d1_count_is_safe"]))],
                   [case], CONFIG)
    assert report["overall"]["regression_rate"] == 1.0
