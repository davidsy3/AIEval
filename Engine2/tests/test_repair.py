"""Stage 3 tests. Owner: ____

Uses FakeLLM only -- no API key, no bandit, no other stage.
"""

import pytest

from config import CONFIG, Config
from llm import OfflineLLM
from models import Explanation, Finding, TriagedFinding
from stages.decide import decide
from stages.repair import (PatchError, apply_edits, assess_risk, build_user_message,
                           extract_edits, extract_fixed_code, extract_risk,
                           extract_section, repair)
from stages.safety import verify
from fakes import FIXED_APP, VULNERABLE_APP, FakeLLM, make_case


def report(risk="Low", code=FIXED_APP, section_e="NONE"):
    body = f"```python\n{code}```" if code else "NO FIX POSSIBLE"
    return (f"A. FINDINGS\n1. CWE-89 at line 20\n\n"
            f"B. EXPLANATIONS\nThe name is now a bound parameter.\n\n"
            f"C. COMPATIBILITY RISK\n{risk} -- same return shape and exceptions.\n\n"
            f"D. FIXED CODE\n{body}\n\n"
            f"E. PROPOSE TO HUMAN\n{section_e}")


VULN_LINE_TEXT = """    return conn.execute(f"SELECT name FROM items WHERE name = '{name}'").fetchall()\n"""
FIXED_LINE_TEXT = '    return conn.execute("SELECT name FROM items WHERE name = ?", (name,)).fetchall()\n'


def block(search, replace):
    return f"<<<<<<< SEARCH\n{search}=======\n{replace}>>>>>>> REPLACE"


def edit_report(*edits, risk="Low", fence=True):
    body = "\n".join(block(s, r) for s, r in edits)
    if fence:
        body = f"```\n{body}\n```"
    return (f"A. FINDINGS\n1. CWE-89 at line 20\n\n"
            f"B. EXPLANATIONS\nThe name is now a bound parameter.\n\n"
            f"C. COMPATIBILITY RISK\n{risk} -- same return shape and exceptions.\n\n"
            f"D. FIXED CODE\n{body}\n\n"
            f"E. PROPOSE TO HUMAN\nNONE")


GOOD_EDIT = (VULN_LINE_TEXT, FIXED_LINE_TEXT)


@pytest.fixture
def confirmed():
    return [TriagedFinding(
        finding=Finding(case_id="case_99_fake", cwe="CWE-89", line_start=20,
                        line_end=20, rule_id="B608"),
        verdict="real",
        explanation=Explanation(what="f-stringed name", why="table disclosure",
                                how_exploited="x' OR '1'='1"),
    )]


# --- A-E parsing (same format as v0) -----------------------------------------

def test_extracts_the_fixed_code_block():
    assert extract_fixed_code(report()) == FIXED_APP


@pytest.mark.parametrize("risk", ["Low", "Medium", "High"])
def test_extracts_each_risk_level(risk):
    assert extract_risk(report(risk=risk)) == risk


def test_missing_risk_section_defaults_to_high():
    """Fail safe: an unreadable risk must never read as Low."""
    assert extract_risk("A. FINDINGS\nnothing here") == "High"


def test_no_fix_possible_yields_no_code():
    assert extract_fixed_code(report(code=None)) is None


def test_no_changes_yields_no_code():
    assert extract_fixed_code(report().replace(f"```python\n{FIXED_APP}```", "NO CHANGES")) is None


def test_unfenced_code_is_still_accepted():
    raw = report().replace(f"```python\n{FIXED_APP}```", FIXED_APP)
    assert extract_fixed_code(raw).strip().startswith('"""Tiny app')


def test_sections_do_not_bleed_into_each_other():
    assert "COMPATIBILITY" not in extract_section(report(), "B. EXPLANATIONS",
                                                  "C. COMPATIBILITY RISK")


# --- the stage ---------------------------------------------------------------

def test_repair_returns_a_fix(tmp_path, confirmed):
    case = make_case(tmp_path)
    fix = repair(case, confirmed, FakeLLM([report()]), CONFIG)
    assert fix.has_code and fix.risk == "Low"
    assert fix.addressed_cwes == ["CWE-89"]
    assert fix.no_fix_possible is False
    assert fix.attempt == 1


def test_no_fix_possible_escape_hatch(tmp_path, confirmed):
    case = make_case(tmp_path)
    fix = repair(case, confirmed, FakeLLM([report(code=None)]), CONFIG)
    assert fix.no_fix_possible is True and not fix.has_code


def test_api_failure_is_not_a_fix(tmp_path, confirmed):
    case = make_case(tmp_path)
    fix = repair(case, confirmed, FakeLLM([RuntimeError("timeout")]), CONFIG)
    assert not fix.has_code and fix.risk == "High" and "failed" in fix.notes


def test_feedback_from_a_failed_attempt_reaches_the_prompt(tmp_path, confirmed):
    case = make_case(tmp_path)
    llm = FakeLLM([report()])
    repair(case, confirmed, llm, CONFIG,
           feedback="test_find_missing passed before and fails now", attempt=2)
    user = llm.last_user_message
    assert "ATTEMPT 2" in user
    assert "test_find_missing passed before and fails now" in user


def test_the_confirmed_findings_and_their_explanations_reach_the_prompt(tmp_path, confirmed):
    case = make_case(tmp_path)
    llm = FakeLLM([report()])
    repair(case, confirmed, llm, CONFIG)
    user = llm.last_user_message
    assert "CWE-89" in user and "f-stringed name" in user
    assert "untrusted data" in user and "BEGIN-" in user


def test_nothing_confirmed_means_no_call(tmp_path):
    llm = FakeLLM([report()])
    fix = repair(make_case(tmp_path), [], llm, CONFIG)
    assert not fix.has_code and llm.calls == 0


def test_offline_returns_the_code_unchanged_at_high_risk(tmp_path, confirmed):
    case = make_case(tmp_path)
    llm = OfflineLLM(Config(offline=True))
    fix = repair(case, confirmed, llm, CONFIG)
    assert fix.fixed_code == case.code
    assert fix.risk == "High"          # so stage 5 can never auto-apply it
    assert llm.calls == 0


# --- patch-level edits: parsing ----------------------------------------------

@pytest.mark.parametrize("fence", [True, False])
def test_extracts_edit_blocks_fenced_or_not(fence):
    edits = extract_edits(edit_report(GOOD_EDIT, ("a\n", "b\n"), fence=fence))
    assert edits == [GOOD_EDIT, ("a\n", "b\n")]


def test_a_whole_file_reply_has_no_edit_blocks():
    assert extract_edits(report()) == []


def test_edit_blocks_are_never_mistaken_for_a_whole_file():
    """A fenced edit list must not be applied as if it were the fixed file."""
    assert extract_fixed_code(edit_report(GOOD_EDIT)) is None


# --- patch-level edits: applying ---------------------------------------------

def test_apply_replaces_exactly_the_quoted_lines():
    assert apply_edits(VULNERABLE_APP, [GOOD_EDIT]) == FIXED_APP


def test_apply_leaves_every_other_line_byte_for_byte():
    fixed = apply_edits(VULNERABLE_APP, [GOOD_EDIT])
    old, new = VULNERABLE_APP.splitlines(), fixed.splitlines()
    assert len(old) == len(new)
    assert [i for i, (a, b) in enumerate(zip(old, new)) if a != b] == [19]   # line 20


def test_apply_tolerates_trailing_whitespace_in_search():
    search = VULN_LINE_TEXT.replace("\n", "   \n")
    assert apply_edits(VULNERABLE_APP, [(search, FIXED_LINE_TEXT)]) == FIXED_APP


def test_apply_does_not_double_blank_context():
    """Blank lines quoted on both sides of a block must not be duplicated."""
    search = "\n" + VULN_LINE_TEXT + "\n"
    replace = "\n" + FIXED_LINE_TEXT + "\n"
    assert apply_edits(VULNERABLE_APP, [(search, replace)]) == FIXED_APP


def test_apply_inserts_after_an_anchor_and_deletes_lines():
    code = "import sqlite3\n\nX = 1\nY = 2\n"
    fixed = apply_edits(code, [("import sqlite3\n", "import os\nimport sqlite3\n"),
                               ("Y = 2\n", "")])
    assert fixed == "import os\nimport sqlite3\n\nX = 1\n"


def test_apply_never_matches_half_a_line():
    with pytest.raises(PatchError, match="do not appear"):
        apply_edits("value = 10\n", [("value = 1", "value = 2\n")])


def test_apply_rejects_search_text_that_is_not_in_the_file():
    with pytest.raises(PatchError, match="edit 1: .*do not appear"):
        apply_edits(VULNERABLE_APP, [("    return totally_made_up()\n", "x\n")])


def test_apply_rejects_ambiguous_search_text():
    code = "def a():\n    pass\n\n\ndef b():\n    pass\n"
    with pytest.raises(PatchError, match="match 2 places"):
        apply_edits(code, [("    pass\n", "    return 1\n")])


def test_apply_rejects_an_empty_search():
    with pytest.raises(PatchError, match="empty"):
        apply_edits(VULNERABLE_APP, [("\n", "import os\n")])


def test_apply_reports_which_edit_failed():
    with pytest.raises(PatchError, match="edit 2"):
        apply_edits(VULNERABLE_APP, [GOOD_EDIT, ("nope\n", "x\n")])


# --- the risk floor ----------------------------------------------------------

def test_minimal_fix_has_a_low_floor(confirmed):
    assert assess_risk(VULNERABLE_APP, FIXED_APP, confirmed) == ("Low", [])


def test_unparseable_fix_is_high(confirmed):
    floor, reasons = assess_risk(VULNERABLE_APP, FIXED_APP + "\ndef oops(:\n", confirmed)
    assert floor == "High" and "does not parse" in reasons[0]


def test_a_fix_that_changes_nothing_is_high(confirmed):
    assert assess_risk(VULNERABLE_APP, VULNERABLE_APP, confirmed)[0] == "High"


def test_removing_a_public_function_is_high(confirmed):
    fixed = FIXED_APP.replace("def find(", "def find_rows(")
    floor, reasons = assess_risk(VULNERABLE_APP, fixed, confirmed)
    assert floor == "High" and any("removed `find`" in r for r in reasons)


def test_a_breaking_public_signature_change_is_high(confirmed):
    fixed = FIXED_APP.replace("def find(conn, name):", "def find(conn, name, limit):")
    assert assess_risk(VULNERABLE_APP, fixed, confirmed)[0] == "High"


def test_a_compatible_public_signature_change_is_medium(confirmed):
    fixed = FIXED_APP.replace("def find(conn, name):", "def find(conn, name, limit=None):")
    floor, reasons = assess_risk(VULNERABLE_APP, fixed, confirmed)
    assert floor == "Medium" and "old calls still work" in reasons[0]


def test_a_private_helper_may_change_shape():
    code = ("def _q(name):\n    return f\"... '{name}'\"\n\n\n"
            "def find(conn, name):\n    return conn.execute(_q(name))\n")
    fixed = ("def _q():\n    return '... ?'\n\n\n"
             "def find(conn, name):\n    return conn.execute(_q(), (name,))\n")
    flagged = [TriagedFinding(finding=Finding(case_id="c", cwe="CWE-89",
                                              line_start=2, line_end=2))]
    assert assess_risk(code, fixed, flagged) == ("Low", [])     # caller is one hop away


def test_removing_a_hard_coded_secret_constant_is_medium():
    code = 'TOKEN = "s3cr3t"\n\n\ndef sign(x):\n    return x + TOKEN\n'
    fixed = ('import os\n\n\ndef sign(x):\n'
             '    return x + os.environ["TOKEN"]\n')
    flagged = [TriagedFinding(finding=Finding(case_id="c", cwe="CWE-798",
                                              line_start=1, line_end=1))]
    floor, reasons = assess_risk(code, fixed, flagged)
    assert floor == "Medium"
    assert reasons == ["removed module-level name `TOKEN`"]    # `sign` reads it: in scope


def test_a_new_third_party_import_is_high(confirmed):
    fixed = "import requests\n" + FIXED_APP
    floor, reasons = assess_risk(VULNERABLE_APP, fixed, confirmed)
    assert floor == "High" and "requests" in reasons[0]


def test_a_new_stdlib_import_is_fine(confirmed):
    fixed = FIXED_APP.replace("import sqlite3\n", "import os\nimport sqlite3\n")
    assert assess_risk(VULNERABLE_APP, fixed, confirmed) == ("Low", [])


def test_editing_unrelated_code_is_medium(confirmed):
    """`count` is the decoy: safe, unflagged, and shares no names with `find`."""
    fixed = FIXED_APP.replace('sql = f"SELECT COUNT(*) FROM {TABLE} WHERE name = ?"',
                              'sql = "SELECT COUNT(*) FROM items WHERE name = ?"')
    floor, reasons = assess_risk(VULNERABLE_APP, fixed, confirmed)
    assert floor == "Medium" and "`count`" in reasons[0]


def test_adding_a_helper_between_functions_is_in_scope(confirmed):
    fixed = FIXED_APP.replace("\n\ndef find(", "\n\ndef _helper():\n    return 1\n\n\ndef find(")
    assert assess_risk(VULNERABLE_APP, fixed, confirmed) == ("Low", [])


# --- the stage, with patch-level edits ---------------------------------------

def test_repair_applies_edit_blocks(tmp_path, confirmed):
    case = make_case(tmp_path)
    llm = FakeLLM([edit_report(GOOD_EDIT)])
    fix = repair(case, confirmed, llm, CONFIG)
    assert fix.fixed_code == FIXED_APP
    assert fix.risk == "Low" and not fix.no_fix_possible
    assert llm.calls == 1 and "1 edit(s) applied" in fix.notes


def test_the_prompt_asks_for_edit_blocks(tmp_path, confirmed):
    llm = FakeLLM([edit_report(GOOD_EDIT)])
    repair(make_case(tmp_path), confirmed, llm, CONFIG)
    system = llm.prompts[0][0]
    assert "<<<<<<< SEARCH" in system and ">>>>>>> REPLACE" in system
    assert "NO FIX POSSIBLE" in system                  # the escape hatch survives


def test_edits_that_do_not_apply_are_reasked_once_with_the_error(tmp_path, confirmed):
    case = make_case(tmp_path)
    llm = FakeLLM([edit_report(("    return made_up()\n", "x\n")), edit_report(GOOD_EDIT)])
    fix = repair(case, confirmed, llm, CONFIG, feedback="test_count failed", attempt=2)
    assert llm.calls == 2
    retry = llm.prompts[1][1]
    assert "COULD NOT BE APPLIED" in retry and "made_up()" in retry
    assert "test_count failed" in retry                 # stage 4 feedback still there
    assert fix.fixed_code == FIXED_APP and fix.attempt == 2
    assert "re-asked" in fix.raw_llm                    # both replies kept for audit


def test_edits_that_never_apply_give_no_code_at_high_risk(tmp_path, confirmed):
    llm = FakeLLM([edit_report(("    return made_up()\n", "x\n"))])
    fix = repair(make_case(tmp_path), confirmed, llm, CONFIG)
    assert llm.calls == 2                               # one re-ask, then give up
    assert not fix.has_code and fix.risk == "High"
    assert "did not apply" in fix.notes


def test_an_api_failure_on_the_reask_is_not_a_fix(tmp_path, confirmed):
    llm = FakeLLM([edit_report(("nope\n", "x\n")), RuntimeError("timeout")])
    fix = repair(make_case(tmp_path), confirmed, llm, CONFIG)
    assert not fix.has_code and fix.risk == "High" and "call failed" in fix.notes


def test_the_floor_raises_the_models_risk(tmp_path, confirmed):
    unrelated = ('    sql = f"SELECT COUNT(*) FROM {TABLE} WHERE name = ?"\n',
                 '    sql = "SELECT COUNT(*) FROM items WHERE name = ?"\n')
    llm = FakeLLM([edit_report(GOOD_EDIT, unrelated, risk="Low")])
    fix = repair(make_case(tmp_path), confirmed, llm, CONFIG)
    assert fix.has_code and fix.risk == "Medium"
    assert "risk floor Medium (model said Low)" in fix.notes


def test_the_floor_never_lowers_the_models_risk(tmp_path, confirmed):
    fix = repair(make_case(tmp_path), confirmed, FakeLLM([edit_report(GOOD_EDIT, risk="High")]),
                 CONFIG)
    assert fix.risk == "High"


def test_a_whole_file_reply_is_still_accepted(tmp_path, confirmed):
    fix = repair(make_case(tmp_path), confirmed, FakeLLM([report()]), CONFIG)
    assert fix.fixed_code == FIXED_APP and "whole-file" in fix.notes


def test_a_truncated_reply_is_reported(tmp_path, confirmed):
    cut = report().split("E. PROPOSE")[0].rsplit("```", 1)[0][:-40]
    fix = repair(make_case(tmp_path), confirmed, FakeLLM([cut]), CONFIG)
    assert not fix.has_code and "truncated" in fix.notes


def test_an_edit_fix_passes_the_safety_net_and_auto_applies(tmp_path, confirmed):
    """Stage 3 -> 4 -> 5 on the hand-made case, with no API key."""
    case = make_case(tmp_path)
    fix = repair(case, confirmed, FakeLLM([edit_report(GOOD_EDIT)]), CONFIG)
    safety = verify(case, fix, CONFIG)
    assert safety.ok and safety.security_verdict is True and not safety.decoy_breaks
    assert decide(case, confirmed, fix, safety, CONFIG).action == "auto_apply"
