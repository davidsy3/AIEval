"""Stage 2 tests. Owner: ____

Uses FakeLLM only -- no API key, no bandit, no other stage.
"""

from pathlib import Path

import pytest

from config import CONFIG, Config
from llm import OfflineLLM
from models import Finding
from stages.triage import (IMPORT_NOTE, INCOMPLETE_NOTE, SHARED_NOTE,
                          _merge_groups, _reference_block, parse_batch_reply,
                          parse_reply, triage)
from fakes import FakeLLM, make_case


def batched(*blocks: str) -> str:
    """A batched reply: one `FINDING n` block per verdict, in order."""
    return "\n\n".join(f"FINDING {n}\n{block}"
                       for n, block in enumerate(blocks, 1))

REAL = ("VERDICT: VULNERABLE\n"
        "WHAT: the name is f-stringed straight into the SELECT.\n"
        "WHY: an attacker reads the whole table.\n"
        "EXPLOIT: pass x' OR '1'='1 as the name.")

CLEARED = ("VERDICT: NOT VULNERABLE\n"
           "WHAT: only the module constant TABLE is interpolated; name is bound.\n"
           "WHY: n/a\n"
           "EXPLOIT: n/a")


@pytest.fixture
def finding():
    return Finding(case_id="case_99_fake", cwe="CWE-89", line_start=20, line_end=20,
                   rule_id="B608", message="possible SQL injection")


# --- parsing -----------------------------------------------------------------

def test_parses_a_vulnerable_verdict():
    verdict, explanation = parse_reply(REAL)
    assert verdict == "real"
    assert "f-stringed" in explanation.what
    assert explanation.why.startswith("an attacker")
    assert "OR '1'='1" in explanation.how_exploited


def test_parses_the_not_vulnerable_escape_hatch():
    verdict, explanation = parse_reply(CLEARED)
    assert verdict == "false_alarm"
    assert "module constant" in explanation.what


@pytest.mark.parametrize("reply", [
    "", "   ", "I think it's fine", "VERDICT:", "probably VULNERABLE maybe?",
])
def test_unusable_replies_give_no_verdict(reply):
    assert parse_reply(reply)[0] is None


# --- the escape hatch and the fail-safe --------------------------------------

def test_real_verdict_is_reported(tmp_path, finding):
    case = make_case(tmp_path)
    triaged = triage(case, [finding], FakeLLM([REAL]), CONFIG)
    assert [t.verdict for t in triaged] == ["real"]
    assert triaged[0].is_real


def test_false_alarm_is_dropped_from_reported(tmp_path, finding):
    case = make_case(tmp_path)
    triaged = triage(case, [finding], FakeLLM([CLEARED]), CONFIG)
    assert triaged[0].verdict == "false_alarm"
    assert not triaged[0].is_real


def test_unparseable_reply_keeps_the_finding(tmp_path, finding):
    """The contract: no usable verdict must never silently delete a finding."""
    case = make_case(tmp_path)
    triaged = triage(case, [finding], FakeLLM(["who knows"]), CONFIG)
    assert triaged[0].verdict == "real"
    assert "no usable VERDICT" in triaged[0].notes


def test_api_failure_keeps_the_finding(tmp_path, finding):
    case = make_case(tmp_path)
    triaged = triage(case, [finding], FakeLLM([RuntimeError("503 overloaded")]), CONFIG)
    assert triaged[0].verdict == "real"
    assert "triage call failed" in triaged[0].notes


# --- shape and offline -------------------------------------------------------

def test_output_is_one_per_input_in_order(tmp_path):
    case = make_case(tmp_path)
    findings = [Finding(case_id=case.case_id, cwe="CWE-89", line_start=n, line_end=n)
                for n in (15, 20)]
    llm = FakeLLM([batched(CLEARED, REAL)])
    triaged = triage(case, findings, llm, CONFIG)
    assert [t.finding.line_start for t in triaged] == [15, 20]
    assert [t.verdict for t in triaged] == ["false_alarm", "real"]
    assert llm.calls == 1, "a file's findings are judged in one call"


def test_offline_keeps_everything_without_calling_the_model(tmp_path, finding):
    case = make_case(tmp_path)
    llm = OfflineLLM(Config(offline=True))
    triaged = triage(case, [finding], llm, CONFIG)
    assert triaged[0].verdict == "real"
    assert "offline" in triaged[0].notes
    assert llm.calls == 0


def test_the_file_is_sent_as_untrusted_data(tmp_path, finding):
    """The nonce-marked block from v0 must be in the prompt."""
    case = make_case(tmp_path)
    llm = FakeLLM([REAL])
    triage(case, [finding], llm, CONFIG)
    user = llm.last_user_message
    assert "untrusted data" in user and "BEGIN-" in user and "END-" in user
    assert "CWE-89" in user and "20" in user


def test_empty_findings_means_no_calls(tmp_path):
    llm = FakeLLM([REAL])
    assert triage(make_case(tmp_path), [], llm, CONFIG) == []
    assert llm.calls == 0


# --- the structural pre-filter ------------------------------------------------

def _cwe89(case, line):
    return Finding(case_id=case.case_id, cwe="CWE-89", line_start=line, line_end=line)


def test_an_import_line_finding_is_cleared_without_a_call(tmp_path):
    """B404 reports `import subprocess` as CWE-78. An import is not a sink."""
    case = make_case(tmp_path)
    import_line = next(n for n, text in enumerate(case.code.splitlines(), 1)
                       if text.startswith("import "))
    finding = Finding(case_id=case.case_id, cwe="CWE-78",
                      line_start=import_line, line_end=import_line,
                      rule_id="B404", message="Consider possible security implications")
    llm = FakeLLM([REAL])

    triaged = triage(case, [finding], llm, CONFIG)

    assert triaged[0].verdict == "false_alarm"
    assert triaged[0].notes == IMPORT_NOTE
    assert llm.calls == 0, "a structural clear must not cost an API call"


def test_an_import_inside_a_string_is_not_treated_as_an_import(tmp_path):
    """The check is AST-based, so file content cannot fake an import line."""
    code = 'DOC = """\nimport subprocess\n"""\nimport os\n'
    case = make_case(tmp_path, code=code, with_functional=False, with_security=False)
    on_string = Finding(case_id=case.case_id, cwe="CWE-78", line_start=2, line_end=2,
                        rule_id="B404")
    llm = FakeLLM([CLEARED])

    triaged = triage(case, [on_string], llm, CONFIG)

    assert llm.calls == 1, "a line inside a string literal must still be judged"
    assert triaged[0].verdict == "false_alarm"


def test_a_file_that_will_not_parse_falls_through_to_the_model(tmp_path):
    case = make_case(tmp_path, code="import os\ndef broken(:\n",
                     with_functional=False, with_security=False)
    llm = FakeLLM([REAL])
    triaged = triage(case, [_cwe89(case, 1)], llm, CONFIG)
    assert llm.calls == 1
    assert triaged[0].verdict == "real"


# --- batching ----------------------------------------------------------------

def test_many_findings_cost_one_call(tmp_path):
    case = make_case(tmp_path)
    findings = [_cwe89(case, n) for n in (15, 20, 24)]
    llm = FakeLLM([batched(CLEARED, REAL, CLEARED)])

    triaged = triage(case, findings, llm, CONFIG)

    assert llm.calls == 1
    assert [t.verdict for t in triaged] == ["false_alarm", "real", "false_alarm"]


def test_a_missing_block_keeps_only_that_finding(tmp_path):
    """One malformed block must not affect its neighbours."""
    case = make_case(tmp_path)
    findings = [_cwe89(case, n) for n in (15, 20, 24)]
    reply = f"FINDING 1\n{CLEARED}\n\nFINDING 3\n{CLEARED}"

    triaged = triage(case, findings, FakeLLM([reply]), CONFIG)

    assert [t.verdict for t in triaged] == ["false_alarm", "real", "false_alarm"]
    assert "no usable VERDICT" in triaged[1].notes


def test_blocks_out_of_order_land_on_the_right_findings(tmp_path):
    case = make_case(tmp_path)
    findings = [_cwe89(case, n) for n in (15, 20)]
    reply = f"FINDING 2\n{REAL}\n\nFINDING 1\n{CLEARED}"

    triaged = triage(case, findings, FakeLLM([reply]), CONFIG)

    assert [t.verdict for t in triaged] == ["false_alarm", "real"]
    assert triaged[1].explanation.what.startswith("the name is f-stringed")


def test_a_truncated_reply_keeps_the_trailing_findings(tmp_path):
    case = make_case(tmp_path)
    findings = [_cwe89(case, n) for n in (15, 20, 24)]
    reply = f"FINDING 1\n{CLEARED}\n\nFINDING 2\nVERDICT: NOT"   # cut mid-verdict

    triaged = triage(case, findings, FakeLLM([reply]), CONFIG)

    assert [t.verdict for t in triaged] == ["false_alarm", "real", "real"]
    assert all("no usable VERDICT" in t.notes for t in triaged[1:])


def test_order_is_kept_across_prefiltered_and_batched_findings(tmp_path):
    case = make_case(tmp_path)
    import_line = next(n for n, text in enumerate(case.code.splitlines(), 1)
                       if text.startswith("import "))
    findings = [
        _cwe89(case, 15),
        Finding(case_id=case.case_id, cwe="CWE-78", line_start=import_line,
                line_end=import_line, rule_id="B404"),
        _cwe89(case, 20),
    ]
    llm = FakeLLM([batched(CLEARED, REAL)])      # only the two judged ones

    triaged = triage(case, findings, llm, CONFIG)

    assert [t.finding.line_start for t in triaged] == [15, import_line, 20]
    assert [t.verdict for t in triaged] == ["false_alarm", "false_alarm", "real"]
    assert triaged[1].notes == IMPORT_NOTE
    assert triaged[2].explanation.how_exploited.startswith("pass x'")


def test_the_real_flaw_survives_while_the_decoy_is_cleared(tmp_path):
    """The canary: bandit's B608 flags both lines 15 and 20 in the fake case.

    Line 20 is the real CWE-89, line 15 is the safe bound-parameter look-alike --
    the same shape as case_01 (29-30 real vs 35-38 decoy) in the dataset.
    """
    case = make_case(tmp_path)
    findings = [_cwe89(case, 15), _cwe89(case, 20)]

    triaged = triage(case, findings, FakeLLM([batched(CLEARED, REAL)]), CONFIG)

    reported = [t.finding.line_start for t in triaged if t.is_real]
    assert reported == [20], "the decoy must be cleared and the real flaw kept"


# --- batch parsing in isolation ----------------------------------------------

def test_parse_batch_reply_pads_missing_blocks():
    parsed = parse_batch_reply(f"FINDING 1\n{REAL}", count=3)
    assert [verdict for verdict, _ in parsed] == ["real", None, None]


def test_parse_batch_reply_reads_a_headerless_reply_only_for_one_finding():
    assert parse_batch_reply(CLEARED, count=1)[0][0] == "false_alarm"
    assert [v for v, _ in parse_batch_reply(CLEARED, count=2)] == [None, None]


def test_parse_batch_reply_takes_the_first_of_duplicate_numbers():
    reply = f"FINDING 1\n{REAL}\n\nFINDING 1\n{CLEARED}"
    assert parse_batch_reply(reply, count=1)[0][0] == "real"


# --- same-flaw merging --------------------------------------------------------

def _finding(case, cwe, start, end, rule=""):
    return Finding(case_id=case.case_id, cwe=cwe, line_start=start, line_end=end,
                   rule_id=rule)


def test_overlapping_same_cwe_findings_cost_one_judgement(tmp_path):
    """Two detectors on one construct is one flaw, so one judgement."""
    case = make_case(tmp_path)
    findings = [_finding(case, "CWE-89", 24, 25, "B608"),
                _finding(case, "CWE-89", 23, 27, "AST")]
    llm = FakeLLM([batched(REAL)])

    triaged = triage(case, findings, llm, CONFIG)

    assert llm.calls == 1
    assert [t.verdict for t in triaged] == ["real", "real"]
    # the widest span (23-27) speaks; the narrower one records where its verdict came from
    assert triaged[0].notes == SHARED_NOTE.format(line=23)
    assert triaged[1].notes == ""


def test_the_widest_span_is_the_one_sent(tmp_path):
    case = make_case(tmp_path)
    findings = [_finding(case, "CWE-89", 24, 25), _finding(case, "CWE-89", 23, 27)]
    llm = FakeLLM([batched(REAL)])

    triage(case, findings, llm, CONFIG)

    assert "lines: 23-27" in llm.last_user_message
    assert "lines: 24-25" not in llm.last_user_message


def test_non_overlapping_findings_are_judged_separately(tmp_path):
    """The guard: case_01's real CWE-89 (29-30) and its decoy (35-38) must not merge."""
    case = make_case(tmp_path)
    findings = [_finding(case, "CWE-89", 29, 30), _finding(case, "CWE-89", 35, 38)]

    triaged = triage(case, findings, FakeLLM([batched(REAL, CLEARED)]), CONFIG)

    assert [t.verdict for t in triaged] == ["real", "false_alarm"]
    assert all(SHARED_NOTE.split(" with")[0] not in t.notes for t in triaged)


def test_merging_never_crosses_cwes(tmp_path):
    case = make_case(tmp_path)
    findings = [_finding(case, "CWE-89", 20, 20), _finding(case, "CWE-78", 20, 20)]

    triaged = triage(case, findings, FakeLLM([batched(REAL, CLEARED)]), CONFIG)

    assert [t.verdict for t in triaged] == ["real", "false_alarm"]


def test_a_missing_block_keeps_every_member_of_its_group(tmp_path):
    case = make_case(tmp_path)
    findings = [_finding(case, "CWE-89", 24, 25), _finding(case, "CWE-89", 23, 27)]

    triaged = triage(case, findings, FakeLLM(["no blocks here"]), CONFIG)

    assert [t.verdict for t in triaged] == ["real", "real"]
    assert all("no usable VERDICT" in t.notes for t in triaged)


def test_merge_groups_is_stable_and_index_based():
    findings = [Finding(case_id="c", cwe="CWE-89", line_start=10, line_end=12),
                Finding(case_id="c", cwe="CWE-89", line_start=40, line_end=40),
                Finding(case_id="c", cwe="CWE-89", line_start=11, line_end=11)]
    assert _merge_groups(findings) == [[0, 2], [1]]
    assert _merge_groups([]) == []


# --- explanation quality floor -----------------------------------------------

THIN = "VERDICT: VULNERABLE\nWHAT: it is f-stringed.\nWHY:\nEXPLOIT: n/a"


def test_a_kept_finding_with_a_thin_explanation_is_flagged(tmp_path, finding):
    triaged = triage(make_case(tmp_path), [finding], FakeLLM([batched(THIN)]), CONFIG)
    assert triaged[0].verdict == "real", "a thin explanation is not grounds for dropping it"
    assert triaged[0].notes.startswith(INCOMPLETE_NOTE)
    assert "WHY" in triaged[0].notes and "EXPLOIT" in triaged[0].notes


def test_a_cleared_finding_is_not_flagged_for_saying_n_a(tmp_path, finding):
    """`n/a` in WHY/EXPLOIT is exactly what the prompt asks of a cleared finding."""
    triaged = triage(make_case(tmp_path), [finding], FakeLLM([batched(CLEARED)]), CONFIG)
    assert triaged[0].verdict == "false_alarm"
    assert triaged[0].notes == ""


def test_a_complete_explanation_is_not_flagged(tmp_path, finding):
    triaged = triage(make_case(tmp_path), [finding], FakeLLM([batched(REAL)]), CONFIG)
    assert triaged[0].notes == ""


# --- reference material -------------------------------------------------------

def test_the_system_prompt_carries_only_the_cwes_in_play(tmp_path, finding):
    case = make_case(tmp_path)
    llm = FakeLLM([batched(REAL)])

    triage(case, [finding], llm, CONFIG)       # the fixture finding is CWE-89

    system = llm.prompts[-1][0]
    assert "CWE-89 — SQL Injection" in system
    assert "REFERENCE MATERIAL" in system
    assert "CWE-22" not in system, "absent CWEs must not bloat the prompt"


def test_reference_material_is_trusted_and_not_in_the_user_message(tmp_path, finding):
    case = make_case(tmp_path)
    llm = FakeLLM([batched(REAL)])
    triage(case, [finding], llm, CONFIG)
    assert "REFERENCE MATERIAL" not in llm.last_user_message


def test_a_missing_reference_file_degrades_silently(tmp_path, finding, monkeypatch):
    import stages.triage as stage
    monkeypatch.setattr(stage, "REFERENCES_DIR", tmp_path / "nothing-here")
    monkeypatch.setattr(stage, "_REFERENCE_CACHE", {})

    triaged = triage(make_case(tmp_path), [finding], FakeLLM([batched(REAL)]), CONFIG)

    assert triaged[0].verdict == "real", "grounding is an enhancement, never a dependency"


def test_reference_files_are_read_once(monkeypatch):
    import stages.triage as stage
    monkeypatch.setattr(stage, "_REFERENCE_CACHE", {})
    reads: list[str] = []
    real_read = Path.read_text

    def counting_read(self, *args, **kwargs):
        reads.append(self.name)
        return real_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", counting_read)
    for _ in range(3):
        assert "CWE-89" in _reference_block(["CWE-89", "CWE-89"])
    assert reads.count("CWE-89.md") == 1
