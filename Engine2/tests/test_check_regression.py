"""check_regression.py tests: hand-made results JSON, no pipeline run needed."""

from check_regression import check, latest_results


def case(case_id, verdict=True, regressions=(), baseline_ran=True, attempts=1):
    safety = {"security_verdict": verdict, "regressions": list(regressions),
              "functional_baseline": {"ran": baseline_ran}}
    earlier = {"security_verdict": False, "regressions": ["test_old"],
               "functional_baseline": {"ran": True}}
    return {"case_id": case_id, "safety": [earlier] * (attempts - 1) + [safety]}


def results(*cases):
    return {"run": {"offline": False}, "cases": list(cases)}


def test_no_regressions_passes():
    result = check(results(case("a"), case("b")))
    assert result["rate"] == 0 and result["verdict"] == "PASS"


def test_exactly_ten_percent_passes():
    cases = [case(f"c{i}") for i in range(9)] + [case("bad", regressions=["test_x"])]
    result = check(results(*cases))
    assert result["rate"] == 0.10 and result["verdict"] == "PASS"
    assert result["regressed"] == ["bad"]


def test_over_ten_percent_fails():
    result = check(results(case("a"), case("bad", regressions=["test_x"])))
    assert result["rate"] == 0.5 and result["verdict"] == "FAIL"


def test_only_oracle_confirmed_repairs_count():
    # verdict False (still exploitable) and None (no oracle, re-scan only) are not successful
    result = check(results(case("ok"), case("no", verdict=False, regressions=["t"]),
                           case("rescan", verdict=None, regressions=["t"])))
    assert result["successful"] == ["ok"] and result["verdict"] == "PASS"


def test_no_successful_repairs_is_n_a():
    result = check(results(case("a", verdict=False), {"case_id": "b", "safety": []}))
    assert result["rate"] is None and result["verdict"] == "N/A"


def test_cases_without_a_functional_baseline_are_excluded():
    result = check(results(case("a", baseline_ran=False), case("b")))
    assert result["excluded"] == ["a"] and result["counted"] == 1


def test_only_the_final_attempt_is_judged():
    # attempt 1 regressed, attempt 3 is clean: the case did not regress
    result = check(results(case("a", attempts=3)))
    assert result["regressed"] == [] and result["verdict"] == "PASS"


def test_latest_results_picks_the_newest_run(tmp_path):
    for name in ("run_20261027-163156.json", "run_20261029-133631.json",
                 "run_20261028-090000.json", "notes.json"):
        (tmp_path / name).write_text("{}", encoding="utf-8")
    assert latest_results(tmp_path).name == "run_20261029-133631.json"
    assert latest_results(tmp_path / "missing") is None
