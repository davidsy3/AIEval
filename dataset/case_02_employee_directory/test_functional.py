import pytest


@pytest.fixture
def directory(mod):
    d = mod.EmployeeDirectory(":memory:")
    d.hire("E-001", "Ada Reyes", "Engineering", 3)
    d.hire("E-002", "Bo Tran", "Engineering", 1)
    d.hire("S-010", "Cleo Marsh", "Support", 2)
    return d


def test_by_department_sorted_by_name(directory):
    rows = directory.by_department("Engineering")
    assert [r["name"] for r in rows] == ["Ada Reyes", "Bo Tran"]
    assert rows[0]["title"] == "Lead"


def test_by_department_unknown_is_empty(directory):
    assert directory.by_department("Legal") == []


def test_headcount(directory):
    assert directory.headcount("Engineering") == 2
    assert directory.headcount("Legal") == 0


def test_promote_updates_band_and_title(directory):
    assert directory.promote("E-002") == "Senior"
    assert directory.by_department("Engineering")[1]["band"] == 2
    with pytest.raises(KeyError):
        directory.promote("E-999")


def test_promote_past_top_band_rejected(directory):
    directory.hire("E-003", "Dee Okoro", "Engineering", 4)
    with pytest.raises(ValueError):
        directory.promote("E-003")


def test_transfer_moves_employee(directory):
    directory.transfer("E-002", "Support")
    assert directory.headcount("Engineering") == 1
    assert [r["name"] for r in directory.by_department("Support")] == ["Bo Tran", "Cleo Marsh"]
    with pytest.raises(KeyError):
        directory.transfer("E-999", "Support")


def test_departments_counts(directory):
    assert directory.departments() == {"Engineering": 2, "Support": 1}


def test_persists_to_file_db(mod, tmp_path):
    path = str(tmp_path / "staff.db")
    first = mod.EmployeeDirectory(path)
    first.hire("E-100", "Eli Vance", "Research", 2)
    first.close()
    assert mod.EmployeeDirectory(path).headcount("Research") == 1
