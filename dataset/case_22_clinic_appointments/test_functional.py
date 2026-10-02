import pytest


@pytest.fixture
def book(mod, tmp_path):
    attachments = tmp_path / "attachments"
    attachments.mkdir()
    (attachments / "referral.pdf").write_bytes(b"%PDF-1.4 referral")
    b = mod.ClinicBook(":memory:", str(attachments))
    b.book("Ana Silva", "Dr Okonjo", "2026-03-02T09:00", "annual check")
    b.book("Ana Silva", "Dr Reyes", "2026-03-09T11:30")
    b.book("Bo Tran", "Dr Okonjo", "2026-03-02T10:00", "follow-up")
    b.register_staff("dana", "reception-password", "reception")
    return b


def test_book_returns_id(book):
    new_id = book.book("Cleo Marsh", "Dr Reyes", "2026-03-10T08:00")
    assert new_id == 4


def test_appointments_for_patient_sorted(book):
    rows = book.appointments_for("Ana Silva")
    assert [r["slot"] for r in rows] == ["2026-03-02T09:00", "2026-03-09T11:30"]
    assert rows[0]["reason"] == "annual check"


def test_appointments_for_unknown_patient(book):
    assert book.appointments_for("Nobody") == []


def test_clinician_day(book):
    rows = book.clinician_day("Dr Okonjo", "2026-03-02")
    assert [r["patient"] for r in rows] == ["Ana Silva", "Bo Tran"]
    assert book.clinician_day("Dr Okonjo", "2026-03-03") == []


def test_cancel_hides_appointment(book):
    book.cancel(1)
    assert [r["slot"] for r in book.appointments_for("Ana Silva")] == ["2026-03-09T11:30"]
    with pytest.raises(KeyError):
        book.cancel(999)


def test_register_staff_rejects_unknown_role(book):
    with pytest.raises(ValueError):
        book.register_staff("eli", "another-password", "surgeon")


def test_staff_login(book):
    assert book.staff_login("dana", "reception-password") is True
    assert book.staff_login("dana", "wrong-password") is False
    assert book.staff_login("nobody", "reception-password") is False


def test_stored_password_present(book):
    assert book.stored_password("dana")
    assert book.stored_password("nobody") is None


def test_export_attachment(book):
    assert book.export_attachment("referral.pdf") == b"%PDF-1.4 referral"
    with pytest.raises(Exception):
        book.export_attachment("absent.pdf")


def test_persists_to_file_db(mod, tmp_path):
    path = str(tmp_path / "clinic.db")
    first = mod.ClinicBook(path, str(tmp_path))
    first.book("Zoe Vaz", "Dr Reyes", "2026-04-01T09:00")
    assert len(mod.ClinicBook(path, str(tmp_path)).appointments_for("Zoe Vaz")) == 1
