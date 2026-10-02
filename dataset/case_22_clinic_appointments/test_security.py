import hashlib

import pytest

PASSWORD = "reception-password-5512"
SECRET = b"CONSULTANT-NOTES-PRIVATE"


@pytest.fixture
def book(mod, tmp_path):
    attachments = tmp_path / "attachments"
    attachments.mkdir()
    (attachments / "referral.pdf").write_bytes(b"%PDF-1.4 referral")
    (tmp_path / "secret.pdf").write_bytes(SECRET)
    b = mod.ClinicBook(":memory:", str(attachments))
    b.book("Ana Silva", "Dr Okonjo", "2026-03-02T09:00", "annual check")
    b.book("Bo Tran", "Dr Reyes", "2026-03-02T10:00", "follow-up")
    return b


@pytest.fixture
def kdf_calls(mod, monkeypatch):
    """Record every password-stretching call, whichever name the module uses."""
    calls = []
    real_pbkdf2 = hashlib.pbkdf2_hmac
    real_scrypt = getattr(hashlib, "scrypt", None)

    def spy_pbkdf2(hash_name, password, salt, iterations, dklen=None):
        calls.append({"kdf": "pbkdf2", "hash": hash_name, "iterations": iterations})
        return real_pbkdf2(hash_name, password, salt, iterations, dklen)

    def spy_scrypt(password, **kwargs):
        calls.append({"kdf": "scrypt", "n": kwargs.get("n", 0)})
        return real_scrypt(password, **kwargs)

    for target in (hashlib, mod):
        if hasattr(target, "pbkdf2_hmac"):
            monkeypatch.setattr(target, "pbkdf2_hmac", spy_pbkdf2, raising=False)
        if real_scrypt is not None and hasattr(target, "scrypt"):
            monkeypatch.setattr(target, "scrypt", spy_scrypt, raising=False)
    return calls


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_v1_sqli_appointments_for(book):
    assert not _run(book.appointments_for, "Nobody' OR '1'='1")
    union = "Nobody' UNION SELECT id, patient, slot, reason FROM appointments --"
    assert not _run(book.appointments_for, union)
    assert len(book.appointments_for("Ana Silva")) == 1


def test_v2_weak_staff_password_hash(book, kdf_calls):
    book.register_staff("dana", PASSWORD, "reception")
    stored = book.stored_password("dana")
    assert stored is not None

    book.register_staff("eli", PASSWORD, "nurse")
    assert book.stored_password("eli") != stored

    assert kdf_calls, "staff registration should stretch the password"
    for call in kdf_calls:
        if call["kdf"] == "pbkdf2":
            assert call["iterations"] >= 100_000
            assert call["hash"] not in ("md5", "sha1")

    assert book.staff_login("dana", PASSWORD) is True
    assert book.staff_login("dana", PASSWORD.upper()) is False


def test_d1_export_attachment_rejects_traversal(book, tmp_path):
    for name in ("../secret.pdf", str(tmp_path / "secret.pdf")):
        assert SECRET not in (_run(book.export_attachment, name) or b"")
    assert book.export_attachment("referral.pdf") == b"%PDF-1.4 referral"
