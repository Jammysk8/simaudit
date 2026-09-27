"""Tests for the storage analysis module."""

from __future__ import annotations

from simaudit.masvs import Severity
from simaudit.modules.storage import (
    scan_documents,
    scan_nsuserdefaults,
    scan_sqlite_databases,
)


def test_nsuserdefaults_detects_token(sample_container, fresh_session):
    sess, _ = fresh_session
    findings = scan_nsuserdefaults(sample_container, "com.example.sampleapp", sess)
    assert len(findings) >= 1
    sensitive = [f for f in findings if f.severity != Severity.INFO]
    assert len(sensitive) >= 1
    assert any("authToken" in (f.raw_output or "") for f in sensitive)


def test_nsuserdefaults_no_plist(tmp_path, fresh_session):
    sess, _ = fresh_session
    findings = scan_nsuserdefaults(tmp_path, "com.nonexistent.app", sess)
    assert findings == []


def test_sqlite_detects_password_column(sample_container, fresh_session):
    sess, _ = fresh_session
    findings = scan_sqlite_databases(sample_container, sess)
    assert len(findings) >= 1
    sensitive = [f for f in findings if f.severity != Severity.INFO]
    assert len(sensitive) >= 1
    assert any(
        "password" in (f.raw_output or "").lower() or "userdata" in f.title.lower()
        for f in sensitive
    )


def test_sqlite_no_dbs(tmp_path, fresh_session):
    sess, _ = fresh_session
    findings = scan_sqlite_databases(tmp_path, sess)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "No SQLite" in findings[0].title


def test_sqlite_encrypted_db(tmp_path, fresh_session):
    """A database we can't open should be reported as INFO, not raise."""
    sess, _ = fresh_session
    db_path = tmp_path / "encrypted.sqlite"
    db_path.write_bytes(b"SQLite format 3\x00" + b"\xff" * 100)
    findings = scan_sqlite_databases(tmp_path, sess)
    assert any(f.severity == Severity.INFO for f in findings)


def test_documents_sensitive_filenames(tmp_path, fresh_session):
    sess, _ = fresh_session
    docs = tmp_path / "Documents"
    docs.mkdir()
    (docs / "private_key.pem").write_text("not a real key")
    (docs / "normal_file.txt").write_text("nothing to see")
    findings = scan_documents(tmp_path, sess)
    sensitive = [f for f in findings if f.severity != Severity.INFO]
    assert len(sensitive) >= 1
    assert "private_key.pem" in (sensitive[0].raw_output or "")


def test_documents_no_sensitive_files(tmp_path, fresh_session):
    sess, _ = fresh_session
    docs = tmp_path / "Documents"
    docs.mkdir()
    (docs / "readme.txt").write_text("hello")
    findings = scan_documents(tmp_path, sess)
    assert all(f.severity == Severity.INFO for f in findings)


def test_documents_empty(tmp_path, fresh_session):
    sess, _ = fresh_session
    findings = scan_documents(tmp_path, sess)
    assert findings == []
