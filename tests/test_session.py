"""Tests for the session model."""

from __future__ import annotations

import pytest

from simaudit.masvs import Severity
from simaudit.session import AssessmentSession, Finding


def test_session_create_and_save(tmp_path):
    sess = AssessmentSession(
        app_name="TestApp",
        bundle_id="com.example.test",
        app_version="2.0",
    )
    path = tmp_path / "session.json"
    saved = sess.save(path)
    assert saved.exists()
    assert saved == path


def test_session_roundtrip(tmp_path):
    sess = AssessmentSession(
        app_name="TestApp",
        bundle_id="com.example.test",
        app_version="2.0",
    )
    f = Finding(
        masvs_id="MASVS-STORAGE-1",
        title="Test finding",
        detail="Some detail",
        severity=Severity.HIGH,
        module="static",
    )
    sess.add_finding(f)
    path = tmp_path / "session.json"
    sess.save(path)

    loaded = AssessmentSession.load(path)
    assert loaded.app_name == "TestApp"
    assert loaded.bundle_id == "com.example.test"
    assert len(loaded.findings) == 1
    assert loaded.findings[0].masvs_id == "MASVS-STORAGE-1"
    assert loaded.findings[0].severity == Severity.HIGH


def test_session_findings_by_severity(fresh_session):
    sess, _ = fresh_session
    sess.add_finding(Finding(masvs_id="MASVS-CODE-4", title="A", detail="", severity=Severity.HIGH))
    sess.add_finding(Finding(masvs_id="MASVS-CODE-4", title="B", detail="", severity=Severity.HIGH))
    sess.add_finding(Finding(masvs_id="MASVS-CODE-4", title="C", detail="", severity=Severity.LOW))

    by_sev = sess.findings_by_severity()
    assert len(by_sev["HIGH"]) == 2
    assert len(by_sev["LOW"]) == 1
    assert len(by_sev["CRITICAL"]) == 0


def test_session_mark_module_run(fresh_session):
    sess, _ = fresh_session
    sess.mark_module_run("static")
    sess.mark_module_run("storage")
    sess.mark_module_run("static")  # duplicate — should not double-add
    assert sess.modules_run == ["static", "storage"]


def test_session_notes(fresh_session):
    sess, _ = fresh_session
    sess.add_note("test note")
    assert len(sess.notes) == 1
    assert "test note" in sess.notes[0]


def test_session_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        AssessmentSession.load(tmp_path / "nonexistent.json")


def test_session_exists(tmp_path):
    path = tmp_path / "session.json"
    assert not AssessmentSession.exists(path)
    sess = AssessmentSession(app_name="X", bundle_id="com.x")
    sess.save(path)
    assert AssessmentSession.exists(path)


def test_finding_to_dict():
    f = Finding(
        masvs_id="MASVS-NETWORK-1",
        title="TLS misconfiguration",
        detail="NSAllowsArbitraryLoads is true",
        severity=Severity.HIGH,
        evidence_paths=["/some/path"],
        module="static",
    )
    d = f.to_dict()
    assert d["masvs_id"] == "MASVS-NETWORK-1"
    assert d["severity"] == "HIGH"
    assert "/some/path" in d["evidence_paths"]
    assert isinstance(d["discovered_at"], str)
