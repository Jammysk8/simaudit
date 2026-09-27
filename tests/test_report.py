"""Tests for the report generator."""

from __future__ import annotations

import json

import pytest

from simaudit.masvs import Severity
from simaudit.report.generator import generate_html, generate_json
from simaudit.session import AssessmentSession, Finding


@pytest.fixture
def populated_session():
    sess = AssessmentSession(
        app_name="ReportTestApp",
        bundle_id="com.example.reporttest",
        app_version="1.0",
        device_udid="REPORT-TEST-UDID",
    )
    sess.add_finding(
        Finding(
            masvs_id="MASVS-NETWORK-1",
            title="ATS disabled globally",
            detail="NSAllowsArbitraryLoads = True",
            severity=Severity.HIGH,
            evidence_paths=["/some/Info.plist"],
            raw_output="NSAllowsArbitraryLoads: True",
            module="static",
        )
    )
    sess.add_finding(
        Finding(
            masvs_id="MASVS-STORAGE-1",
            title="Auth token in NSUserDefaults",
            detail="Key 'authToken' found",
            severity=Severity.HIGH,
            module="storage",
        )
    )
    sess.add_finding(
        Finding(
            masvs_id="MASVS-CODE-4",
            title="Low minimum OS version",
            detail="MinimumOSVersion = 14.0",
            severity=Severity.LOW,
            module="static",
        )
    )
    sess.mark_module_run("static")
    sess.mark_module_run("storage")
    return sess


def test_generate_html_creates_file(tmp_path, populated_session):
    out = tmp_path / "report.html"
    result = generate_html(populated_session, out)
    assert result == out
    assert out.exists()
    content = out.read_text()
    assert "ReportTestApp" in content
    assert "simaudit" in content.lower()


def test_generate_html_contains_findings(tmp_path, populated_session):
    out = tmp_path / "report.html"
    generate_html(populated_session, out)
    content = out.read_text()
    assert "ATS disabled globally" in content
    assert "MASVS-NETWORK-1" in content
    assert "Auth token in NSUserDefaults" in content
    assert "MASVS-STORAGE-1" in content


def test_generate_html_severity_labels(tmp_path, populated_session):
    out = tmp_path / "report.html"
    generate_html(populated_session, out)
    content = out.read_text()
    assert "HIGH" in content
    assert "LOW" in content


def test_generate_html_simulator_warning(tmp_path, populated_session):
    out = tmp_path / "report.html"
    generate_html(populated_session, out)
    content = out.read_text()
    assert "Simulator-only" in content or "simulator" in content.lower()


def test_generate_html_modules_listed(tmp_path, populated_session):
    out = tmp_path / "report.html"
    generate_html(populated_session, out)
    content = out.read_text()
    assert "static" in content
    assert "storage" in content


def test_generate_json_structure(tmp_path, populated_session):
    out = tmp_path / "report.json"
    result = generate_json(populated_session, out)
    assert result == out
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["session"]["app_name"] == "ReportTestApp"
    assert data["summary"]["total_findings"] == 3
    assert data["summary"]["by_severity"]["HIGH"] == 2
    assert data["summary"]["by_severity"]["LOW"] == 1
    assert len(data["findings"]) == 3


def test_generate_json_findings_sorted_by_severity(tmp_path, populated_session):
    out = tmp_path / "report.json"
    generate_json(populated_session, out)
    data = json.loads(out.read_text())
    severities = [f["severity"] for f in data["findings"]]
    # HIGH should appear before LOW
    assert severities.index("HIGH") < severities.index("LOW")


def test_generate_json_finding_fields(tmp_path, populated_session):
    out = tmp_path / "report.json"
    generate_json(populated_session, out)
    data = json.loads(out.read_text())
    f = data["findings"][0]
    assert "id" in f
    assert "masvs_id" in f
    assert "title" in f
    assert "severity" in f
    assert "discovered_at" in f
    assert "module" in f


def test_generate_empty_session(tmp_path):
    sess = AssessmentSession(app_name="Empty", bundle_id="com.empty")
    html_out = tmp_path / "report.html"
    json_out = tmp_path / "report.json"
    generate_html(sess, html_out)
    generate_json(sess, json_out)
    assert html_out.exists()
    assert json_out.exists()
    data = json.loads(json_out.read_text())
    assert data["summary"]["total_findings"] == 0
