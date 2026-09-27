"""Tests for the static analysis module."""

from __future__ import annotations

from simaudit.masvs import Severity
from simaudit.modules.static import (
    find_binary,
    scan_binary_flags,
    scan_info_plist,
    scan_strings_for_secrets,
)


def test_scan_info_plist_detects_ats(sample_app_path, fresh_session):
    sess, _ = fresh_session
    findings = scan_info_plist(sample_app_path, sess)
    masvs_ids = [f.masvs_id for f in findings]
    # Fixture has NSAllowsArbitraryLoads = True
    assert "MASVS-NETWORK-1" in masvs_ids
    assert any("ATS" in t or "arbitrary" in t.lower() for t in [f.title for f in findings])


def test_scan_info_plist_detects_url_scheme(sample_app_path, fresh_session):
    sess, _ = fresh_session
    findings = scan_info_plist(sample_app_path, sess)
    scheme_findings = [f for f in findings if "sampleapp" in (f.raw_output or "")]
    assert len(scheme_findings) >= 1


def test_scan_info_plist_detects_low_min_os(sample_app_path, fresh_session):
    sess, _ = fresh_session
    findings = scan_info_plist(sample_app_path, sess)
    # Fixture has MinimumOSVersion = 14.0 which is < 15
    low_os = [f for f in findings if "minimum" in f.title.lower() or "MinimumOS" in f.detail]
    assert len(low_os) >= 1


def test_scan_info_plist_missing_plist(tmp_path, fresh_session):
    sess, _ = fresh_session
    findings = scan_info_plist(tmp_path / "NonExistent.app", sess)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO


def test_find_binary(sample_app_path):
    binary = find_binary(sample_app_path)
    assert binary is not None
    assert binary.name == "SampleApp"


def test_scan_binary_flags_no_crash(sample_app_path, fresh_session):
    """Binary flag scan should not raise on a non-Mach-O file."""
    sess, _ = fresh_session
    # The fixture binary is just a text file; scan should return findings gracefully
    findings = scan_binary_flags(sample_app_path, sess)
    assert isinstance(findings, list)


def test_scan_strings_for_secrets_no_crash(sample_app_path, fresh_session):
    sess, _ = fresh_session
    findings = scan_strings_for_secrets(sample_app_path, sess)
    assert isinstance(findings, list)


def test_scan_info_plist_all_ok(tmp_path, fresh_session):
    """Plist with no issues should return only INFO findings."""
    sess, _ = fresh_session
    app = tmp_path / "Clean.app"
    app.mkdir()
    plist_content = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>Clean</string>
    <key>CFBundleIdentifier</key><string>com.example.clean</string>
    <key>MinimumOSVersion</key><string>17.0</string>
</dict>
</plist>"""
    (app / "Info.plist").write_bytes(plist_content)
    findings = scan_info_plist(app, sess)
    non_info = [f for f in findings if f.severity != Severity.INFO]
    assert len(non_info) == 0
