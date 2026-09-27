"""Tests for the deep link module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from simaudit.modules.deeplinks import (
    build_test_urls,
    extract_url_schemes,
)
from simaudit.modules.deeplinks import (
    run as deeplinks_run,
)


def test_extract_url_schemes(sample_app_path):
    schemes = extract_url_schemes(sample_app_path)
    assert len(schemes) == 1
    assert schemes[0].scheme == "sampleapp"
    assert schemes[0].role == "Editor"


def test_extract_url_schemes_missing_plist(tmp_path):
    schemes = extract_url_schemes(tmp_path / "Missing.app")
    assert schemes == []


def test_extract_url_schemes_no_types(tmp_path):
    app = tmp_path / "NoScheme.app"
    app.mkdir()
    plist = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleIdentifier</key><string>com.x</string>
</dict></plist>"""
    (app / "Info.plist").write_bytes(plist)
    schemes = extract_url_schemes(app)
    assert schemes == []


def test_build_test_urls():
    urls = build_test_urls("myapp")
    assert len(urls) > 0
    labels = [label for label, _ in urls]
    assert "base" in labels
    assert "path_traversal" in labels
    # All URLs should start with myapp://
    for _, url in urls:
        assert url.startswith("myapp://")


def test_deeplinks_run_no_device(sample_app_path, fresh_session):
    """Without a device, run should still enumerate schemes and return findings."""
    sess, _ = fresh_session
    # Pass empty udid — should not crash, just skip the firing step
    findings = deeplinks_run(sample_app_path, "", sess)
    assert len(findings) >= 1
    assert any("sampleapp" in (f.raw_output or "") or "sampleapp" in f.title for f in findings)


def test_deeplinks_run_with_mocked_device(sample_app_path, fresh_session):
    """With a mocked device, run should fire URLs and produce a test matrix finding."""
    sess, _ = fresh_session
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stderr = ""

    with patch("simaudit.modules.deeplinks.open_url", return_value=mock_result):
        findings = deeplinks_run(sample_app_path, "FAKE-UDID-1234", sess, delay=0)

    matrix_findings = [f for f in findings if "test matrix" in f.title.lower()]
    assert len(matrix_findings) == 1
    assert "fired" in matrix_findings[0].title


def test_deeplinks_no_schemes_app(tmp_path, fresh_session):
    sess, _ = fresh_session
    app = tmp_path / "NoScheme.app"
    app.mkdir()
    plist = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleIdentifier</key><string>com.noscheme</string>
</dict></plist>"""
    (app / "Info.plist").write_bytes(plist)
    findings = deeplinks_run(app, "", sess)
    assert len(findings) == 1
    assert findings[0].title.startswith("No URL schemes")
