"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_app_path() -> Path:
    return FIXTURES / "SampleApp.app"


@pytest.fixture
def sample_container() -> Path:
    return FIXTURES / "AppContainer"


@pytest.fixture
def fresh_session(tmp_path):
    """Return a fresh AssessmentSession backed by a temp directory."""
    from simaudit.session import AssessmentSession

    sess = AssessmentSession(
        app_name="SampleApp",
        bundle_id="com.example.sampleapp",
        app_version="1.0",
        device_udid="TEST-DEVICE-UDID",
    )
    sess_path = tmp_path / "session.json"
    sess.save(sess_path)
    return sess, sess_path
