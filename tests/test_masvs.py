"""Tests for MASVS control definitions."""

from simaudit.masvs import CONTROLS, MasvsCategory, Severity, control


def test_all_controls_have_required_fields():
    for control_id, (title, category, default_severity) in CONTROLS.items():
        assert control_id.startswith("MASVS-"), f"Bad control ID: {control_id}"
        assert isinstance(title, str) and title
        assert isinstance(category, MasvsCategory)
        assert isinstance(default_severity, Severity)


def test_control_lookup_known():
    info = control("MASVS-STORAGE-1")
    assert info["id"] == "MASVS-STORAGE-1"
    assert "storage" in info["category"].lower()
    assert info["default_severity"] in [s.value for s in Severity]


def test_control_lookup_unknown():
    info = control("MASVS-UNKNOWN-99")
    assert info["id"] == "MASVS-UNKNOWN-99"
    assert info["title"] == "Unknown control"


def test_severity_ordering():
    severities = [s.value for s in Severity]
    assert "CRITICAL" in severities
    assert "HIGH" in severities
    assert "INFO" in severities


def test_all_masvs_categories_present():
    categories_in_controls = {v[1] for v in CONTROLS.values()}
    expected = {
        MasvsCategory.STORAGE,
        MasvsCategory.CRYPTO,
        MasvsCategory.CODE,
        MasvsCategory.PLATFORM,
        MasvsCategory.NETWORK,
        MasvsCategory.AUTH,
    }
    assert expected.issubset(categories_in_controls)
