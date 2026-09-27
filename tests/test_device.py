"""Tests for the simctl device wrapper (mocked — no real Simulator required)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from simaudit.device import (
    SimctlError,
    boot_device,
    create_device,
    default_device_type,
    default_ios_runtime,
    find_device,
    get_app_container,
    list_devices,
)

SAMPLE_DEVICES_JSON = {
    "devices": {
        "com.apple.CoreSimulator.SimRuntime.iOS-17-5": [
            {
                "udid": "AAAA-1111-BBBB-2222",
                "name": "simaudit-lab",
                "state": "Booted",
            },
            {
                "udid": "CCCC-3333-DDDD-4444",
                "name": "iPhone 15 Pro",
                "state": "Shutdown",
            },
        ]
    }
}

SAMPLE_RUNTIMES_JSON = {
    "runtimes": [
        {
            "identifier": "com.apple.CoreSimulator.SimRuntime.iOS-17-5",
            "name": "iOS 17.5",
            "version": "17.5",
            "isAvailable": True,
        },
        {
            "identifier": "com.apple.CoreSimulator.SimRuntime.iOS-16-4",
            "name": "iOS 16.4",
            "version": "16.4",
            "isAvailable": True,
        },
    ]
}

SAMPLE_DEVICE_TYPES_JSON = {
    "devicetypes": [
        {"identifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-15", "name": "iPhone 15"},
        {"identifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-16", "name": "iPhone 16"},
    ]
}


def _make_proc(stdout: str = "", returncode: int = 0, stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.stdout = stdout
    m.stderr = stderr
    m.returncode = returncode
    return m


@patch("simaudit.device.subprocess.run")
def test_list_devices(mock_run):
    mock_run.return_value = _make_proc(json.dumps(SAMPLE_DEVICES_JSON))
    devices = list_devices()
    assert len(devices) == 2
    names = [d.name for d in devices]
    assert "simaudit-lab" in names
    assert "iPhone 15 Pro" in names


@patch("simaudit.device.subprocess.run")
def test_find_device_by_name(mock_run):
    mock_run.return_value = _make_proc(json.dumps(SAMPLE_DEVICES_JSON))
    dev = find_device("simaudit-lab")
    assert dev is not None
    assert dev.udid == "AAAA-1111-BBBB-2222"
    assert dev.is_booted


@patch("simaudit.device.subprocess.run")
def test_find_device_by_udid(mock_run):
    mock_run.return_value = _make_proc(json.dumps(SAMPLE_DEVICES_JSON))
    dev = find_device("CCCC-3333-DDDD-4444")
    assert dev is not None
    assert dev.name == "iPhone 15 Pro"
    assert not dev.is_booted


@patch("simaudit.device.subprocess.run")
def test_find_device_not_found(mock_run):
    mock_run.return_value = _make_proc(json.dumps(SAMPLE_DEVICES_JSON))
    dev = find_device("nonexistent")
    assert dev is None


@patch("simaudit.device.subprocess.run")
def test_create_device_returns_udid(mock_run):
    fake_udid = "ABCDEF12-3456-7890-ABCD-EF1234567890"
    mock_run.return_value = _make_proc(f"{fake_udid}\n")
    udid = create_device("test-device", "com.apple.type.iPhone-15", "com.apple.runtime.iOS-17")
    assert udid == fake_udid


@patch("simaudit.device.subprocess.run")
def test_create_device_bad_output(mock_run):
    mock_run.return_value = _make_proc("not-a-uuid")
    with pytest.raises(SimctlError, match="Unexpected output"):
        create_device("test", "type", "runtime")


@patch("simaudit.device.subprocess.run")
def test_boot_device_skips_if_booted(mock_run):
    mock_run.return_value = _make_proc(json.dumps(SAMPLE_DEVICES_JSON))
    boot_device("AAAA-1111-BBBB-2222")
    # Should only have called list (one call), not boot (two calls)
    assert mock_run.call_count == 1


@patch("simaudit.device.subprocess.run")
def test_get_app_container_returns_path(mock_run):
    mock_run.return_value = _make_proc("/path/to/container\n")
    path = get_app_container("UDID", "com.example.app")
    assert path == Path("/path/to/container")


@patch("simaudit.device.subprocess.run")
def test_get_app_container_not_installed(mock_run):
    mock_run.return_value = _make_proc("", returncode=1, stderr="No container found")
    path = get_app_container("UDID", "com.notinstalled")
    assert path is None


@patch("simaudit.device.subprocess.run")
def test_default_ios_runtime(mock_run):
    mock_run.return_value = _make_proc(json.dumps(SAMPLE_RUNTIMES_JSON))
    rt = default_ios_runtime()
    assert rt == "com.apple.CoreSimulator.SimRuntime.iOS-17-5"


@patch("simaudit.device.subprocess.run")
def test_default_device_type_prefers_iphone16(mock_run):
    mock_run.return_value = _make_proc(json.dumps(SAMPLE_DEVICE_TYPES_JSON))
    dt = default_device_type()
    assert dt == "com.apple.CoreSimulator.SimDeviceType.iPhone-16"


@patch("simaudit.device.subprocess.run")
def test_simctl_error_on_xcrun_failure(mock_run):
    import subprocess

    mock_run.side_effect = subprocess.CalledProcessError(1, "xcrun", stderr="error!")
    with pytest.raises(SimctlError):
        list_devices()


def test_simctl_error_on_no_xcrun():
    with patch("simaudit.device.subprocess.run", side_effect=FileNotFoundError):
        with pytest.raises(SimctlError, match="xcrun not found"):
            list_devices()
