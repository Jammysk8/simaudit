"""simctl wrapper — all Simulator device lifecycle operations go through this module."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class SimctlError(RuntimeError):
    pass


@dataclass
class SimDevice:
    udid: str
    name: str
    state: str  # "Booted", "Shutdown", etc.
    runtime: str

    @property
    def is_booted(self) -> bool:
        return self.state == "Booted"


def _run(args: list[str], capture: bool = True, check: bool = True) -> subprocess.CompletedProcess:
    """Run xcrun simctl with the given arguments."""
    cmd = ["xcrun", "simctl"] + args
    try:
        return subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            check=check,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else ""
        raise SimctlError(f"simctl {' '.join(args[:2])} failed: {stderr}") from exc
    except FileNotFoundError:
        raise SimctlError(
            "xcrun not found — Xcode Command Line Tools must be installed.\n"
            "Run: xcode-select --install"
        )


def list_devices() -> list[SimDevice]:
    """Return all known Simulator devices."""
    result = _run(["list", "devices", "--json"])
    data = json.loads(result.stdout)
    devices: list[SimDevice] = []
    for runtime_key, device_list in data.get("devices", {}).items():
        for d in device_list:
            devices.append(
                SimDevice(
                    udid=d["udid"],
                    name=d["name"],
                    state=d["state"],
                    runtime=runtime_key,
                )
            )
    return devices


def find_device(name_or_udid: str) -> Optional[SimDevice]:
    """Find a device by name or UDID. Returns None if not found."""
    for dev in list_devices():
        if dev.udid == name_or_udid or dev.name == name_or_udid:
            return dev
    return None


def list_runtimes() -> list[dict]:
    """Return available runtimes as a list of dicts."""
    result = _run(["list", "runtimes", "--json"])
    data = json.loads(result.stdout)
    return data.get("runtimes", [])


def list_device_types() -> list[dict]:
    """Return available device types."""
    result = _run(["list", "devicetypes", "--json"])
    data = json.loads(result.stdout)
    return data.get("devicetypes", [])


def create_device(name: str, device_type: str, runtime: str) -> str:
    """Create a new Simulator device and return its UDID."""
    result = _run(["create", name, device_type, runtime])
    udid = result.stdout.strip()
    if not re.match(r"^[0-9A-F-]{36}$", udid, re.IGNORECASE):
        raise SimctlError(f"Unexpected output from simctl create: {udid!r}")
    return udid


def boot_device(udid: str) -> None:
    """Boot a Simulator device (no-op if already booted)."""
    dev = find_device(udid)
    if dev and dev.is_booted:
        return
    _run(["boot", udid])


def shutdown_device(udid: str) -> None:
    """Shut down a Simulator device."""
    _run(["shutdown", udid], check=False)


def erase_device(udid: str) -> None:
    """Erase all content and settings on a device (must be shut down first)."""
    shutdown_device(udid)
    _run(["erase", udid])


def install_app(udid: str, app_path: Path) -> None:
    """Install a .app bundle onto the booted device."""
    if not app_path.exists():
        raise SimctlError(f"App path does not exist: {app_path}")
    _run(["install", udid, str(app_path)])


def uninstall_app(udid: str, bundle_id: str) -> None:
    """Uninstall an app by bundle ID."""
    _run(["uninstall", udid, bundle_id])


def get_app_container(udid: str, bundle_id: str, container: str = "data") -> Optional[Path]:
    """
    Return the path to an app's container directory on the host filesystem.
    container: 'app', 'data', or 'groups'
    Returns None if the app is not installed.
    """
    result = _run(["get_app_container", udid, bundle_id, container], check=False)
    if result.returncode != 0:
        return None
    path = result.stdout.strip()
    return Path(path) if path else None


def open_url(udid: str, url: str) -> subprocess.CompletedProcess:
    """Open a URL on the booted device. Used for deep-link testing."""
    return _run(["openurl", udid, url], check=False)


def take_screenshot(udid: str, output_path: Path) -> None:
    """Capture a screenshot of the booted device to a file."""
    _run(["io", udid, "screenshot", str(output_path)])


def get_booted_udid() -> Optional[str]:
    """Return the UDID of the first booted device, or None."""
    for dev in list_devices():
        if dev.is_booted:
            return dev.udid
    return None


def default_ios_runtime() -> Optional[str]:
    """Return the identifier of the latest available iOS runtime."""
    runtimes = [r for r in list_runtimes() if r.get("isAvailable") and "iOS" in r.get("name", "")]
    if not runtimes:
        return None
    return sorted(runtimes, key=lambda r: r.get("version", "0"))[-1]["identifier"]


def default_device_type() -> Optional[str]:
    """Return the identifier of a recent iPhone device type."""
    types = list_device_types()
    preferred = ["iPhone 16", "iPhone 15", "iPhone 14"]
    for name in preferred:
        for dt in types:
            if dt.get("name") == name:
                return dt["identifier"]
    iphones = [dt for dt in types if "iPhone" in dt.get("name", "")]
    return iphones[-1]["identifier"] if iphones else None
