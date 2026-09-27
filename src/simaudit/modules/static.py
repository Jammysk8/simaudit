"""Static analysis module — Info.plist, entitlements, binary flags, secrets patterns."""

from __future__ import annotations

import plistlib
import re
import subprocess
from pathlib import Path
from typing import Optional

from ..masvs import Severity
from ..session import AssessmentSession, Finding

MODULE_NAME = "static"

# Regex patterns for common API key / secret shapes
SECRET_PATTERNS: list[tuple[str, str, Severity]] = [
    (
        r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*[A-Za-z0-9+/]{16,}",
        "AWS credential pattern",
        Severity.CRITICAL,
    ),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API key (AIza...)", Severity.HIGH),
    (
        r"(?i)(api[_-]?key|apikey)\s*[=:\"']\s*[A-Za-z0-9\-_]{20,}",
        "Generic API key pattern",
        Severity.HIGH,
    ),
    (
        r"(?i)(password|passwd|secret)\s*[=:\"']\s*\S{8,}",
        "Hardcoded password pattern",
        Severity.HIGH,
    ),
    (r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}", "Bearer token pattern", Severity.HIGH),
    (r"(?i)(private[_-]?key|rsa[_-]?key)", "Private key reference", Severity.HIGH),
    (
        r"(?i)(slack|twilio|stripe)[_-]?(token|key|secret)[=:\"']\s*[A-Za-z0-9]{20,}",
        "Third-party service key",
        Severity.HIGH,
    ),
]

# ATS exception keys that weaken TLS
ATS_WEAKENING_KEYS = {
    "NSAllowsArbitraryLoads": (
        Severity.HIGH,
        "ATS disabled globally — all HTTP traffic allowed",
        "MASVS-NETWORK-1",
    ),
    "NSAllowsArbitraryLoadsInWebContent": (
        Severity.MEDIUM,
        "ATS disabled for WebView content",
        "MASVS-PLATFORM-2",
    ),
    "NSAllowsLocalNetworking": (Severity.LOW, "Local network HTTP allowed", "MASVS-NETWORK-1"),
    "NSExceptionAllowsInsecureHTTPLoads": (
        Severity.MEDIUM,
        "Per-domain HTTP exception present",
        "MASVS-NETWORK-1",
    ),
    "NSThirdPartyExceptionAllowsInsecureHTTPLoads": (
        Severity.MEDIUM,
        "Third-party HTTP exception present",
        "MASVS-NETWORK-1",
    ),
}


def _read_plist(path: Path) -> Optional[dict]:
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        try:
            result = subprocess.run(
                ["plutil", "-convert", "json", "-o", "-", str(path)],
                capture_output=True,
                text=True,
                check=True,
            )
            import json

            return json.loads(result.stdout)
        except Exception:
            return None


def _run_strings(binary_path: Path) -> str:
    try:
        result = subprocess.run(
            ["strings", str(binary_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout
    except FileNotFoundError:
        return ""


def _run_otool(binary_path: Path) -> str:
    try:
        result = subprocess.run(
            ["otool", "-hv", str(binary_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout
    except FileNotFoundError:
        return ""


def _run_codesign_entitlements(app_path: Path) -> Optional[str]:
    try:
        result = subprocess.run(
            ["codesign", "-d", "--entitlements", "-", str(app_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout + result.stderr
    except FileNotFoundError:
        return None


def find_binary(app_path: Path) -> Optional[Path]:
    """Find the main executable inside a .app bundle."""
    plist_path = app_path / "Info.plist"
    plist = _read_plist(plist_path)
    if plist:
        exec_name = plist.get("CFBundleExecutable")
        if exec_name:
            candidate = app_path / exec_name
            if candidate.exists():
                return candidate
    for candidate in app_path.iterdir():
        if (
            candidate.is_file()
            and not candidate.name.startswith(".")
            and candidate.suffix not in {".plist", ".png", ".strings", ".nib", ".car"}
        ):
            return candidate
    return None


def scan_info_plist(app_path: Path, session: AssessmentSession) -> list[Finding]:
    findings: list[Finding] = []
    plist_path = app_path / "Info.plist"

    if not plist_path.exists():
        findings.append(
            Finding(
                masvs_id="MASVS-CODE-4",
                title="Info.plist not found",
                detail=f"Expected Info.plist at {plist_path}",
                severity=Severity.INFO,
                module=MODULE_NAME,
            )
        )
        return findings

    plist = _read_plist(plist_path)
    if plist is None:
        findings.append(
            Finding(
                masvs_id="MASVS-CODE-4",
                title="Info.plist could not be parsed",
                detail=str(plist_path),
                severity=Severity.INFO,
                module=MODULE_NAME,
            )
        )
        return findings

    # Check ATS exceptions
    ats = plist.get("NSAppTransportSecurity", {})
    for key, (sev, title, masvs_id) in ATS_WEAKENING_KEYS.items():
        if ats.get(key):
            findings.append(
                Finding(
                    masvs_id=masvs_id,
                    title=title,
                    detail=f"Info.plist key NSAppTransportSecurity.{key} = True",
                    severity=sev,
                    evidence_paths=[str(plist_path)],
                    module=MODULE_NAME,
                )
            )

    # Check URL schemes (for deep link audit awareness)
    url_types = plist.get("CFBundleURLTypes", [])
    schemes = []
    for url_type in url_types:
        schemes.extend(url_type.get("CFBundleURLSchemes", []))
    if schemes:
        findings.append(
            Finding(
                masvs_id="MASVS-PLATFORM-1",
                title=f"Custom URL scheme(s) registered: {', '.join(schemes)}",
                detail="Custom URL schemes can be registered by any app; use Universal Links for auth callbacks.",
                severity=Severity.INFO,
                evidence_paths=[str(plist_path)],
                raw_output=f"Schemes: {schemes}",
                module=MODULE_NAME,
            )
        )

    # Check minimum OS version
    min_os = plist.get("MinimumOSVersion", "")
    if min_os:
        try:
            major = int(min_os.split(".")[0])
            if major < 15:
                findings.append(
                    Finding(
                        masvs_id="MASVS-CODE-1",
                        title=f"Low minimum OS version: {min_os}",
                        detail="Supporting iOS < 15 includes devices that cannot receive security updates.",
                        severity=Severity.LOW,
                        evidence_paths=[str(plist_path)],
                        module=MODULE_NAME,
                    )
                )
        except ValueError:
            pass

    return findings


def scan_entitlements(app_path: Path, session: AssessmentSession) -> list[Finding]:
    findings: list[Finding] = []
    raw = _run_codesign_entitlements(app_path)
    if not raw:
        return findings

    risky = {
        "com.apple.security.get-task-allow": (
            Severity.MEDIUM,
            "get-task-allow entitlement present — allows debugger attachment (remove in release builds)",
        ),
        "com.apple.private": (Severity.INFO, "Private entitlement(s) present"),
        "com.apple.developer.icloud-container-environment": (
            Severity.INFO,
            "iCloud container access",
        ),
    }

    for key, (sev, description) in risky.items():
        if key in raw:
            findings.append(
                Finding(
                    masvs_id="MASVS-CODE-4",
                    title=description,
                    detail=f"Found in entitlements: {key}",
                    severity=sev,
                    raw_output=raw[:4000],
                    module=MODULE_NAME,
                )
            )

    return findings


def scan_binary_flags(app_path: Path, session: AssessmentSession) -> list[Finding]:
    findings: list[Finding] = []
    binary = find_binary(app_path)
    if not binary:
        findings.append(
            Finding(
                masvs_id="MASVS-CODE-4",
                title="Main executable not found in .app bundle",
                detail=str(app_path),
                severity=Severity.INFO,
                module=MODULE_NAME,
            )
        )
        return findings

    otool_out = _run_otool(binary)

    if otool_out:
        # PIE — Position Independent Executable
        if "PIE" not in otool_out and "pie" not in otool_out.lower():
            findings.append(
                Finding(
                    masvs_id="MASVS-CODE-4",
                    title="PIE (Position Independent Executable) flag not set",
                    detail="ASLR is less effective without PIE. Compile with -pie.",
                    severity=Severity.MEDIUM,
                    evidence_paths=[str(binary)],
                    raw_output=otool_out[:2000],
                    module=MODULE_NAME,
                )
            )

    # Stack canary check via nm
    try:
        nm_result = subprocess.run(
            ["nm", str(binary)],
            capture_output=True,
            text=True,
            check=False,
        )
        nm_out = nm_result.stdout
        if "__stack_chk_fail" not in nm_out and "stack_chk" not in nm_out:
            findings.append(
                Finding(
                    masvs_id="MASVS-CODE-4",
                    title="Stack canary (__stack_chk_fail) symbol not found",
                    detail="Stack protection may not be enabled. Compile with -fstack-protector-all.",
                    severity=Severity.MEDIUM,
                    evidence_paths=[str(binary)],
                    module=MODULE_NAME,
                )
            )
        # ARC
        if "_objc_release" not in nm_out and "objc_storeStrong" not in nm_out:
            findings.append(
                Finding(
                    masvs_id="MASVS-CODE-4",
                    title="ARC (Automatic Reference Counting) markers not found",
                    detail="Binary may not be compiled with ARC enabled.",
                    severity=Severity.LOW,
                    evidence_paths=[str(binary)],
                    module=MODULE_NAME,
                )
            )
    except FileNotFoundError:
        pass

    return findings


def scan_strings_for_secrets(app_path: Path, session: AssessmentSession) -> list[Finding]:
    findings: list[Finding] = []
    binary = find_binary(app_path)
    if not binary:
        return findings

    strings_out = _run_strings(binary)
    if not strings_out:
        return findings

    seen_patterns: set[str] = set()
    for pattern, description, severity in SECRET_PATTERNS:
        matches = re.findall(pattern, strings_out)
        if matches and description not in seen_patterns:
            seen_patterns.add(description)
            # Truncate match for display — don't log the full value
            display = matches[0][:40] + "…" if len(matches[0]) > 40 else matches[0]
            findings.append(
                Finding(
                    masvs_id="MASVS-CRYPTO-2",
                    title=f"Possible hardcoded secret: {description}",
                    detail=f"Pattern match in binary strings. First match (truncated): {display!r}. Verify manually.",
                    severity=severity,
                    evidence_paths=[str(binary)],
                    module=MODULE_NAME,
                )
            )

    return findings


def run(app_path: Path, session: AssessmentSession) -> list[Finding]:
    """Run all static analysis checks and return findings."""
    all_findings: list[Finding] = []
    all_findings.extend(scan_info_plist(app_path, session))
    all_findings.extend(scan_entitlements(app_path, session))
    all_findings.extend(scan_binary_flags(app_path, session))
    all_findings.extend(scan_strings_for_secrets(app_path, session))
    session.mark_module_run(MODULE_NAME)
    for f in all_findings:
        session.add_finding(f)
    return all_findings
