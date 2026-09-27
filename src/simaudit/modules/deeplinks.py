"""Deep link testing module — URL scheme enumeration and test-matrix firing."""

from __future__ import annotations

import plistlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import quote

from ..device import SimctlError, open_url
from ..masvs import Severity
from ..session import AssessmentSession, Finding

MODULE_NAME = "deeplinks"


@dataclass
class DeepLinkResult:
    url: str
    success: bool
    log_snippet: str = ""
    error: str = ""


@dataclass
class SchemeInfo:
    scheme: str
    role: Optional[str] = None
    handler_url: Optional[str] = None
    icon_files: list[str] = field(default_factory=list)


def extract_url_schemes(app_path: Path) -> list[SchemeInfo]:
    """Parse Info.plist for registered CFBundleURLSchemes."""
    plist_path = app_path / "Info.plist"
    if not plist_path.exists():
        return []

    try:
        with open(plist_path, "rb") as f:
            plist = plistlib.load(f)
    except Exception:
        return []

    schemes: list[SchemeInfo] = []
    for url_type in plist.get("CFBundleURLTypes", []):
        role = url_type.get("CFBundleTypeRole", "")
        for scheme in url_type.get("CFBundleURLSchemes", []):
            schemes.append(SchemeInfo(scheme=scheme, role=role))

    return schemes


def extract_universal_link_domains(app_path: Path) -> list[str]:
    """Read associated-domains entitlement if present in the .app."""
    # In Simulator, entitlements are embedded in the binary's code signature.
    import subprocess

    try:
        result = subprocess.run(
            ["codesign", "-d", "--entitlements", "-", str(app_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        output = result.stdout + result.stderr
    except FileNotFoundError:
        return []

    domains: list[str] = []
    # Simple parse — looking for applinks: domain entries
    import re

    for match in re.finditer(r"applinks:([a-zA-Z0-9.\-]+)", output):
        domains.append(match.group(1))
    return domains


# Test payloads for common injection/bypass scenarios
# These are generic inputs for training app testing — not exploitation payloads.
_TEST_CASES: list[tuple[str, str]] = [
    ("base", ""),
    ("path_traversal", "../../../etc/passwd"),
    ("empty_host", "//"),
    ("unicode_path", "/test/éà"),
    ("long_param", "a" * 200),
    ("special_chars", "/test?q=" + quote("<script>alert(1)</script>")),
]


def build_test_urls(scheme: str) -> list[tuple[str, str]]:
    """Return (label, url) pairs to fire for a given scheme."""
    urls = []
    for label, payload in _TEST_CASES:
        if payload:
            urls.append((label, f"{scheme}://{payload}"))
        else:
            urls.append((label, f"{scheme}://"))
    return urls


def run(
    app_path: Path,
    udid: str,
    session: AssessmentSession,
    delay: float = 0.5,
) -> list[Finding]:
    """
    Enumerate URL schemes, fire a test matrix via simctl openurl, return findings.

    delay: seconds to wait between URL openurl calls (default 0.5s).
    """
    all_findings: list[Finding] = []

    schemes = extract_url_schemes(app_path)
    ul_domains = extract_universal_link_domains(app_path)

    if not schemes and not ul_domains:
        all_findings.append(
            Finding(
                masvs_id="MASVS-PLATFORM-1",
                title="No URL schemes or Universal Links registered",
                detail="App does not expose URL scheme or Universal Link entry points.",
                severity=Severity.INFO,
                module=MODULE_NAME,
            )
        )
        session.mark_module_run(MODULE_NAME)
        for f in all_findings:
            session.add_finding(f)
        return all_findings

    # Report discovered schemes as INFO
    if schemes:
        scheme_list = ", ".join(f"{s.scheme}://" for s in schemes)
        all_findings.append(
            Finding(
                masvs_id="MASVS-PLATFORM-1",
                title=f"Custom URL scheme(s) found: {scheme_list}",
                detail=(
                    "Custom URL schemes can be claimed by any installed app. "
                    "OAuth callbacks or sensitive actions delivered via custom schemes "
                    "are vulnerable to scheme hijacking. Prefer Universal Links."
                ),
                severity=Severity.INFO if len(schemes) == 1 else Severity.LOW,
                evidence_paths=[str(app_path / "Info.plist")],
                raw_output="\n".join(f"{s.scheme}:// (role={s.role})" for s in schemes),
                module=MODULE_NAME,
            )
        )

    if ul_domains:
        all_findings.append(
            Finding(
                masvs_id="MASVS-PLATFORM-1",
                title=f"Universal Links configured for: {', '.join(ul_domains)}",
                detail="Verify .well-known/apple-app-site-association is served over HTTPS with correct paths.",
                severity=Severity.INFO,
                module=MODULE_NAME,
            )
        )

    # Fire test URLs — requires a booted device
    results: list[DeepLinkResult] = []
    if udid:
        for scheme_info in schemes:
            test_cases = build_test_urls(scheme_info.scheme)
            for label, url in test_cases:
                try:
                    result = open_url(udid, url)
                    success = result.returncode == 0
                    results.append(
                        DeepLinkResult(
                            url=url,
                            success=success,
                            error=result.stderr.strip() if not success else "",
                        )
                    )
                except SimctlError as exc:
                    results.append(DeepLinkResult(url=url, success=False, error=str(exc)))
                time.sleep(delay)

        fired = len(results)
        accepted = sum(1 for r in results if r.success)
        rejected = fired - accepted
        raw_lines = [
            f"{'OK' if r.success else 'ERR'} {r.url}" + (f" — {r.error}" if r.error else "")
            for r in results
        ]

        all_findings.append(
            Finding(
                masvs_id="MASVS-PLATFORM-1",
                title=f"Deep link test matrix: {fired} URLs fired, {accepted} accepted, {rejected} rejected",
                detail=(
                    "Review the raw output for unexpected acceptance of malformed or injection-style paths. "
                    "The app's URL handler should validate all parameters before acting on them."
                ),
                severity=Severity.INFO,
                raw_output="\n".join(raw_lines),
                module=MODULE_NAME,
            )
        )

    session.mark_module_run(MODULE_NAME)
    for f in all_findings:
        session.add_finding(f)
    return all_findings
