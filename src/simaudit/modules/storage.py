"""Storage analysis module — walks the app data container for sensitive data."""

from __future__ import annotations

import plistlib
import re
import sqlite3
from pathlib import Path
from typing import Optional

from ..masvs import Severity
from ..session import AssessmentSession, Finding

MODULE_NAME = "storage"

# Key names that suggest sensitive data in NSUserDefaults / plists
SENSITIVE_KEY_PATTERNS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|auth|credential|private|session|pin|"
    r"credit[_-]?card|ssn|social[_-]?security|dob|date[_-]?of[_-]?birth)",
    re.IGNORECASE,
)

# Plist keys to skip (known safe system keys)
SAFE_PLIST_KEYS = {
    "NSWindow",
    "NSToolbar",
    "NSLanguage",
    "AppleLanguages",
    "AppleLocale",
    "NSInterfaceStyle",
    "com.apple",
}


def _is_safe_key(key: str) -> bool:
    for safe in SAFE_PLIST_KEYS:
        if key.startswith(safe):
            return True
    return False


def _read_plist_dict(path: Path) -> Optional[dict]:
    try:
        with open(path, "rb") as f:
            data = plistlib.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _plist_to_str(val) -> str:
    if isinstance(val, (bytes, bytearray)):
        return f"<binary data {len(val)} bytes>"
    return str(val)[:200]


def scan_nsuserdefaults(
    container: Path, bundle_id: str, session: AssessmentSession
) -> list[Finding]:
    """Scan NSUserDefaults plist in Library/Preferences/<bundle_id>.plist."""
    findings: list[Finding] = []
    prefs_dir = container / "Library" / "Preferences"
    if not prefs_dir.exists():
        return findings

    plist_path = prefs_dir / f"{bundle_id}.plist"
    if not plist_path.exists():
        # Also check for partial matches (bundle ID prefixes)
        candidates = list(prefs_dir.glob(f"{bundle_id}*.plist"))
        if not candidates:
            return findings
        plist_path = candidates[0]

    plist = _read_plist_dict(plist_path)
    if plist is None:
        return findings

    sensitive_keys = []
    for key, value in plist.items():
        if _is_safe_key(key):
            continue
        if SENSITIVE_KEY_PATTERNS.search(key):
            sensitive_keys.append(f"{key}: {_plist_to_str(value)}")

    if sensitive_keys:
        findings.append(
            Finding(
                masvs_id="MASVS-STORAGE-1",
                title="Potentially sensitive keys in NSUserDefaults",
                detail=(
                    "NSUserDefaults is not encrypted. Sensitive values stored here are readable "
                    "by anyone with filesystem access to the app's data container.\n"
                    f"Keys found: {', '.join(k.split(':')[0] for k in sensitive_keys[:10])}"
                ),
                severity=Severity.HIGH,
                evidence_paths=[str(plist_path)],
                raw_output="\n".join(sensitive_keys[:20]),
                module=MODULE_NAME,
            )
        )
    else:
        findings.append(
            Finding(
                masvs_id="MASVS-STORAGE-1",
                title="NSUserDefaults inspected — no obviously sensitive keys found",
                detail=f"Reviewed {len(plist)} keys in {plist_path.name}",
                severity=Severity.INFO,
                evidence_paths=[str(plist_path)],
                module=MODULE_NAME,
            )
        )

    return findings


def scan_sqlite_databases(container: Path, session: AssessmentSession) -> list[Finding]:
    """Find and summarize all SQLite databases in the data container."""
    findings: list[Finding] = []
    db_paths = list(container.rglob("*.sqlite")) + list(container.rglob("*.db"))

    if not db_paths:
        findings.append(
            Finding(
                masvs_id="MASVS-STORAGE-1",
                title="No SQLite databases found in app container",
                detail=str(container),
                severity=Severity.INFO,
                module=MODULE_NAME,
            )
        )
        return findings

    for db_path in db_paths[:10]:  # Limit to first 10 databases
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            schema_lines = []
            sensitive_tables = []
            for table in tables:
                try:
                    cursor.execute(f"PRAGMA table_info({table})")  # noqa: S608
                    columns = [row[1] for row in cursor.fetchall()]
                    cursor.execute(f'SELECT COUNT(*) FROM "{table}"')  # noqa: S608
                    row_count = cursor.fetchone()[0]
                    schema_lines.append(f"{table} ({', '.join(columns)}) — {row_count} rows")
                    if any(SENSITIVE_KEY_PATTERNS.search(c) for c in columns):
                        sensitive_tables.append(table)
                except sqlite3.Error:
                    schema_lines.append(f"{table} — could not inspect")
            conn.close()

            rel_path = db_path.relative_to(container)
            if sensitive_tables:
                findings.append(
                    Finding(
                        masvs_id="MASVS-STORAGE-1",
                        title=f"SQLite database with sensitive-looking columns: {db_path.name}",
                        detail=(
                            f"Tables with sensitive column names: {', '.join(sensitive_tables)}.\n"
                            "Verify that this data is encrypted at rest or that it does not contain "
                            "sensitive PII/credentials."
                        ),
                        severity=Severity.MEDIUM,
                        evidence_paths=[str(db_path)],
                        raw_output="\n".join(schema_lines),
                        module=MODULE_NAME,
                    )
                )
            else:
                findings.append(
                    Finding(
                        masvs_id="MASVS-STORAGE-1",
                        title=f"SQLite database inspected: {db_path.name}",
                        detail=f"Location: {rel_path}. No obviously sensitive column names.",
                        severity=Severity.INFO,
                        evidence_paths=[str(db_path)],
                        raw_output="\n".join(schema_lines),
                        module=MODULE_NAME,
                    )
                )
        except sqlite3.Error as exc:
            findings.append(
                Finding(
                    masvs_id="MASVS-STORAGE-1",
                    title=f"SQLite database could not be opened: {db_path.name}",
                    detail=str(exc),
                    severity=Severity.INFO,
                    evidence_paths=[str(db_path)],
                    module=MODULE_NAME,
                )
            )

    return findings


def scan_cache(container: Path, session: AssessmentSession) -> list[Finding]:
    """Check NSURLCache and generic cache directories."""
    findings: list[Finding] = []
    cache_dir = container / "Library" / "Caches"
    if not cache_dir.exists():
        return findings

    # Look for Cache.db (NSURLCache disk cache)
    cache_dbs = list(cache_dir.rglob("Cache.db"))
    for db_path in cache_dbs:
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            row_counts = {}
            for table in tables:
                try:
                    cursor.execute(f'SELECT COUNT(*) FROM "{table}"')  # noqa: S608
                    row_counts[table] = cursor.fetchone()[0]
                except sqlite3.Error:
                    row_counts[table] = -1
            conn.close()
            total = sum(v for v in row_counts.values() if v > 0)
            if total > 0:
                findings.append(
                    Finding(
                        masvs_id="MASVS-STORAGE-2",
                        title=f"NSURLCache disk cache contains {total} cached entries",
                        detail=(
                            "HTTP response caching may persist sensitive API responses to disk. "
                            "Verify that sensitive endpoints set Cache-Control: no-store."
                        ),
                        severity=Severity.MEDIUM,
                        evidence_paths=[str(db_path)],
                        raw_output=str(row_counts),
                        module=MODULE_NAME,
                    )
                )
        except sqlite3.Error:
            pass

    # Count total cache size
    total_bytes = sum(f.stat().st_size for f in cache_dir.rglob("*") if f.is_file())
    if total_bytes > 10 * 1024 * 1024:  # >10 MB
        findings.append(
            Finding(
                masvs_id="MASVS-STORAGE-2",
                title=f"Large cache directory: {total_bytes // (1024 * 1024)} MB",
                detail="Large caches may contain sensitive data. Review contents manually.",
                severity=Severity.LOW,
                evidence_paths=[str(cache_dir)],
                module=MODULE_NAME,
            )
        )

    return findings


def scan_documents(container: Path, session: AssessmentSession) -> list[Finding]:
    """Enumerate Documents/ directory for sensitive-looking files."""
    findings: list[Finding] = []
    docs_dir = container / "Documents"
    if not docs_dir.exists():
        return findings

    files = [f for f in docs_dir.rglob("*") if f.is_file()]
    if not files:
        return findings

    sensitive_exts = {".key", ".pem", ".p12", ".pfx", ".cert", ".crt", ".cer"}
    sensitive_names = re.compile(r"(?i)(password|secret|token|key|credential|private)")

    flagged = []
    for f in files:
        if f.suffix.lower() in sensitive_exts:
            flagged.append(f"{f.name} — sensitive extension")
        elif sensitive_names.search(f.stem):
            flagged.append(f"{f.name} — sensitive filename")

    if flagged:
        findings.append(
            Finding(
                masvs_id="MASVS-STORAGE-2",
                title=f"Potentially sensitive files in Documents/: {len(flagged)} file(s)",
                detail="Files in Documents/ are accessible via iTunes file sharing and may be backed up.",
                severity=Severity.MEDIUM,
                evidence_paths=[str(docs_dir)],
                raw_output="\n".join(flagged),
                module=MODULE_NAME,
            )
        )
    else:
        findings.append(
            Finding(
                masvs_id="MASVS-STORAGE-2",
                title=f"Documents/ directory inspected — {len(files)} file(s), no sensitive names",
                detail=str(docs_dir),
                severity=Severity.INFO,
                evidence_paths=[str(docs_dir)],
                module=MODULE_NAME,
            )
        )

    return findings


def run(container: Path, bundle_id: str, session: AssessmentSession) -> list[Finding]:
    """Run all storage analysis checks and return findings."""
    all_findings: list[Finding] = []
    all_findings.extend(scan_nsuserdefaults(container, bundle_id, session))
    all_findings.extend(scan_sqlite_databases(container, session))
    all_findings.extend(scan_cache(container, session))
    all_findings.extend(scan_documents(container, session))
    session.mark_module_run(MODULE_NAME)
    for f in all_findings:
        session.add_finding(f)
    return all_findings
