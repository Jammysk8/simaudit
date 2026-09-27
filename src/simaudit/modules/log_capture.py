"""Log capture module — structured unified log collection from the Simulator."""

from __future__ import annotations

import re
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..masvs import Severity
from ..session import AssessmentSession, Finding

MODULE_NAME = "log_capture"

# Sensitive data patterns to flag in log output

SENSITIVE_LOG_PATTERNS: list[tuple[str, str, Severity]] = [
    (r"(?i)(password|passwd)\s*[:=]\s*\S+", "Password logged", Severity.CRITICAL),
    (
        r"(?i)(token|bearer|api[_-]?key)\s*[:=]\s*[A-Za-z0-9\-_.]{10,}",
        "Auth token logged",
        Severity.HIGH,
    ),
    (r"\b4[0-9]{12}(?:[0-9]{3})?\b", "Credit card number pattern (Visa)", Severity.CRITICAL),
    (r"\b5[1-5][0-9]{14}\b", "Credit card number pattern (MC)", Severity.CRITICAL),
    (r"(?i)(ssn|social.security)\s*[:=]\s*\d{3}-\d{2}-\d{4}", "SSN pattern", Severity.CRITICAL),
    (r"(?i)private[_-]?key\s*[:=]", "Private key reference logged", Severity.HIGH),
]


def _build_log_command(
    bundle_id: Optional[str] = None,
    level: str = "debug",
    extra_predicates: Optional[list[str]] = None,
) -> list[str]:
    cmd = ["log", "stream", "--style", "compact", "--level", level]
    predicates = []
    if bundle_id:
        predicates.append(f'subsystem == "{bundle_id}"')
        predicates.append(f'process CONTAINS "{bundle_id.split(".")[-1]}"')
    if extra_predicates:
        predicates.extend(extra_predicates)
    if predicates:
        combined = " OR ".join(f"({p})" for p in predicates)
        cmd += ["--predicate", combined]
    return cmd


def stream_log(
    bundle_id: Optional[str],
    output_path: Path,
    duration_seconds: int = 30,
    level: str = "debug",
) -> tuple[int, str]:
    """
    Stream the unified log for duration_seconds seconds and write to output_path.
    Returns (line_count, summary).
    """
    cmd = _build_log_command(bundle_id=bundle_id, level=level)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines_written = 0
    sensitive_hits: list[str] = []

    try:
        with open(output_path, "w") as out_file:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )

            def _timeout():
                proc.terminate()

            timer = threading.Timer(duration_seconds, _timeout)
            timer.start()
            try:
                for line in proc.stdout:  # type: ignore[union-attr]
                    out_file.write(line)
                    lines_written += 1
                    for pattern, label, _ in SENSITIVE_LOG_PATTERNS:
                        if re.search(pattern, line):
                            sensitive_hits.append(f"[{label}] {line.rstrip()[:200]}")
            finally:
                timer.cancel()
                proc.wait()
    except FileNotFoundError:
        return 0, "log command not found — requires macOS"

    summary = f"{lines_written} log lines captured"
    if sensitive_hits:
        summary += f"; {len(sensitive_hits)} sensitive pattern hit(s)"
    return lines_written, summary


def analyze_log_file(
    log_path: Path,
    session: AssessmentSession,
) -> list[Finding]:
    """Analyze a previously captured log file for sensitive data patterns."""
    findings: list[Finding] = []
    if not log_path.exists():
        return findings

    text = log_path.read_text(errors="replace")
    lines = text.splitlines()

    hits_by_label: dict[str, list[str]] = {}
    for line in lines:
        for pattern, label, severity in SENSITIVE_LOG_PATTERNS:
            if re.search(pattern, line):
                hits_by_label.setdefault(label, []).append(line[:300])

    for label, matching_lines in hits_by_label.items():
        # Determine severity from pattern definition
        sev = next(
            (s for _, lbl, s in SENSITIVE_LOG_PATTERNS if lbl == label),
            Severity.HIGH,
        )
        findings.append(
            Finding(
                masvs_id="MASVS-STORAGE-1",
                title=f"Sensitive data in unified log: {label}",
                detail=(
                    f"{len(matching_lines)} line(s) matching pattern. "
                    "Sensitive data in logs is readable by any app with the com.apple.logging entitlement "
                    "and by anyone with physical or forensic access to device logs."
                ),
                severity=sev,
                evidence_paths=[str(log_path)],
                raw_output="\n".join(matching_lines[:10]),
                module=MODULE_NAME,
            )
        )

    if not findings:
        findings.append(
            Finding(
                masvs_id="MASVS-STORAGE-1",
                title=f"Log capture analyzed — {len(lines)} lines, no sensitive patterns matched",
                detail=str(log_path),
                severity=Severity.INFO,
                evidence_paths=[str(log_path)],
                module=MODULE_NAME,
            )
        )

    return findings


def run(
    bundle_id: Optional[str],
    output_dir: Path,
    session: AssessmentSession,
    duration_seconds: int = 30,
) -> list[Finding]:
    """Capture unified log for duration_seconds, analyze, return findings."""
    all_findings: list[Finding] = []

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    log_path = output_dir / f"log_{timestamp}.txt"

    line_count, summary = stream_log(
        bundle_id=bundle_id,
        output_path=log_path,
        duration_seconds=duration_seconds,
    )

    all_findings.append(
        Finding(
            masvs_id="MASVS-STORAGE-1",
            title=f"Log capture: {summary}",
            detail=f"Captured to {log_path}",
            severity=Severity.INFO,
            evidence_paths=[str(log_path)],
            module=MODULE_NAME,
        )
    )

    if line_count > 0:
        all_findings.extend(analyze_log_file(log_path, session))

    session.mark_module_run(MODULE_NAME)
    for f in all_findings:
        session.add_finding(f)
    return all_findings
