"""Assessment session model — persistent JSON-backed state for a simaudit run."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from .masvs import Severity

SESSION_FILE = ".simaudit/session.json"


class Finding(BaseModel):
    """A single security finding mapped to a MASVS control."""

    id: str = Field(default_factory=lambda: str(uuid4())[:8])
    masvs_id: str
    title: str
    detail: str
    severity: Severity
    evidence_paths: list[str] = Field(default_factory=list)
    raw_output: Optional[str] = None
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    module: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "masvs_id": self.masvs_id,
            "title": self.title,
            "detail": self.detail,
            "severity": self.severity.value,
            "evidence_paths": self.evidence_paths,
            "raw_output": self.raw_output,
            "discovered_at": self.discovered_at.isoformat(),
            "module": self.module,
        }


class AssessmentSession(BaseModel):
    """Root model — everything simaudit knows about one assessment."""

    session_id: str = Field(default_factory=lambda: str(uuid4())[:12])
    app_name: str
    bundle_id: str
    app_version: str = ""
    device_udid: str = ""
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    findings: list[Finding] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    modules_run: list[str] = Field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.updated_at = datetime.now(timezone.utc)

    def add_note(self, note: str) -> None:
        self.notes.append(f"[{datetime.now(timezone.utc).isoformat()}] {note}")
        self.updated_at = datetime.now(timezone.utc)

    def mark_module_run(self, module: str) -> None:
        if module not in self.modules_run:
            self.modules_run.append(module)
        self.updated_at = datetime.now(timezone.utc)

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        order = [s.value for s in Severity]
        result: dict[str, list[Finding]] = {s: [] for s in order}
        for f in self.findings:
            result[f.severity.value].append(f)
        return result

    def findings_by_category(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            cat = f.masvs_id.rsplit("-", 1)[0] if "-" in f.masvs_id else f.masvs_id
            result.setdefault(cat, []).append(f)
        return result

    def save(self, path: Optional[Path] = None) -> Path:
        target = path or Path(SESSION_FILE)
        target.parent.mkdir(parents=True, exist_ok=True)
        self.updated_at = datetime.now(timezone.utc)
        target.write_text(self.model_dump_json(indent=2))
        return target

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "AssessmentSession":
        target = path or Path(SESSION_FILE)
        if not target.exists():
            raise FileNotFoundError(
                f"No session found at {target}. Run 'simaudit session init' first."
            )
        return cls.model_validate_json(target.read_text())

    @classmethod
    def exists(cls, path: Optional[Path] = None) -> bool:
        target = path or Path(SESSION_FILE)
        return target.exists()
