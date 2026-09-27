"""Report generator — produces self-contained HTML and machine-readable JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..masvs import Severity
from ..session import AssessmentSession

TEMPLATE_DIR = Path(__file__).parent / "templates"

SEVERITY_ORDER = [s.value for s in Severity]
SEVERITY_COLOR = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#3498db",
    "INFO": "#7f8c8d",
}


def _severity_sort_key(f) -> int:
    try:
        return SEVERITY_ORDER.index(f.severity.value)
    except ValueError:
        return 99


def generate_html(session: AssessmentSession, output_path: Path) -> Path:
    """Render the assessment session to a self-contained HTML report."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")

    categories: dict[str, list] = {}
    for f in sorted(session.findings, key=_severity_sort_key):
        cat = f.masvs_id.rsplit("-", 1)[0] if f.masvs_id.count("-") >= 2 else f.masvs_id
        categories.setdefault(cat, []).append(f)

    stats = {
        "total": len(session.findings),
        "by_severity": {s: 0 for s in SEVERITY_ORDER},
    }
    for f in session.findings:
        stats["by_severity"][f.severity.value] += 1

    rendered = template.render(
        session=session,
        categories=categories,
        stats=stats,
        severity_color=SEVERITY_COLOR,
        generated_at=datetime.now(timezone.utc).isoformat(),
        simaudit_version="0.1.0",
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered)
    return output_path


def generate_json(session: AssessmentSession, output_path: Path) -> Path:
    """Write a machine-readable JSON report."""
    data = {
        "simaudit_version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "session": {
            "session_id": session.session_id,
            "app_name": session.app_name,
            "bundle_id": session.bundle_id,
            "app_version": session.app_version,
            "device_udid": session.device_udid,
            "started_at": session.started_at.isoformat(),
            "updated_at": session.updated_at.isoformat(),
            "modules_run": session.modules_run,
        },
        "summary": {
            "total_findings": len(session.findings),
            "by_severity": {
                s: sum(1 for f in session.findings if f.severity.value == s) for s in SEVERITY_ORDER
            },
        },
        "findings": [f.to_dict() for f in sorted(session.findings, key=_severity_sort_key)],
        "notes": session.notes,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, indent=2))
    return output_path
