"""simaudit CLI — entry point for all commands."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .device import (
    SimctlError,
    boot_device,
    create_device,
    default_device_type,
    default_ios_runtime,
    erase_device,
    find_device,
    get_app_container,
    list_devices,
    shutdown_device,
)
from .modules import deeplinks, log_capture, static, storage
from .report import generator
from .session import AssessmentSession, Finding

console = Console(stderr=True)
out = Console()


def _err(msg: str) -> None:
    console.print(f"[red]Error:[/red] {msg}")


def _ok(msg: str) -> None:
    console.print(f"[green]✓[/green] {msg}")


def _info(msg: str) -> None:
    console.print(f"[dim]{msg}[/dim]")


def _session_or_exit(session_path: Optional[str]) -> AssessmentSession:
    path = Path(session_path) if session_path else None
    try:
        return AssessmentSession.load(path)
    except FileNotFoundError as exc:
        _err(str(exc))
        sys.exit(1)


# ─── Root ────────────────────────────────────────────────────────────────────


@click.group()
@click.version_option(__version__, prog_name="simaudit")
def cli():
    """iOS Simulator security assessment CLI.

    Automates repeatable app-level security checks against Xcode Simulator,
    maps findings to MASVS v2 controls, and generates structured reports.

    \b
    Simulator-only — not a substitute for real-device or jailbreak-based testing.
    See README for full scope and limitations.
    """


# ─── device ──────────────────────────────────────────────────────────────────


@cli.group()
def device():
    """Simulator device lifecycle management."""


@device.command("init")
@click.option("--name", default="simaudit-lab", show_default=True, help="Device name")
@click.option(
    "--runtime", default=None, help="Runtime identifier (auto-selects latest iOS if omitted)"
)
@click.option(
    "--device-type",
    default=None,
    help="Device type identifier (auto-selects recent iPhone if omitted)",
)
def device_init(name: str, runtime: Optional[str], device_type: Optional[str]):
    """Create and boot a Simulator device for assessment."""
    try:
        rt = runtime or default_ios_runtime()
        dt = device_type or default_device_type()
        if not rt:
            _err("No iOS runtime available. Install one via Xcode → Settings → Platforms.")
            sys.exit(1)
        if not dt:
            _err("No iPhone device type found.")
            sys.exit(1)

        existing = find_device(name)
        if existing:
            _info(f"Device '{name}' already exists ({existing.udid})")
            if not existing.is_booted:
                _info("Booting…")
                boot_device(existing.udid)
                _ok(f"Device booted: {existing.udid}")
            else:
                _ok(f"Device already booted: {existing.udid}")
            return

        _info(f"Creating device '{name}' with runtime={rt} type={dt}")
        udid = create_device(name, dt, rt)
        _info(f"Booting {udid}…")
        boot_device(udid)
        _ok(f"Device ready: {name} ({udid})")
        _info("Tip: run 'open -a Simulator' to see it.")

    except SimctlError as exc:
        _err(str(exc))
        sys.exit(1)


@device.command("reset")
@click.argument("name_or_udid", default="simaudit-lab")
def device_reset(name_or_udid: str):
    """Erase and reboot a device to a clean state."""
    try:
        dev = find_device(name_or_udid)
        if not dev:
            _err(f"Device not found: {name_or_udid}")
            sys.exit(1)
        _info(f"Shutting down {dev.udid}…")
        shutdown_device(dev.udid)
        _info("Erasing…")
        erase_device(dev.udid)
        _info("Booting…")
        boot_device(dev.udid)
        _ok(f"Device reset and booted: {dev.name} ({dev.udid})")
    except SimctlError as exc:
        _err(str(exc))
        sys.exit(1)


@device.command("list")
def device_list():
    """List all Simulator devices."""
    try:
        devices = list_devices()
    except SimctlError as exc:
        _err(str(exc))
        sys.exit(1)

    table = Table(title="Simulator Devices")
    table.add_column("Name", style="bold")
    table.add_column("UDID", style="dim")
    table.add_column("State")
    table.add_column("Runtime", style="dim")

    for d in devices:
        state_style = "green" if d.is_booted else "dim"
        table.add_row(
            d.name, d.udid, f"[{state_style}]{d.state}[/{state_style}]", d.runtime.split(".")[-1]
        )

    out.print(table)


# ─── session ─────────────────────────────────────────────────────────────────


@cli.group()
def session():
    """Assessment session management."""


@session.command("init")
@click.option("--app-name", required=True, help="Human-readable app name")
@click.option("--bundle-id", required=True, help="App bundle identifier (e.g. com.example.App)")
@click.option("--app-version", default="", help="App version string")
@click.option(
    "--device", "device_name", default="simaudit-lab", show_default=True, help="Device name or UDID"
)
@click.option("--session-path", default=None, help="Override session file path")
def session_init(
    app_name: str, bundle_id: str, app_version: str, device_name: str, session_path: Optional[str]
):
    """Initialize a new assessment session."""
    path = Path(session_path) if session_path else None

    if AssessmentSession.exists(path):
        _err("A session already exists. Delete .simaudit/session.json to start fresh.")
        sys.exit(1)

    dev = find_device(device_name)
    udid = dev.udid if dev else ""

    sess = AssessmentSession(
        app_name=app_name,
        bundle_id=bundle_id,
        app_version=app_version,
        device_udid=udid,
    )
    saved = sess.save(path)
    _ok(f"Session initialized: {saved}")
    _info(f"  App: {app_name} ({bundle_id})")
    if udid:
        _info(f"  Device: {device_name} ({udid})")


@session.command("status")
@click.option("--session-path", default=None)
def session_status(session_path: Optional[str]):
    """Show current session status and finding summary."""
    sess = _session_or_exit(session_path)

    out.print(f"\n[bold]Session:[/bold] {sess.session_id}")
    out.print(f"  App:      {sess.app_name} ({sess.bundle_id})")
    if sess.app_version:
        out.print(f"  Version:  {sess.app_version}")
    if sess.device_udid:
        out.print(f"  Device:   {sess.device_udid}")
    out.print(f"  Started:  {sess.started_at.strftime('%Y-%m-%d %H:%M UTC')}")
    out.print(f"  Updated:  {sess.updated_at.strftime('%Y-%m-%d %H:%M UTC')}")
    out.print(f"  Modules:  {', '.join(sess.modules_run) or 'none yet'}")

    by_sev = sess.findings_by_severity()
    sev_colors = {
        "CRITICAL": "red",
        "HIGH": "yellow",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim",
    }
    out.print(f"\n[bold]Findings:[/bold] {len(sess.findings)} total")
    for sev, findings in by_sev.items():
        if findings:
            out.print(f"  [{sev_colors[sev]}]{sev}[/{sev_colors[sev]}]: {len(findings)}")


# ─── scan ─────────────────────────────────────────────────────────────────────


@cli.group()
def scan():
    """Run security scan modules against the target app."""


@scan.command("static")
@click.argument("app_path", type=click.Path(exists=True, path_type=Path))
@click.option("--session-path", default=None)
def scan_static(app_path: Path, session_path: Optional[str]):
    """Static analysis: Info.plist, entitlements, binary flags, secrets patterns."""
    sess = _session_or_exit(session_path)
    path = Path(session_path) if session_path else None

    _info(f"Running static scan on {app_path.name}…")
    findings = static.run(app_path, sess)
    sess.save(path)

    _print_findings(findings)
    _ok(f"Static scan complete — {len(findings)} finding(s)")


@scan.command("storage")
@click.option("--session-path", default=None)
def scan_storage(session_path: Optional[str]):
    """Storage scan: NSUserDefaults, SQLite, caches, Documents/."""
    sess = _session_or_exit(session_path)
    path = Path(session_path) if session_path else None

    if not sess.device_udid:
        _err("No device UDID in session. Re-run 'session init' with --device.")
        sys.exit(1)

    container = get_app_container(sess.device_udid, sess.bundle_id)
    if not container:
        _err(
            f"App container not found for {sess.bundle_id} on {sess.device_udid}.\n"
            "Make sure the app is installed and the device is booted."
        )
        sys.exit(1)

    _info(f"Scanning container: {container}")
    findings = storage.run(container, sess.bundle_id, sess)
    sess.save(path)

    _print_findings(findings)
    _ok(f"Storage scan complete — {len(findings)} finding(s)")


# ─── test ─────────────────────────────────────────────────────────────────────


@cli.group()
def test():
    """Run behavioral test suites against the running app."""


@test.command("deeplinks")
@click.argument("app_path", type=click.Path(exists=True, path_type=Path))
@click.option("--session-path", default=None)
@click.option("--delay", default=0.5, show_default=True, help="Seconds between URL fires")
def test_deeplinks(app_path: Path, session_path: Optional[str], delay: float):
    """Enumerate URL schemes and fire a test matrix via simctl openurl."""
    sess = _session_or_exit(session_path)
    path = Path(session_path) if session_path else None

    _info(f"Testing deep links from {app_path.name}…")
    findings = deeplinks.run(app_path, sess.device_udid, sess, delay=delay)
    sess.save(path)

    _print_findings(findings)
    _ok(f"Deep link test complete — {len(findings)} finding(s)")


# ─── capture ──────────────────────────────────────────────────────────────────


@cli.command("capture")
@click.argument("subcommand", type=click.Choice(["log"]))
@click.option("--duration", default=30, show_default=True, help="Capture duration in seconds")
@click.option(
    "--output-dir", default=".simaudit/evidence", show_default=True, type=click.Path(path_type=Path)
)
@click.option("--session-path", default=None)
def capture(subcommand: str, duration: int, output_dir: Path, session_path: Optional[str]):
    """Capture device output. Use: simaudit capture log"""
    sess = _session_or_exit(session_path)
    path = Path(session_path) if session_path else None

    if subcommand == "log":
        _info(f"Capturing unified log for {duration}s (bundle: {sess.bundle_id})…")
        findings = log_capture.run(sess.bundle_id, output_dir, sess, duration_seconds=duration)
        sess.save(path)
        _print_findings(findings)
        _ok(f"Log capture complete — {len(findings)} finding(s)")


# ─── report ───────────────────────────────────────────────────────────────────


@cli.command("report")
@click.option(
    "--output",
    "-o",
    default=".simaudit/report.html",
    show_default=True,
    type=click.Path(path_type=Path),
)
@click.option(
    "--json-output",
    default=".simaudit/report.json",
    show_default=True,
    type=click.Path(path_type=Path),
)
@click.option("--session-path", default=None)
def report(output: Path, json_output: Path, session_path: Optional[str]):
    """Generate HTML and JSON reports from the current session."""
    sess = _session_or_exit(session_path)

    html_path = generator.generate_html(sess, output)
    json_path = generator.generate_json(sess, json_output)

    _ok(f"HTML report: {html_path}")
    _ok(f"JSON report: {json_path}")

    # Summary table
    table = Table(title=f"Assessment Summary — {sess.app_name}")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    sev_colors = {
        "CRITICAL": "red",
        "HIGH": "yellow",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim",
    }
    by_sev = sess.findings_by_severity()
    for sev, findings in by_sev.items():
        if findings:
            table.add_row(f"[{sev_colors[sev]}]{sev}[/{sev_colors[sev]}]", str(len(findings)))
    table.add_row("[bold]TOTAL[/bold]", str(len(sess.findings)))
    out.print(table)


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _print_findings(findings: list[Finding]) -> None:
    sev_colors = {
        "CRITICAL": "red",
        "HIGH": "yellow",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim",
    }
    for f in findings:
        color = sev_colors.get(f.severity.value, "white")
        out.print(f"  [{color}]{f.severity.value:8}[/{color}] [dim]{f.masvs_id:22}[/dim] {f.title}")
