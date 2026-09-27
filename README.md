# simaudit

**Repeatable iOS Simulator security assessments, mapped to OWASP MASVS v2.**

`simaudit` is a command-line tool for mobile security professionals who want a structured, reproducible way to assess iOS apps during development and testing. It works entirely against the Xcode iOS Simulator — no physical device, no jailbreak, no provisioning profile.

---

## Who it's for

- Mobile app security engineers running assessments as part of a secure SDLC
- Penetration testers who want a Simulator-first workflow before moving to real devices
- Developers who want automated MASVS checks in a local pipeline

---

## What it does

| Command | What it checks | MASVS coverage |
|---------|---------------|----------------|
| `scan static <app.app>` | Info.plist (ATS, URL schemes, min OS), entitlements, binary flags (PIE, stack canaries, ARC), hardcoded secrets | MASVS-STORAGE, MASVS-NETWORK, MASVS-CODE, MASVS-CRYPTO, MASVS-PLATFORM |
| `scan storage` | NSUserDefaults sensitive keys, SQLite schemas (password/token columns), NSURLCache, Documents/ filenames | MASVS-STORAGE |
| `test deeplinks <app.app>` | Enumerates registered URL schemes and universal link domains; fires a test matrix via `simctl openurl` | MASVS-PLATFORM |
| `capture log` | Streams the unified log (filtered to the target bundle ID), flags sensitive data patterns (passwords, tokens, card numbers, SSNs) | MASVS-STORAGE |
| `report` | Generates a self-contained HTML report and a machine-readable JSON report | All |

Everything is stored in an **assessment session** (`.simaudit/session.json`) so findings accumulate across module runs and you can generate the final report at any time.

---

## Simulator limitations

`simaudit` operates only against `xcrun simctl`-managed devices on macOS. This means:

- **No Keychain testing** — Simulator Keychain is not isolated per-app
- **No ATS enforcement** — Simulator does not enforce App Transport Security
- **No entitlement enforcement** — codesign entitlements are present but not enforced
- **No hardware-backed security** — Secure Enclave, biometrics, APNS not available
- **Frida without frida-server** — Simulator processes are macOS processes; `frida -p <PID>` attaches directly (not yet implemented in v0.1, planned for v1.1)

A Simulator finding is a **lead**, not a confirmed vulnerability on real hardware. Always validate HIGH/CRITICAL findings on a real device before reporting.

---

## Install

**Requirements:** Python 3.11+, macOS with Xcode and the iOS Simulator runtime installed.

```bash
# From source (recommended for security work)
git clone https://github.com/Jammysk8/simaudit.git
cd simaudit
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Verify the install:

```bash
simaudit --version
simaudit --help
```

---

## Usage

### 1. Prepare a device

```bash
# Create and boot a dedicated assessment device
simaudit device init --name simaudit-lab

# List all Simulator devices
simaudit device list

# Erase and reboot to a known-clean state between assessments
simaudit device reset simaudit-lab
```

### 2. Start a session

```bash
# Initialize a session for the target app
simaudit session init \
  --app-name "MyApp" \
  --bundle-id "com.example.MyApp" \
  --app-version "2.3.1" \
  --device simaudit-lab

# Check session status at any time
simaudit session status
```

### 3. Run scans

```bash
# Static analysis against the .app bundle
simaudit scan static /path/to/MyApp.app

# Storage scan (requires the app installed and device booted)
simaudit scan storage

# Deep link enumeration and test firing
simaudit test deeplinks /path/to/MyApp.app

# Unified log capture (30 seconds by default)
simaudit capture log --duration 60
```

### 4. Generate reports

```bash
# Write HTML + JSON reports
simaudit report

# Custom output paths
simaudit report -o ~/assessments/myapp.html --json-output ~/assessments/myapp.json
```

The HTML report is self-contained (no external dependencies) and opens in any browser.

---

## Session files

All session data lives in `.simaudit/` in the current working directory:

```
.simaudit/
  session.json        # session metadata + all findings
  evidence/           # log captures and other artifacts
  report.html         # latest HTML report
  report.json         # latest JSON report
```

Add `.simaudit/` to your `.gitignore` — sessions typically contain app data you do not want checked in.

---

## Architecture

```
src/simaudit/
  cli.py              # Click entry point; all command groups
  device.py           # xcrun simctl wrappers
  session.py          # AssessmentSession and Finding (Pydantic v2)
  masvs.py            # MASVS v2 control catalog (15 controls)
  modules/
    static.py         # Info.plist, entitlements, binary, secrets
    storage.py        # NSUserDefaults, SQLite, caches, Documents
    deeplinks.py      # URL scheme enumeration and test firing
    log_capture.py    # Unified log streaming and analysis
  report/
    generator.py      # Jinja2 HTML + JSON report generation
    templates/
      report.html.j2  # Self-contained HTML template
```

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
make test

# Run tests with coverage report
make test-cov

# Lint and format
make lint
make fmt
```

### Running the tests

Tests mock all subprocess calls — no real Simulator or app is required:

```bash
pytest tests/ -v
```

### Adding a scan module

1. Create `src/simaudit/modules/mymodule.py` with a `run(...)` function that returns `list[Finding]`
2. Add a `MODULE_NAME` constant and call `session.mark_module_run(MODULE_NAME)` at the end of `run()`
3. Wire a new Click command in `cli.py`
4. Add tests in `tests/test_mymodule.py`

---

## Security and legal scope

`simaudit` is designed for **authorized testing only**:

- Only run against apps and devices you own or have explicit written authorization to test
- Do not use against production devices or services
- Simulator findings must be validated on real hardware before reporting to a vendor
- Follow responsible disclosure practices for any findings you report

See `LICENSE` (MIT) for the full terms.

---

## Roadmap

**v0.1 (current)**
- Static analysis, storage, deep links, log capture, HTML/JSON report
- Full MASVS v2 mapping
- 58-test suite, all mocked

**v1.1 (planned)**
- Frida runtime inspection (Simulator processes are macOS processes — no frida-server required)
- WebView traffic observation via `xcrun simctl diagnose`
- Screenshot capture and diff across test steps
- CI mode (`--exit-code-on-severity HIGH`)

---

## License

MIT — see [LICENSE](LICENSE).
