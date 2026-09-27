# Changelog

All notable changes to simaudit are documented here.

## [0.1.0] — 2026-09-27

Initial public release.

### Added

- **`device` commands** — `init`, `reset`, `list` via `xcrun simctl`
- **`session` commands** — `init`, `status`; Pydantic v2 `AssessmentSession` and `Finding` models with JSON serialization
- **`scan static`** — Info.plist analysis (ATS, URL schemes, minimum OS version), codesign entitlements, binary flags (PIE, stack canaries, ARC), hardcoded secret patterns via `strings`
- **`scan storage`** — NSUserDefaults sensitive key detection, SQLite schema inspection, NSURLCache scan, Documents/ filename audit
- **`test deeplinks`** — URL scheme enumeration from Info.plist, universal link domain extraction from entitlements, test URL matrix firing via `simctl openurl`
- **`capture log`** — unified log streaming with bundle ID filter, sensitive data pattern detection (passwords, tokens, card numbers, SSNs, private keys)
- **`report`** — self-contained HTML report (Jinja2, no external dependencies) and machine-readable JSON report
- **MASVS v2 control catalog** — 15 controls across STORAGE, CRYPTO, PLATFORM, CODE, NETWORK, AUTH categories
- **58-test suite** — all mocked (no real Simulator required); covers device, session, static, storage, deeplinks, report, masvs modules
- MIT license, pyproject.toml (PEP 517), Makefile, .gitignore
