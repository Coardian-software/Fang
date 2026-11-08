# Changelog

All notable changes to Fang are documented in this file. The format follows Keep a Changelog and the project aims for semantic versioning.

## [Unreleased]

### Changed

- Dropped the GUI entirely. Fang is now a Cobra CLI (`fang scan run`, `fang findings`, `fang modules`, `fang report`, `fang export`) and stays that way.
- Calibrated the module portfolio to about 42 focused modules: the CORE15 web vulnerability classes (sqli, xss, ssrf, cmdi, lfi, redirect, cors, ssti, xxe, nosqli, graphql, headers, recon, browser, inject), the KEEP tier, and new narrow fold modules.

### Added

- Crawl-first scanning stage with hard caps: `--max-depth`, `--max-pages`, and `--no-crawl`.
- One shared engine-owned HTTP client for all modules, honoring `--proxy`, `--rate-limit`, custom headers, and cookies, with retry middleware applied uniformly.
- Panic-isolated module execution so a faulty check cannot take down a scan.
- Context-aware cancellation across the engine.
- Confidence scoring kernel: STRONG/WEAK pattern classes, marker reflection, baseline delta, and cross-module corroboration. Weak evidence is capped below Critical.
- Finding deduplication keyed on sha1(class|host|param|path).
- Stable finding fingerprints (sha256-truncated) with first_seen, last_seen, occurrence counts, and an open/reopened/fixed lifecycle.
- Incremental crash-safe persistence to SQLite.
- Public regression tests, race-test coverage, response-size limits, dependency security updates, and Docker runtime asset checks.

## [0.1.0]

Not yet released. See ROADMAP.md for what gates the first tagged release.
