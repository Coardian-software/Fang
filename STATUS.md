# Fang Status

Last updated: 2026-09-04

## Current state

Fang is a post-GUI, CLI-only project. The frontend was removed and the interface is a Cobra command line (`fang scan run`, `fang findings`, `fang modules`, `fang report`, `fang export`). The engine underneath has been rebuilt around calibration, stable tracking, and safe defaults.

## What ships today

### Module portfolio

42 focused modules, calibrated down from a larger unfiltered set:

- CORE15 web vulnerability classes: sqli, xss, ssrf, cmdi, lfi, redirect, cors, ssti, xxe, nosqli, graphql, headers, recon, browser, inject
- KEEP tier: modules retained after the calibration pass
- New folds: narrow, single-purpose checks that complement the CORE15 set (central, cicd, cloud, crlf, deser, docker, evasion, exposure, git, helm, k8s, ldap, method, npm, oidc, proto, race, rest, sbom, serverless, smuggler, soap, terraform, websocket, xpath)

Fold modules send GET-only probes by design.

### Crawler

Crawl-first scanning with hard caps: `--max-depth` (default 2), `--max-pages` (default 200), and `--crawl` to opt in (crawling is off by default for safe, minimal-footprint scans).

### HTTP client

One shared, engine-owned HTTP client serves every module. It honors `--proxy`, `--rate-limit`, custom headers, and cookies, and applies retry middleware uniformly. No module opens its own sockets.

### Engine runtime

- Context-aware cancellation throughout; Ctrl-C and timeouts stop work promptly (graceful shutdown)
- Panic-isolated module execution; a faulty check cannot take down the scan
- `--aggressive` flag gates mutating probes; off by default
- `--allow-private` flag gates loopback/RFC1918/link-local targets; off by default

### Detection kernel

A confidence scoring kernel sits between raw evidence and reported severity:

- STRONG and WEAK pattern classes
- Marker reflection checks
- Baseline delta comparison
- Cross-module corroboration
- Weak evidence is capped below Critical regardless of pattern match
- Deduplication keyed on sha1(class|host|param|path)

### Finding lifecycle

Findings carry stable fingerprints (sha256-truncated) and persist across scans with first_seen, last_seen, occurrence counts, and an open/reopened/fixed lifecycle.

### Persistence

Incremental, crash-safe writes to a local SQLite database at `~/.fang/data/fang.db`. A killed scan keeps everything it already recorded.

### Reporting

Unified `--format` flag supports: JSON, SARIF, Markdown, HTML, CSV, JSONL, and PDF (via headless Chromium). CI mode (`--ci` + `--fail-on`) provides deterministic exit codes for pipelines.

### Terminal styling

All colored terminal output uses the embedded `internal/pigment` engine — zero external color dependencies in the module graph.

## Project facts

- Language: Go, single static binary
- Go version: 1.25+
- License: MIT
- Security policy: SECURITY.md
- Testing: zero test files hosted in the repo; quality gates (gofmt, vet, staticcheck, govulncheck) run locally via `make quality` and the pre-push hook. See TESTS.md.
- CI: `go vet`, `staticcheck`, `gofmt` check, `govulncheck` — no test jobs
