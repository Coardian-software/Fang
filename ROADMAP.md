# Fang Roadmap

Last updated: 2026-09-04

## Shipped

- Single static Go binary, Cobra CLI interface
- Calibrated portfolio of 42 focused modules: CORE15 web vulnerability classes (sqli, xss, ssrf, cmdi, lfi, redirect, cors, ssti, xxe, nosqli, graphql, headers, recon, browser, inject), the KEEP tier, and new folds
- Crawl-first scanning with caps: `--max-depth` (default 2), `--max-pages` (default 200), `--crawl` to opt in
- One shared engine-owned HTTP client honoring `--proxy`, `--rate-limit`, headers, and cookies, with retry middleware
- Context-aware cancellation across the engine; graceful shutdown on Ctrl-C
- Panic-isolated module execution
- Confidence scoring kernel: STRONG/WEAK pattern classes, marker reflection, baseline delta, corroboration; weak evidence capped below Critical
- Deduplication keyed on sha1(class|host|param|path)
- Stable finding fingerprints (sha256-truncated) with first_seen, last_seen, occurrences, and an open/reopened/fixed lifecycle
- Incremental crash-safe persistence to SQLite
- GET-only probes in fold modules by design
- CI mode with `--ci` flag and `--fail-on` severity threshold for deterministic exit codes
- Unified `--format` flag across commands: JSON, SARIF, Markdown, HTML, CSV, JSONL, PDF
- JSONL streaming output for pipeline consumption
- SARIF export
- pigment embedded terminal styling engine — zero external color dependencies
- Test-hosting policy: zero test files in the repo, local quality gates only (TESTS.md)

## Next

Planned work in rough priority order:

1. **goreleaser releases v0.1.0.** Publish checksummed binaries for linux/darwin/windows on amd64 and arm64 using the `.goreleaser.yaml` in this repo. Until then, build from source.
2. **Authenticated scanning.** Session replay against logged-in targets.

## Later

Under consideration, no commitments:

- **Template data packs.** A community model for optional detection data packs, without reintroducing a runtime template DSL.

The GUI will not come back. Fang is a CLI tool for CI pipelines and terminal users.
