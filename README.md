# Fang

> Fang is the best CI-native exposure linter because calibrated findings ship from a single static binary with zero template management.

Fang is a crawl-first web exposure linter written in Go. It compiles to a single static binary that carries 42 focused detection modules covering the CORE15 web vulnerability classes plus curated fold modules. Every finding leaves the engine with a calibrated confidence score and a stable fingerprint, so results persist and reconcile across scans instead of being re-triaged from zero each run.

Fang uses an embedded terminal styling engine — **`internal/pigment`** — for all colored output. There are zero external color or styling dependencies in the dependency graph.

## How Fang compares

| | Fang | nuclei | OWASP ZAP | sqlmap |
|---|---|---|---|---|
| Core model | Static binary with a built-in, calibrated module portfolio | YAML template DSL executed by a Go engine | Proxy-centric scanner with add-ons | Targeted SQL injection tool |
| Setup burden | None. Nothing to fetch, sync, or manage | Template repos must be installed and kept current | Java runtime, proxy configuration, add-ons | Deep DBMS-specific tuning per target |
| Coverage style | Broad exposure sweep: sqli, xss, ssrf, cmdi, lfi, redirect, cors, ssti, xxe, nosqli, graphql, headers, recon, browser, inject, plus fold checks | As broad as your installed template set | Full-application scanning through the proxy | Very deep on a single vulnerability class |
| Evidence handling | Confidence kernel caps weak evidence below Critical | Severity defined per template | Plugin-defined severity | Manual analyst review |
| Cross-scan tracking | sha256 fingerprints with first_seen, last_seen, occurrences, and an open/reopened/fixed lifecycle | Per-run output | Session-scoped reports | Per-run output |
| Authenticated replay | Not yet. On the roadmap | Supported via templates | Supported | Supported with auth data |

What Fang does not try to do:

- No template DSL. Detection logic ships compiled inside the binary.
- No authenticated-session replay yet. Scans run unauthenticated today.
- Fold modules send GET-only probes by design. No destructive payloads.
- Not a replacement for a full DAST suite or a manual penetration test.

## Install

From source:

```bash
git clone https://github.com/aydocs/Fang.git
cd fang
make install
```

Requirements: Go 1.25 or newer. MIT licensed. See SECURITY.md for reporting vulnerabilities in Fang itself.

## Quickstart

```bash
fang scan run https://example.com --max-depth 2 --max-pages 200
fang findings list
```

Scan flags:

| Flag | Default | Purpose |
|---|---|---|
| `--max-depth` | `2` | Maximum crawl depth from the target URL |
| `--max-pages` | `200` | Maximum pages the crawler visits |
| `--crawl` | `false` | Enable crawl-first stage (off by default; scan only the target URL without it) |
| `--proxy` | empty | Route all engine HTTP traffic through a proxy, e.g. `http://host:port` |
| `--rate-limit` | engine default (50 rps) | Cap the shared client's global request rate |
| `--threads` | `20` | Number of concurrent scan threads |
| `--timeout` | `600` | Per-request timeout in seconds |
| `--modules` | all | Comma-separated list of module IDs to run |
| `--profile` | none | Scan profile (quick, passive, api, infra, full) |
| `--allow-private` | `false` | Permit scanning loopback, RFC1918 and link-local targets |
| `--aggressive` | `false` | Enable mutating (non-GET) probes and intrusive checks |
| `--format` | none | Output format: `json`, `sarif`, `markdown`, `html`, `csv`, `jsonl`, `pdf` |
| `--ci` | `false` | CI mode: exit 1 when findings meet `--fail-on` threshold |
| `--fail-on` | `medium` | Severity threshold for `--ci` (info, low, medium, high, critical) |

Global output flags also exist: `--no-color` disables terminal color output, `--quiet` suppresses non-essential output, and `--json` forces JSON output.

Under the hood: one shared engine-owned HTTP client honors the proxy, rate limit, custom headers, and cookies, with retry middleware applied consistently to every module. Modules run panic-isolated, so a faulty check cannot take down the scan. Context-aware cancellation stops work promptly on Ctrl-C or timeout. All findings are persisted incrementally to a local SQLite database, which makes long scans crash-safe.

## Architecture

```
main.go
├── cmd/                 Cobra CLI commands (scan, findings, modules, report, etc.)
├── internal/
│   ├── engine/         Orchestration: config, pipeline, pool, registry, crawler stage
│   ├── crawler/        Crawl-first stage: URL discovery, robots, JS extraction
│   ├── http/           Shared HTTP client (rate limiting, retries, proxy, cookies)
│   ├── db/             SQLite persistence (targets, scans, findings, schedules)
│   ├── report/         Report generation (HTML, JSON, SARIF, Markdown, PDF, CSV, JSONL)
│   ├── pigment/        Embedded terminal styling engine (zero external deps)
│   ├── detect/         Confidence scoring kernel + finding aggregation
│   ├── scheduler/      Cron-based scan scheduling + notifications
│   ├── auth/           Session/token management
│   ├── config/         Application configuration
│   ├── inject/         Payload generation (XSS, SQLi, etc.)
│   ├── integration/    Slack, Jira, SIEM, GitHub integrations
│   └── plugin/         Plugin manager
├── modules/            42 detection modules (sqli, xss, ssrf, cmdi, etc.)
├── pkg/models/         Shared data models (Finding, Severity, ScanResult, etc.)
└── templates/          YAML templates for CVEs, misconfigs, takeover
```

## Responsible use

Fang is for authorized security testing only. Run it exclusively against systems you own or have explicit written permission to test.

Scanning systems without authorization may be illegal under computer misuse and fraud laws in your jurisdiction, including but not limited to the Computer Fraud and Abuse Act in the United States, the Computer Misuse Act in the United Kingdom, and equivalent legislation elsewhere. You are solely responsible for ensuring your use of Fang complies with all applicable laws, regulations, and agreements. The authors accept no liability for misuse or for any damage caused by running this tool against targets you are not authorized to assess.

## Development

```bash
make quality      # build + vet + staticcheck (tests run locally only, never in repo)
git config core.hooksPath .githooks   # enables the pre-push hook (gofmt, vet, staticcheck, govulncheck)
```

Fang hosts zero test files in this repository by policy. Tests live in the maintainer's local tree and quality gates run locally before push. See TESTS.md for the full policy and CONTRIBUTING.md for how to submit changes.

CI runs: `go vet`, `staticcheck`, `gofmt` check, and `govulncheck` — no test jobs.
