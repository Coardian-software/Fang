# Contributing to Fang

Thanks for wanting to help. This document covers what a good contribution looks like and the gates it must pass.

## Setup

You need Go 1.26 or newer. No Node.js, no frontend, no other toolchains.

```bash
git clone https://github.com/aydocs/fang.git
cd fang
go mod tidy
make build
```

Enable the pre-push hook once after cloning:

```bash
git config core.hooksPath .githooks
```

## Pull requests include regression tests

When your change fixes or adds behavior, include a focused `*_test.go` regression test and a **reproduction recipe** in the PR description:

- The target behavior or vulnerability class involved
- The exact command line you ran (flags included)
- Observed output before the change
- Expected output after the change

Tests are part of the public contract and run in CI. Do not include real customer targets, scan reports, credentials, or production response data in fixtures.

## Local quality gates are required

Before every push:

```bash
make quality        # build + vet + tests
make conformance    # module-contract harness
```

The pre-push hook enforces gofmt, vet, staticcheck, and tests automatically once `core.hooksPath` is set to `.githooks`. If the hook rejects your push, fix the issue and push again; do not bypass it.

CI runs lint, govulncheck, and build only. It is not a substitute for the local gates.

## Commit style

Use conventional commits:

```
feat(scan): add --no-crawl flag to skip crawler stage
fix(detect): cap weak-evidence sqli findings below critical
docs(readme): update quickstart flags table
refactor(engine): extract retry middleware into shared client
chore(deps): bump spf13/cobra
```

Types in use: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`. Keep the subject line imperative and under 72 characters.

## Module development

Detection modules implement the engine's module contract and register themselves under `modules/`. The engine handles scheduling, HTTP traffic, persistence, and panic isolation; a module focuses on detection logic.

Rules of thumb:

- Route all HTTP through the shared engine client. Never open your own sockets.
- Fold modules send GET-only probes by design. No destructive payloads.
- Respect context cancellation; check `ctx.Done()` in loops.
- Emit evidence honestly. The confidence kernel caps weak evidence below Critical, but garbage evidence still wastes everyone's time.

## Code standards

- gofmt-clean, idiomatic Go
- `go vet ./...` passes
- All text in English
- Meaningful names over comments

## Reporting issues

Use the GitHub issue tracker. Include steps to reproduce, expected behavior, and actual behavior. For security issues in Fang itself, follow SECURITY.md instead of opening a public issue.
