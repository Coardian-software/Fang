# Testing Policy

Fang hosts **zero** test files in this repository — by design.

- All `*_test.go` and `testdata/` live only in the maintainer's local working
  tree and are excluded via `.gitignore`.
- Quality gates run **locally** before every push:
  - `make quality` (build + vet + tests)
  - `make conformance` (module-contract harness)
  - the `.githooks/pre-push` hook enforces gofmt + vet + staticcheck + tests
    automatically (`git config core.hooksPath .githooks` is required once after
    clone).
- CI (GitHub Actions) runs lint, govulncheck, and build only.

## Contributing

Pull requests should include a **reproduction recipe** (target behavior,
command line used, observed vs expected output) instead of test files — any
test-shaped file in a PR will be rejected by policy.
