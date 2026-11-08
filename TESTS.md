# Testing Policy

Tests are first-class repository artifacts. They use synthetic HTTP servers
and fixtures only; customer targets, reports, credentials, and real response
data stay outside the repository.

- Quality gates run locally and in CI:
  - `make quality` (build + vet + tests)
  - `make conformance` (module-contract harness)
  - the `.githooks/pre-push` hook enforces gofmt + vet + staticcheck + tests
    automatically (`git config core.hooksPath .githooks` is required once after
    clone).
- CI also runs unit tests, race tests, dependency scanning, build, and Docker
  startup smoke tests.

## Contributing

Pull requests should include a focused regression test and a **reproduction
recipe** (target behavior, command line used, observed vs expected output).
