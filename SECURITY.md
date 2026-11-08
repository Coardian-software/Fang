# Security Policy

## Reporting a Vulnerability

To report a security vulnerability, use a GitHub Security Advisory for this
repository. If private reporting is unavailable, contact the repository
maintainers through GitHub before opening a public issue.

Do not disclose security vulnerabilities publicly until they have been addressed by the maintainers.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Scope and limitations

Fang is a local CLI scanner, not an authenticated multi-tenant service. Its
database and reports can contain sensitive target URLs, evidence, requests,
and responses; treat them as confidential. Do not run scans without
authorization.

The project does not promise a response-time SLA. Maintainers will triage
reports as capacity allows and coordinate disclosure with the reporter.
