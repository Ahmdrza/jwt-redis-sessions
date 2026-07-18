# Security policy

## Supported versions

Only the latest release line is supported with security fixes. Production runtimes are Node.js 22
and 24 LTS with Redis 7 or newer. End-of-life Node.js releases are not supported.

## Reporting a vulnerability

Please use GitHub private vulnerability reporting for this repository. Do not open a public issue
containing exploit details, live tokens, secrets, Redis URLs, or user data. Include affected
versions, impact, reproduction steps, and any suggested mitigation. Maintainers should acknowledge
the report within seven days and coordinate disclosure after a fix is available.

See [docs/security.md](docs/security.md) and [docs/threat-model.md](docs/threat-model.md) for the
deployment model and security boundaries.
