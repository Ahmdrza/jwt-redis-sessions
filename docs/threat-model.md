# Threat model

## Protected assets

- JWT signing secret
- access and refresh bearer credentials
- active sessions and authorization claims
- user identifiers stored in session records

## Defended attacks

- Refresh replay and concurrent logout: a versioned Redis compare-and-swap atomically checks the
  current refresh digest and session version before replacing both records. Refresh, replay, and
  logout therefore have one winner across processes.
- Redis credential disclosure: refresh tokens are stored as SHA-256 digests; complete access
  tokens are not embedded in blacklist keys.
- Payload confusion/leakage: an allowlist, reserved-claim checks, primitive-only values, and a
  4 KiB limit prevent arbitrary user/database objects from becoming credentials or sessions.
- Algorithm/type confusion: verification requires HS256, configured issuer/audience, expiration,
  and the expected access/refresh type.
- Logout/session revocation: access verification requires a live Redis session and checks the
  blacklist. Its activity update is conditional on the current session version and per-user
  revocation generation, so it cannot recreate a concurrently revoked session. Redis failures
  fail closed.
- Logout-all: a persistent per-user revocation generation is incremented before session cleanup.
  Tokens issued against an older generation stay invalid even if cleanup races with verification.
- Brute-force distribution: rate-limit counters are shared in Redis rather than process memory.

## Trust boundaries and residual risks

- A stolen access token is usable until it expires or its session is revoked. Use short access
  lifetimes and HTTPS.
- SHA-256 protects high-entropy tokens, not low-entropy user identifiers from offline guessing.
  User-index keys hide casual PII exposure but Redis remains confidential infrastructure.
- HMAC gives every verifier signing capability. Restrict the secret; choose an asymmetric token
  design if independent verifiers must not sign.
- Fingerprints are a risk signal, not a device identity. Strict mode can reject legitimate network
  or browser changes; non-strict mode only warns.
- Application authorization must still validate current roles/permissions where immediate policy
  changes matter.
- The host controls proxy trust, CSRF defenses, cookies, CORS, logging, monitoring, and shutdown.

## Security invariants covered by tests

The test suite checks concurrent refresh replay, forced refresh-versus-logout and
verify-versus-logout-all interleavings, digest-only Redis storage/keying, old-session invalidation,
indexed lookups without keyspace scans, cross-instance rate limiting, fail-closed blacklist
behavior, strict payload validation, auth-context attachment, and import lifecycle safety. The
concurrency cases run against both deterministic test doubles and Redis 7.
