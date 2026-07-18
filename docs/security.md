# Security and production deployment

## Required controls

- Run a supported Node.js release (22 or 24 LTS) and Redis 7 or newer.
- Supply `JWT_SECRET` through the host's secret manager. Use at least 32 random bytes; rotate it
  using an application-controlled rollout.
- Use TLS to Redis with a `rediss://` URL, authentication, network isolation, and least privilege.
- Terminate HTTPS at the application or a trusted proxy.
- Keep access tokens short-lived. The defaults are 15 minutes for access and seven days for
  refresh/session state.
- Apply `rateLimit()` to authentication endpoints or use an equivalent distributed gateway
  limiter. It stores counters in Redis and fails through Express error handling if Redis fails.
- Call `closeRedisConnection()` from host-owned shutdown handling. This package never installs
  signal listeners and never exits the process.

## Supported environment variables

| Variable                      | Default                            | Purpose                                            |
| ----------------------------- | ---------------------------------- | -------------------------------------------------- |
| `JWT_SECRET`                  | none                               | HMAC secret, minimum 32 characters                 |
| `JWT_ACCESS_TOKEN_EXPIRY`     | `15m`                              | Access JWT lifetime                                |
| `JWT_REFRESH_TOKEN_EXPIRY`    | `7d`                               | Refresh JWT lifetime                               |
| `JWT_ISSUER`                  | `jwt-redis-sessions`               | Required issuer claim                              |
| `JWT_AUDIENCE`                | `jwt-redis-sessions-users`         | Required audience claim                            |
| `REDIS_URL`                   | `redis://localhost:6379`           | Redis URL; use `rediss://` for TLS                 |
| `REDIS_PASSWORD`              | none                               | Redis password when not embedded in URL            |
| `REDIS_DB`                    | `0`                                | Redis database                                     |
| `REDIS_KEY_PREFIX`            | `jwt-redis-sessions:`              | Key namespace                                      |
| `SESSION_TTL`                 | `604800`                           | Sliding session TTL in seconds                     |
| `REFRESH_TOKEN_TTL`           | `604800`                           | Refresh digest TTL in seconds                      |
| `TOKEN_LENGTH`                | `32`                               | Random session ID bytes                            |
| `JWT_ALLOWED_TOKEN_FIELDS`    | `userId,id,email,role,permissions` | Payload allowlist                                  |
| `ENABLE_TOKEN_FINGERPRINTING` | `true`                             | Add request fingerprint when a request is supplied |
| `FINGERPRINT_STRICT_MODE`     | `false`                            | Reject fingerprint mismatches                      |

`REDIS_SSL`, `MAX_LOGIN_ATTEMPTS`, `LOCKOUT_TIME`, and `BCRYPT_ROUNDS` are not supported. Put TLS
in `REDIS_URL`, and configure rate-limit arguments in application code.

## Cookie and token transport

Access tokens are bearer credentials. Send them only in an `Authorization: Bearer` header over
HTTPS. If a browser stores refresh tokens in cookies, use `HttpOnly`, `Secure`, an appropriate
`SameSite` policy, a narrow `Path`, and CSRF protection whenever cookies may be sent cross-site.
Do not put tokens in URLs, logs, analytics events, or local storage for high-risk applications.

Redis stores SHA-256 refresh digests and uses SHA-256 token digests in blacklist key names. Redis
session records still contain the explicitly allowed identity/authorization fields, so Redis data
must be treated as confidential. Refresh rotation and activity updates use atomic Redis scripts;
logout-all also retains small hashed per-user revocation-generation keys without a TTL. Do not
delete those generation keys independently while tokens signed by the same JWT secret may exist.

## Host-owned lifecycle

```js
require('dotenv').config() // optional and controlled by the application
const sessions = require('jwt-redis-sessions')

await sessions.initialize()

process.once('SIGTERM', async () => {
  await sessions.closeRedisConnection()
  // The application decides when and how to exit.
})
```

An already connected Redis client can be supplied with
`initialize({ redisClient: client })`. The package will not close a client it does not own.
