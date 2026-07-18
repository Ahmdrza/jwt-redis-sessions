# Migrating from 2.x to 3.0.0

## Security hardening release

This release intentionally changes insecure behavior:

1. The package no longer loads `.env`. Load it in the application before importing this package,
   or inject environment variables through the deployment platform.
2. The package no longer installs `SIGINT`/`SIGTERM` handlers or calls `process.exit()`. Application
   shutdown code must call `closeRedisConnection()`.
3. Token data is allowlisted and primitive-only. The default fields are `userId`, `id`, `email`,
   `role`, and `permissions`. Add intentionally reviewed fields with
   `JWT_ALLOWED_TOKEN_FIELDS`; remove passwords, hashes, secrets, credentials, and nested objects.
4. Existing plaintext refresh values are incompatible with digest comparison. Users must sign in
   again after deployment, or old refresh sessions should be invalidated before rollout.
5. Refresh rotation keeps the same session ID, increments an internal session version, invalidates
   access tokens from the prior version, and permits only one concurrent refresh. Do not treat a
   session ID change as evidence that rotation occurred.
6. User-session lookup now uses hashed Redis set indexes. Sessions created by older releases will
   not appear in `getUserSessions()`; invalidate old keys or require reauthentication.
7. `auth` exposes the single verification result at `req.auth.decoded` and `req.auth.session`.
   Remove duplicate `verifyToken()` calls in protected routes.
8. `rateLimit()` is asynchronous and Redis-backed. Express handles it normally; custom callers and
   tests must await the returned middleware.
9. The default `SESSION_TTL` is seven days, matching refresh state. Review explicit shorter values.
10. Supported production runtimes are Node.js 22 and 24 LTS and Redis 7 or newer.
11. Logout-all now stores persistent, hashed per-user revocation-generation keys. These small keys
    intentionally outlive session TTLs so an older token can never become valid again.

Before rollout, delete legacy keys under the configured package prefix during a maintenance window
or change `REDIS_KEY_PREFIX` to start with an empty namespace. This forces reauthentication and
avoids mixed storage formats.
