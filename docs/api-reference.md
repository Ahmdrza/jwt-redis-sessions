# API Reference

## Token Management

### `generateToken(data: TokenData): Promise<TokenResponse>`

Generate access and refresh tokens.

**Important for revokeAllUserTokens functionality:**
Your token data must include at least one of these fields:

- `userId`
- `id`
- `email`

This is required for the `revokeAllUserTokens` function to identify and revoke all sessions for a user.

```javascript
const tokens = await generateToken({
  userId: 'user123',     // Used by revokeAllUserTokens
  email: 'user@example.com',
  role: 'admin',         // Additional custom data
  permissions: ['read', 'write']
})

// Returns:
{
  accessToken: 'eyJhbGc...',
  refreshToken: 'eyJhbGc...',
  expiresIn: '15m',
  tokenType: 'Bearer'
}
```

### `refreshToken(refreshToken: string): Promise<TokenResponse>`

Refresh an access token using a refresh token.

```javascript
const newTokens = await refreshToken(oldRefreshToken)
```

### `revokeToken(token: string): Promise<{ success: boolean, message: string }>`

Revoke a specific token.

```javascript
await revokeToken(accessToken)
```

### `revokeAllUserTokens(userIdentifier: string): Promise<{ success: boolean, message: string }>`

Revoke all tokens for a specific user.

```javascript
await revokeAllUserTokens('user123')
```

## Middleware

### `auth`

Main authentication middleware. It verifies once and attaches the result to `req.auth`.

```javascript
app.get('/protected', auth, async (req, res) => {
  console.log(req.auth.decoded) // User data
  console.log(req.auth.session) // Session data
})
```

### `rateLimit(maxAttempts?, windowMs?)`

Rate limiting middleware to prevent brute force attacks.

```javascript
// Default: 5 attempts per 15 minutes
app.post('/login', rateLimit(), loginHandler)

// Custom: 10 attempts per 5 minutes
app.post('/api', rateLimit(10, 5 * 60 * 1000), handler)
```

## Advanced Usage

### Custom Error Handling

The library provides custom error classes for better error handling:

```javascript
const { AuthError, ValidationError, TokenError, RedisError } = require('jwt-redis-sessions')

app.use((err, req, res, next) => {
  if (err instanceof TokenError) {
    return res.status(401).json({
      error: 'Token Error',
      message: err.message,
    })
  }

  if (err instanceof ValidationError) {
    return res.status(400).json({
      error: 'Validation Error',
      message: err.message,
    })
  }

  // Handle other errors
  res.status(500).json({ error: 'Internal Server Error' })
})
```

### Session Management

Get all active sessions for a user:

```javascript
const sessions = await getUserSessions('user123')
console.log(sessions)
// [
//   {
//     sessionId: 'abc123...',
//     userId: 'user123',
//     createdAt: '2024-01-01T00:00:00.000Z',
//     lastActivity: '2024-01-01T01:00:00.000Z',
//     ...
//   }
// ]
```

### Manual Initialization

By default, Redis is initialized on first use. You can initialize explicitly, optionally with an
already-connected client. Externally supplied clients are not closed by the package.

```javascript
const { createClient } = require('redis')
const { initialize, closeRedisConnection } = require('jwt-redis-sessions')

const redisClient = createClient({ url: process.env.REDIS_URL })
await redisClient.connect()
await initialize({ redisClient })

// Graceful shutdown
process.on('SIGTERM', async () => {
  await closeRedisConnection()
  await redisClient.quit()
  // The host application decides whether and when to exit.
})
```

### Explicit Configuration

Call `configure()` before initialization, or pass the same overrides to `initialize({ config })`.
Unknown options and invalid values are rejected, and configuration cannot change after initialization.

```javascript
const sessions = require('jwt-redis-sessions')

sessions.configure({
  jwt: {
    secret: process.env.JWT_SECRET,
    issuer: 'accounts-api',
    audience: 'accounts-users',
  },
  redis: {
    url: 'rediss://redis.internal:6380',
    keyPrefix: 'accounts:sessions:',
  },
  security: {
    allowedTokenFields: ['userId', 'email', 'role', 'permissions'],
  },
})
```

## TypeScript Support

The library includes comprehensive TypeScript definitions:

```typescript
import { generateToken, auth, TokenData, TokenResponse } from 'jwt-redis-sessions'

app.post('/login', async (req, res) => {
  const userData: TokenData = {
    userId: 'user123',
    email: 'user@example.com',
  }

  const tokens: TokenResponse = await generateToken(userData)
  res.json(tokens)
})

app.get('/profile', auth, async (req, res) => {
  res.json({ user: req.auth?.decoded, session: req.auth?.session })
})
```

## Error Handling

The library throws specific error types for different scenarios:

- `AuthError` - General authentication errors
- `TokenError` - Token-specific errors (invalid, expired, etc.)
- `ValidationError` - Input validation errors
- `RedisError` - Redis connection or operation errors
