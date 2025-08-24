# jwt-redis-sessions

A secure, production-ready JWT authentication and session management library for Node.js applications using Redis as the session store.

## Features

- 🔐 **Secure JWT Implementation** - Proper token generation with configurable expiration
- 🔄 **Refresh Token Rotation** - Automatic refresh token rotation for enhanced security
- 🚪 **Session Management** - Redis-based session storage with automatic cleanup
- 🛡️ **Token Revocation** - Logout functionality with token blacklisting
- ⚡ **Rate Limiting** - Built-in rate limiting middleware
- 🔍 **TypeScript Support** - Full TypeScript definitions included
- 🚨 **Error Handling** - Comprehensive error handling with custom error classes
- 🔧 **Configurable** - Extensive configuration options via environment variables

## Prerequisites

- **Node.js** 14.0 or higher
- **Redis** 6.0 or higher (running locally or accessible via URL)
- **npm** or **yarn** package manager

## Installation

```bash
npm install jwt-redis-sessions
# or
yarn add jwt-redis-sessions
```

## Quick Start Guide

### 1. Start Redis Server

Make sure Redis is running on your system:

```bash
# On macOS with Homebrew
brew services start redis

# On Ubuntu/Debian
sudo systemctl start redis-server

# On Windows, download and run Redis from official website
# Or use Docker:
docker run -d -p 6379:6379 redis:7-alpine
```

### 2. Set up environment variables

Create a `.env` file in your project root:

```env
# Required: Strong JWT secret (minimum 32 characters)
JWT_SECRET=your-super-secure-jwt-secret-key-with-at-least-32-characters-for-production

# Redis connection (default: redis://localhost:6379)
REDIS_URL=redis://localhost:6379

# Optional: Token expiration times
JWT_ACCESS_TOKEN_EXPIRY=15m
JWT_REFRESH_TOKEN_EXPIRY=7d
```

> 🔒 **Security Note**: Generate a cryptographically secure JWT secret in production using:
>
> ```bash
> node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
> ```

See [.env.example](.env.example) for all available options.

### 3. Basic Usage

```javascript
const express = require('express')
const { generateToken, auth, logout } = require('jwt-redis-sessions')

const app = express()
app.use(express.json())

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    // Validate user credentials here
    const user = {
      id: 'user123',
      email: 'user@example.com',
    }

    // Generate tokens
    const tokens = await generateToken(user)

    res.json(tokens)
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// Protected route
app.get('/profile', auth, (req, res) => {
  res.json({
    message: 'This is a protected route',
    user: req.user,
    session: req.session,
  })
})

// Logout
app.post('/logout', auth, logout)

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000')
})
```

### 4. Complete Working Example

Here's a full authentication system example:

```javascript
// server.js
require('dotenv').config()
const express = require('express')
const bcrypt = require('bcrypt') // npm install bcrypt
const {
  generateToken,
  auth,
  optionalAuth,
  rateLimit,
  logout,
  logoutAll,
  refresh,
} = require('jwt-redis-sessions')

const app = express()
app.use(express.json())

// Mock user database (use your real database)
const users = [
  {
    id: 'user1',
    email: 'alice@example.com',
    password: '$2b$10$eQ8qIz7jnTxYo8bv5YNB9u7a8IZRvQz3cQ8x1xZYIZRvQz3cQ8x1x', // password: 'test123'
  },
]

// Register endpoint
app.post('/register', rateLimit(3, 60000), async (req, res) => {
  try {
    const { email, password } = req.body

    // Check if user exists
    if (users.find((u) => u.email === email)) {
      return res.status(400).json({ error: 'User already exists' })
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10)
    const newUser = {
      id: `user${users.length + 1}`,
      email,
      password: hashedPassword,
    }
    users.push(newUser)

    // Generate tokens
    const tokens = await generateToken({
      userId: newUser.id,
      email: newUser.email,
    })

    res.status(201).json({
      message: 'User registered successfully',
      user: { id: newUser.id, email: newUser.email },
      tokens,
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// Login endpoint
app.post('/login', rateLimit(), async (req, res) => {
  try {
    const { email, password } = req.body

    // Find user
    const user = users.find((u) => u.email === email)
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }

    // Generate tokens
    const tokens = await generateToken({
      userId: user.id,
      email: user.email,
    })

    res.json({
      message: 'Login successful',
      user: { id: user.id, email: user.email },
      tokens,
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// Protected routes
app.get('/profile', auth, (req, res) => {
  res.json({
    message: 'Profile data',
    user: req.user,
    sessionInfo: {
      sessionId: req.session.sessionId,
      createdAt: req.session.createdAt,
      lastActivity: req.session.lastActivity,
    },
  })
})

// Public route with optional authentication
app.get('/public', optionalAuth, (req, res) => {
  res.json({
    message: 'This is public content',
    authenticated: !!req.user,
    user: req.user || null,
  })
})

// Token management
app.post('/refresh', refresh)
app.post('/logout', auth, logout)
app.post('/logout-all', auth, logoutAll)

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() })
})

// Error handling
app.use((err, req, res, next) => {
  console.error(err)
  res.status(err.statusCode || 500).json({
    error: err.message || 'Internal server error',
  })
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`)
  console.log(`📊 Endpoints available:`)
  console.log(`   POST /register - Register new user`)
  console.log(`   POST /login - Login user`)
  console.log(`   GET  /profile - Protected profile (requires auth)`)
  console.log(`   GET  /public - Public content (optional auth)`)
  console.log(`   POST /refresh - Refresh tokens`)
  console.log(`   POST /logout - Logout current session`)
  console.log(`   POST /logout-all - Logout all sessions`)
})
```

### 5. Test the API

```bash
# Register a new user
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"test123"}'

# Login (get tokens)
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"test123"}'

# Access protected route (replace YOUR_ACCESS_TOKEN)
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:3000/profile

# Refresh tokens (replace YOUR_REFRESH_TOKEN)
curl -X POST http://localhost:3000/refresh \
  -H "Authorization: Bearer YOUR_REFRESH_TOKEN"

# Logout
curl -X POST http://localhost:3000/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Troubleshooting

### Common Issues

#### 1. "JWT_SECRET must be at least 32 characters long"

**Problem**: Your JWT secret is too short.

**Solution**: Generate a secure 32+ character secret:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

#### 2. "Redis client not initialized or not connected"

**Problem**: Redis server is not running or not accessible.

**Solutions**:

- **Check Redis is running**: `redis-cli ping` (should return "PONG")
- **Start Redis**:
  - macOS: `brew services start redis`
  - Ubuntu: `sudo systemctl start redis-server`
  - Docker: `docker run -d -p 6379:6379 redis:7-alpine`
- **Check connection URL**: Verify `REDIS_URL` in your `.env` file

#### 3. "Token has been revoked" errors

**Problem**: Using tokens after logout or token revocation.

**Solution**:

- Get new tokens via `/login` or `/refresh` endpoint
- Check if logout was called on the token
- Verify token hasn't expired

#### 4. Rate limiting triggers too quickly

**Problem**: Rate limiting is blocking legitimate requests.

**Solutions**:

```javascript
// Increase limits for specific endpoints
app.post('/login', rateLimit(10, 5 * 60 * 1000), loginHandler) // 10 attempts per 5 mins

// Or disable for development
if (process.env.NODE_ENV !== 'production') {
  app.post('/login', loginHandler) // No rate limiting in dev
}
```

#### 5. CORS issues in browser

**Problem**: Cross-origin requests blocked.

**Solution**: Add CORS middleware:

```javascript
const cors = require('cors') // npm install cors
app.use(
  cors({
    origin: ['http://localhost:3000', 'https://yourapp.com'],
    credentials: true,
  })
)
```

#### 6. TypeScript import errors

**Problem**: TypeScript can't find type definitions.

**Solution**: Import types explicitly:

```typescript
import type { AuthRequest, TokenData } from 'jwt-redis-sessions'
```

### Debugging Tips

#### Enable Debug Logging

```javascript
// Add to your .env file
NODE_ENV = development

// The library will include stack traces in error responses
```

#### Check Redis Keys

```bash
# Connect to Redis CLI
redis-cli

# List all session keys
KEYS jwt-redis-sessions:*

# Check specific session
GET jwt-redis-sessions:session:your-session-id

# Check blacklisted tokens
KEYS jwt-redis-sessions:blacklist:*
```

#### Verify Token Content

```javascript
const jwt = require('jsonwebtoken')

// Decode token without verification (for debugging only)
const decoded = jwt.decode(token, { complete: true })
console.log('Token header:', decoded.header)
console.log('Token payload:', decoded.payload)
```

## API Reference

### Token Management

#### `generateToken(data: TokenData): Promise<TokenResponse>`

Generate access and refresh tokens.

```javascript
const tokens = await generateToken({
  userId: 'user123',
  email: 'user@example.com'
})

// Returns:
{
  accessToken: 'eyJhbGc...',
  refreshToken: 'eyJhbGc...',
  expiresIn: '15m',
  tokenType: 'Bearer'
}
```

#### `refreshToken(refreshToken: string): Promise<TokenResponse>`

Refresh an access token using a refresh token.

```javascript
const newTokens = await refreshToken(oldRefreshToken)
```

#### `revokeToken(token: string): Promise<{ success: boolean, message: string }>`

Revoke a specific token.

```javascript
await revokeToken(accessToken)
```

#### `revokeAllUserTokens(userId: string): Promise<{ success: boolean, message: string }>`

Revoke all tokens for a specific user.

```javascript
await revokeAllUserTokens('user123')
```

### Middleware

#### `auth`

Main authentication middleware that validates tokens and attaches user info to the request.

```javascript
app.get('/protected', auth, (req, res) => {
  console.log(req.user) // Decoded JWT payload
  console.log(req.session) // Session data from Redis
  console.log(req.token) // The actual token
})
```

#### `optionalAuth`

Optional authentication that doesn't fail if no token is provided.

```javascript
app.get('/public', optionalAuth, (req, res) => {
  if (req.user) {
    // User is authenticated
  } else {
    // User is not authenticated
  }
})
```

#### `rateLimit(maxAttempts?, windowMs?)`

Rate limiting middleware to prevent brute force attacks.

```javascript
// Default: 5 attempts per 15 minutes
app.post('/login', rateLimit(), loginHandler)

// Custom: 10 attempts per 5 minutes
app.post('/api', rateLimit(10, 5 * 60 * 1000), handler)
```

### Handlers

#### `logout`

Logout handler that revokes the current token.

```javascript
app.post('/logout', auth, logout)
```

#### `logoutAll`

Logout handler that revokes all tokens for the authenticated user.

```javascript
app.post('/logout-all', auth, logoutAll)
```

#### `refresh`

Refresh token handler.

```javascript
app.post('/refresh', refresh)
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

By default, Redis connection is initialized on first use. You can manually initialize:

```javascript
const { initialize, closeRedisConnection } = require('jwt-redis-sessions')

// Initialize
await initialize()

// Graceful shutdown
process.on('SIGTERM', async () => {
  await closeRedisConnection()
  process.exit(0)
})
```

## Configuration

All configuration is done through environment variables. See [.env.example](.env.example) for all options.

### JWT Configuration

- `JWT_SECRET` - Secret key for signing tokens (required, min 32 chars)
- `JWT_ACCESS_TOKEN_EXPIRY` - Access token expiration (default: '15m')
- `JWT_REFRESH_TOKEN_EXPIRY` - Refresh token expiration (default: '7d')
- `JWT_ISSUER` - Token issuer (default: 'jwt-redis-sessions')
- `JWT_AUDIENCE` - Token audience (default: 'jwt-redis-sessions-users')

### Redis Configuration

- `REDIS_URL` - Redis connection URL (default: 'redis://localhost:6379')
- `REDIS_HOST` - Redis host (default: 'localhost')
- `REDIS_PORT` - Redis port (default: 6379)
- `REDIS_PASSWORD` - Redis password (optional)
- `REDIS_DB` - Redis database number (default: 0)
- `REDIS_KEY_PREFIX` - Prefix for Redis keys (default: 'jwt-redis-sessions:')

### Security Configuration

- `MAX_LOGIN_ATTEMPTS` - Max login attempts for rate limiting (default: 5)
- `LOCKOUT_TIME` - Lockout time in seconds (default: 900)
- `TOKEN_LENGTH` - Length of generated tokens (default: 32)

## Security Best Practices & Production Deployment

### 🔒 Essential Security Requirements

1. **Strong JWT Secret**:

   ```bash
   # Generate in production:
   JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
   ```

2. **HTTPS Only**: Always use HTTPS in production

   ```javascript
   // Redirect HTTP to HTTPS
   app.use((req, res, next) => {
     if (req.header('x-forwarded-proto') !== 'https') {
       res.redirect(`https://${req.header('host')}${req.url}`)
     } else {
       next()
     }
   })
   ```

3. **Secure Redis Connection**:

   ```env
   # Use SSL/TLS in production
   REDIS_URL=rediss://username:password@redis-host:6380

   # Or with explicit SSL config
   REDIS_SSL=true
   REDIS_HOST=your-redis-host.com
   REDIS_PORT=6380
   REDIS_PASSWORD=your-secure-password
   ```

4. **Environment-Based Configuration**:

   ```env
   # Production settings
   NODE_ENV=production
   JWT_ACCESS_TOKEN_EXPIRY=15m    # Short access token lifetime
   JWT_REFRESH_TOKEN_EXPIRY=7d    # Reasonable refresh token lifetime
   SESSION_TTL=86400              # 24 hours
   MAX_LOGIN_ATTEMPTS=3           # Strict rate limiting
   LOCKOUT_TIME=1800             # 30 minutes lockout
   ```

5. **Security Headers**:

   ```javascript
   const helmet = require('helmet') // npm install helmet

   app.use(
     helmet({
       contentSecurityPolicy: {
         directives: {
           defaultSrc: ["'self'"],
           styleSrc: ["'self'", "'unsafe-inline'"],
           scriptSrc: ["'self'"],
           imgSrc: ["'self'", 'data:', 'https:'],
         },
       },
       hsts: {
         maxAge: 31536000, // 1 year
         includeSubDomains: true,
         preload: true,
       },
     })
   )
   ```

### 🚀 Production Deployment Checklist

#### Before Deployment

- [ ] Generate secure `JWT_SECRET` (32+ characters)
- [ ] Configure Redis with SSL/TLS and authentication
- [ ] Set up proper CORS origins
- [ ] Enable rate limiting on all auth endpoints
- [ ] Configure secure session and cookie settings
- [ ] Set up monitoring and logging
- [ ] Test token refresh flows
- [ ] Verify logout functionality works correctly

#### Production Environment Variables

```env
# Security
NODE_ENV=production
JWT_SECRET=your-64-character-hex-secret-here
JWT_ACCESS_TOKEN_EXPIRY=15m
JWT_REFRESH_TOKEN_EXPIRY=7d

# Redis (with SSL)
REDIS_URL=rediss://username:password@your-redis-host.com:6380

# Rate Limiting
MAX_LOGIN_ATTEMPTS=3
LOCKOUT_TIME=1800

# Sessions
SESSION_TTL=86400
REFRESH_TOKEN_TTL=604800

# Optional: Custom configuration
JWT_ISSUER=your-app-name
JWT_AUDIENCE=your-app-users
REDIS_KEY_PREFIX=your-app:jwt:
```

#### Production Monitoring

```javascript
// Monitor authentication events
const { generateToken, revokeToken } = require('jwt-redis-sessions')

// Add logging wrapper
const originalGenerateToken = generateToken
const generateTokenWithLogging = async (data) => {
  const result = await originalGenerateToken(data)
  console.log(`Token generated for user: ${data.userId || data.id}`)
  // Send to your monitoring service
  return result
}

// Monitor failed authentication attempts
app.use((err, req, res, next) => {
  if (err.statusCode === 401) {
    console.log(`Failed auth attempt from ${req.ip}:`, {
      url: req.url,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString(),
    })
    // Alert on suspicious patterns
  }
  next(err)
})
```

### 🛡️ Advanced Security Features

#### 1. Token Binding (Optional)

```javascript
// Bind tokens to IP address
app.use('/auth', (req, res, next) => {
  req.clientIP = req.ip || req.connection.remoteAddress
  next()
})

// Include IP in token payload
const tokens = await generateToken({
  userId: user.id,
  email: user.email,
  boundIP: req.clientIP,
})

// Verify IP binding in middleware
app.use(auth, (req, res, next) => {
  if (req.user.boundIP && req.user.boundIP !== req.clientIP) {
    return res.status(401).json({ error: 'Token IP binding mismatch' })
  }
  next()
})
```

#### 2. Suspicious Activity Detection

```javascript
// Track failed attempts per IP
const suspiciousIPs = new Map()

app.use((err, req, res, next) => {
  if (err.statusCode === 401) {
    const ip = req.ip
    const attempts = suspiciousIPs.get(ip) || 0
    suspiciousIPs.set(ip, attempts + 1)

    // Block after many failures
    if (attempts > 20) {
      return res.status(429).json({ error: 'IP temporarily blocked' })
    }
  }
  next(err)
})
```

## TypeScript Support

The library includes comprehensive TypeScript definitions:

```typescript
import { generateToken, auth, AuthRequest, TokenData, TokenResponse } from 'jwt-redis-sessions'

app.post('/login', async (req, res) => {
  const userData: TokenData = {
    userId: 'user123',
    email: 'user@example.com',
  }

  const tokens: TokenResponse = await generateToken(userData)
  res.json(tokens)
})

app.get('/profile', auth, (req: AuthRequest, res) => {
  res.json({ user: req.user })
})
```

## Error Handling

The library throws specific error types for different scenarios:

- `AuthError` - General authentication errors
- `TokenError` - Token-specific errors (invalid, expired, etc.)
- `ValidationError` - Input validation errors
- `RedisError` - Redis connection or operation errors

## Testing

```bash
# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Generate coverage report
npm run test:coverage
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) file for details

## Author

Ahmad Raza

## Support

For issues and feature requests, please use the [GitHub issue tracker](https://github.com/Ahmdrza/jwt-redis-sessions/issues).
