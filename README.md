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

## Prerequisites

- **Node.js** 14.0 or higher
- **Redis** 6.0 or higher
- **npm** or **yarn** package manager

## Installation

```bash
npm install jwt-redis-sessions
# or
yarn add jwt-redis-sessions
```

## Quick Start

### 1. Start Redis Server

```bash
# macOS with Homebrew
brew services start redis

# Ubuntu/Debian
sudo systemctl start redis-server

# Docker
docker run -d -p 6379:6379 redis:7-alpine
```

### 2. Set up environment variables

Create a `.env` file:

```env
# Required: Strong JWT secret (minimum 32 characters)
JWT_SECRET=your-super-secure-jwt-secret-key-with-at-least-32-characters-for-production

# Optional: Redis connection (default: redis://localhost:6379)
REDIS_URL=redis://localhost:6379

# Optional: Token expiration times
JWT_ACCESS_TOKEN_EXPIRY=15m
JWT_REFRESH_TOKEN_EXPIRY=7d
```

> 🔒 **Security Note**: Generate a cryptographically secure JWT secret:
>
> ```bash
> node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
> ```

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
      userId: 'user123',
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

## Configuration

All configuration is done through environment variables. See [.env.example](.env.example) for all available options.

### JWT Configuration

- `JWT_SECRET` - Secret key for signing tokens (required, min 32 chars)
- `JWT_ACCESS_TOKEN_EXPIRY` - Access token expiration (default: '15m')
- `JWT_REFRESH_TOKEN_EXPIRY` - Refresh token expiration (default: '7d')

### Redis Configuration

- `REDIS_URL` - Redis connection URL (default: 'redis://localhost:6379')
- `REDIS_HOST` - Redis host (default: 'localhost')
- `REDIS_PORT` - Redis port (default: 6379)
- `REDIS_PASSWORD` - Redis password (optional)

## API Overview

### Token Management

- `generateToken(data)` - Generate access and refresh tokens
- `refreshToken(token)` - Refresh an access token
- `revokeToken(token)` - Revoke a specific token
- `revokeAllUserTokens(userId)` - Revoke all tokens for a user

### Middleware

- `auth` - Main authentication middleware
- `optionalAuth` - Optional authentication
- `rateLimit(maxAttempts, windowMs)` - Rate limiting middleware

### Handlers

- `logout` - Logout current session
- `logoutAll` - Logout all sessions
- `refresh` - Refresh token handler

## Documentation

- **[Complete Examples](./docs/examples.md)** - Full working code examples
- **[API Reference](./docs/api-reference.md)** - Detailed API documentation
- **[Troubleshooting](./docs/troubleshooting.md)** - Common issues and solutions
- **[Security Guide](./docs/security.md)** - Production security best practices

## Testing

```bash
npm test
npm run test:coverage
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Author

Ahmad Raza

## Support

For issues and feature requests, please use the [GitHub issue tracker](https://github.com/Ahmdrza/jwt-redis-sessions/issues).
