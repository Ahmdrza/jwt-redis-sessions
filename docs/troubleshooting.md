# Troubleshooting Guide

## Common Issues

### 1. "JWT_SECRET must be at least 32 characters long"

**Problem**: Your JWT secret is too short.

**Solution**: Generate a secure 32+ character secret:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 2. "Redis client not initialized or not connected"

**Problem**: Redis server is not running or not accessible.

**Solutions**:

- **Check Redis is running**: `redis-cli ping` (should return "PONG")
- **Start Redis**:
  - macOS: `brew services start redis`
  - Ubuntu: `sudo systemctl start redis-server`
  - Docker: `docker run -d -p 6379:6379 redis:7-alpine`
- **Check connection URL**: Verify `REDIS_URL` in your `.env` file

### 3. "Token has been revoked" errors

**Problem**: Using tokens after logout or token revocation.

**Solution**:

- Get new tokens via `/login` or `/refresh` endpoint
- Check if logout was called on the token
- Verify token hasn't expired

### 4. Rate limiting triggers too quickly

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

### 5. CORS issues in browser

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

### 6. TypeScript import errors

**Problem**: TypeScript can't find type definitions.

**Solution**: Import types explicitly:

```typescript
import type { TokenData } from 'jwt-redis-sessions'
```

## Debugging Tips

### Enable Debug Logging

```javascript
// Add to your .env file
NODE_ENV = development

// The library will include stack traces in error responses
```

### Check Redis Keys

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

### Verify Token Content

```javascript
const jwt = require('jsonwebtoken')

// Decode token without verification (for debugging only)
const decoded = jwt.decode(token, { complete: true })
console.log('Token header:', decoded.header)
console.log('Token payload:', decoded.payload)
```
