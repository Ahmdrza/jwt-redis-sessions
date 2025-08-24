# Security Best Practices & Production Deployment

## 🔒 Essential Security Requirements

### 1. Strong JWT Secret

Generate a cryptographically secure secret in production:

```bash
JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
```

### 2. HTTPS Only

Always use HTTPS in production:

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

### 3. Secure Redis Connection

```env
# Use SSL/TLS in production
REDIS_URL=rediss://username:password@redis-host:6380

# Or with explicit SSL config
REDIS_SSL=true
REDIS_HOST=your-redis-host.com
REDIS_PORT=6380
REDIS_PASSWORD=your-secure-password
```

### 4. Environment-Based Configuration

```env
# Production settings
NODE_ENV=production
JWT_ACCESS_TOKEN_EXPIRY=15m    # Short access token lifetime
JWT_REFRESH_TOKEN_EXPIRY=7d    # Reasonable refresh token lifetime
SESSION_TTL=86400              # 24 hours
MAX_LOGIN_ATTEMPTS=3           # Strict rate limiting
LOCKOUT_TIME=1800             # 30 minutes lockout
```

### 5. Security Headers

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

## 🚀 Production Deployment Checklist

### Before Deployment

- [ ] Generate secure `JWT_SECRET` (32+ characters)
- [ ] Configure Redis with SSL/TLS and authentication
- [ ] Set up proper CORS origins
- [ ] Enable rate limiting on all auth endpoints
- [ ] Configure secure session and cookie settings
- [ ] Set up monitoring and logging
- [ ] Test token refresh flows
- [ ] Verify logout functionality works correctly

### Production Environment Variables

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

## 🛡️ Advanced Security Features

### 1. Token Binding (Optional)

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

### 2. Suspicious Activity Detection

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

### 3. Production Monitoring

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
