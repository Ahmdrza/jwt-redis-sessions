# Examples

## Complete Working Example

Here's a full authentication system example:

```javascript
// server.js
require('dotenv').config()
const express = require('express')
const bcrypt = require('bcrypt') // npm install bcrypt
const {
  generateToken,
  verifyToken,
  refreshToken,
  revokeToken,
  revokeAllUserTokens,
  auth,
  rateLimit,
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
app.get('/profile', auth, async (req, res) => {
  // Get user data from token
  const token = req.headers.authorization?.split(' ')[1]
  const result = await verifyToken(token)

  res.json({
    message: 'Profile data',
    user: result.decoded,
    sessionInfo: {
      sessionId: result.session.sessionId,
      createdAt: result.session.createdAt,
      lastActivity: result.session.lastActivity,
    },
  })
})

// Token management
app.post('/refresh', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1]
    if (!token) {
      return res.status(400).json({ error: 'Refresh token required' })
    }

    const newTokens = await refreshToken(token)
    res.json(newTokens)
  } catch (error) {
    res.status(401).json({ error: error.message })
  }
})

app.post('/logout', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1]
    if (!token) {
      return res.status(400).json({ error: 'Token required' })
    }

    await revokeToken(token)
    res.json({ success: true, message: 'Logged out successfully' })
  } catch (error) {
    res.status(401).json({ error: error.message })
  }
})

app.post('/logout-all', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1]
    if (!token) {
      return res.status(400).json({ error: 'Token required' })
    }

    const result = await verifyToken(token)
    const userIdentifier = result.decoded.userId || result.decoded.id || result.decoded.email

    if (!userIdentifier) {
      return res.status(400).json({ error: 'User identifier not found' })
    }

    const logoutResult = await revokeAllUserTokens(userIdentifier)
    res.json({ success: true, message: logoutResult.message })
  } catch (error) {
    res.status(401).json({ error: error.message })
  }
})

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

## Test the API

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
