const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const config = require('./config')
const { validateSecret, validateTokenData, constantTimeCompare } = require('./validation.util')
const { AuthError, TokenError } = require('./errors')
const redisHelper = require('./redis.config')

// Generate a unique session ID
const generateSessionId = () => {
  return crypto.randomBytes(config.security.tokenLength).toString('hex')
}

// Generate access token with proper payload
exports.generateToken = async (data = {}) => {
  try {
    // Validate input
    validateSecret(config.jwt.secret)
    validateTokenData(data)

    const sessionId = generateSessionId()
    const now = Math.floor(Date.now() / 1000)

    // Create JWT payload with claims
    const payload = {
      ...data,
      sessionId,
      iat: now,
      iss: config.jwt.issuer,
      aud: config.jwt.audience,
      type: 'access',
    }

    // Generate access token with expiration
    const accessToken = jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.accessTokenExpiry,
      algorithm: 'HS256',
    })

    // Generate refresh token
    const refreshPayload = {
      sessionId,
      userId: data.userId || data.id,
      iat: now,
      iss: config.jwt.issuer,
      aud: config.jwt.audience,
      type: 'refresh',
    }

    const refreshToken = jwt.sign(refreshPayload, config.jwt.secret, {
      expiresIn: config.jwt.refreshTokenExpiry,
      algorithm: 'HS256',
    })

    // Store session data in Redis
    const sessionData = {
      ...data,
      sessionId,
      createdAt: new Date().toISOString(),
      lastActivity: new Date().toISOString(),
    }

    await redisHelper.setWithExpiry(
      `session:${sessionId}`,
      JSON.stringify(sessionData),
      config.redis.sessionTTL
    )

    // Store refresh token in Redis
    await redisHelper.setWithExpiry(
      `refresh:${sessionId}`,
      refreshToken,
      config.redis.refreshTokenTTL
    )

    return {
      accessToken,
      refreshToken,
      expiresIn: config.jwt.accessTokenExpiry,
      tokenType: 'Bearer',
    }
  } catch (error) {
    if (error.name === 'ValidationError' || error.name === 'RedisError') {
      throw error
    }
    throw new TokenError(`Failed to generate token: ${error.message}`)
  }
}

// Verify and decode token
exports.verifyToken = async (token) => {
  try {
    validateSecret(config.jwt.secret)

    // Check if token is blacklisted first
    const isBlacklisted = await exports.isTokenBlacklisted(token)
    if (isBlacklisted) {
      throw new TokenError('Token has been revoked')
    }

    // Verify JWT with explicit algorithm enforcement
    const decoded = jwt.verify(token, config.jwt.secret, {
      algorithms: ['HS256'], // Only allow HMAC with SHA-256
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
      ignoreNotBefore: false,
      ignoreExpiration: false,
      clockTolerance: 0,
    })

    // Additional security check: ensure algorithm is not 'none'
    const header = jwt.decode(token, { complete: true })
    if (!header || header.header.alg === 'none') {
      throw new TokenError('Invalid token algorithm')
    }

    if (decoded.type !== 'access') {
      throw new TokenError('Invalid token type')
    }

    // Check if session exists in Redis
    const sessionData = await redisHelper.get(`session:${decoded.sessionId}`)

    if (!sessionData) {
      throw new TokenError('Session not found or expired')
    }

    // Update last activity
    const session = JSON.parse(sessionData)
    session.lastActivity = new Date().toISOString()

    await redisHelper.setWithExpiry(
      `session:${decoded.sessionId}`,
      JSON.stringify(session),
      config.redis.sessionTTL
    )

    return {
      valid: true,
      decoded,
      session,
    }
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      throw new TokenError('Invalid token')
    }
    if (error.name === 'TokenExpiredError') {
      throw new TokenError('Token expired')
    }
    if (
      error.name === 'ValidationError' ||
      error.name === 'RedisError' ||
      error.name === 'TokenError'
    ) {
      throw error
    }
    throw new AuthError(`Token verification failed: ${error.message}`)
  }
}

// Refresh token rotation
exports.refreshToken = async (refreshToken) => {
  try {
    validateSecret(config.jwt.secret)

    // Verify refresh token with explicit algorithm enforcement
    const decoded = jwt.verify(refreshToken, config.jwt.secret, {
      algorithms: ['HS256'], // Only allow HMAC with SHA-256
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
      ignoreNotBefore: false,
      ignoreExpiration: false,
      clockTolerance: 0,
    })

    // Additional security check: ensure algorithm is not 'none'
    const header = jwt.decode(refreshToken, { complete: true })
    if (!header || header.header.alg === 'none') {
      throw new TokenError('Invalid token algorithm')
    }

    if (decoded.type !== 'refresh') {
      throw new TokenError('Invalid token type')
    }

    // Check if refresh token exists in Redis
    const storedRefreshToken = await redisHelper.get(`refresh:${decoded.sessionId}`)

    if (!storedRefreshToken || !constantTimeCompare(storedRefreshToken, refreshToken)) {
      throw new TokenError('Invalid refresh token')
    }

    // Get session data
    const sessionData = await redisHelper.get(`session:${decoded.sessionId}`)

    if (!sessionData) {
      throw new TokenError('Session not found or expired')
    }

    const session = JSON.parse(sessionData)

    // Delete old refresh token (rotation)
    await redisHelper.del(`refresh:${decoded.sessionId}`)

    // Generate new tokens
    const newTokens = await exports.generateToken(session)

    return newTokens
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      throw new TokenError('Invalid refresh token')
    }
    if (error.name === 'TokenExpiredError') {
      throw new TokenError('Refresh token expired')
    }
    if (error.name === 'TokenError' || error.name === 'RedisError') {
      throw error
    }
    throw new AuthError(`Token refresh failed: ${error.message}`)
  }
}

// Logout / Revoke token
exports.revokeToken = async (token) => {
  try {
    validateSecret(config.jwt.secret)

    // Verify and decode token
    const decoded = jwt.verify(token, config.jwt.secret, {
      algorithms: ['HS256'],
    })

    // Delete session and refresh token from Redis
    await Promise.all([
      redisHelper.del(`session:${decoded.sessionId}`),
      redisHelper.del(`refresh:${decoded.sessionId}`),
    ])

    // Add token to blacklist until it expires
    const exp = decoded.exp - Math.floor(Date.now() / 1000)
    if (exp > 0) {
      await redisHelper.setWithExpiry(`blacklist:${token}`, '1', exp)
    }

    return { success: true, message: 'Token revoked successfully' }
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      // Token is already invalid, consider it revoked
      return { success: true, message: 'Token already invalid' }
    }
    throw new AuthError(`Failed to revoke token: ${error.message}`)
  }
}

// Check if token is blacklisted
exports.isTokenBlacklisted = async (token) => {
  try {
    const exists = await redisHelper.exists(`blacklist:${token}`)
    return exists === 1
  } catch (error) {
    // If Redis fails, consider token valid for safety
    console.error('Failed to check token blacklist:', error)
    return false
  }
}

// Get all active sessions for a user
exports.getUserSessions = async (userId) => {
  try {
    const client = redisHelper.getRedisClient()
    const sessions = []

    // Use SCAN instead of KEYS for production safety
    let cursor = '0'
    do {
      const result = await client.scan(cursor, {
        MATCH: `${config.redis.keyPrefix}session:*`,
        COUNT: 100,
      })
      cursor = result.cursor
      const keys = result.keys

      for (const key of keys) {
        const sessionData = await client.get(key)
        if (sessionData) {
          const session = JSON.parse(sessionData)
          if (session.userId === userId || session.id === userId) {
            sessions.push(session)
          }
        }
      }
    } while (cursor !== '0')

    return sessions
  } catch (error) {
    throw new AuthError(`Failed to get user sessions: ${error.message}`)
  }
}

// Revoke all tokens for a user
exports.revokeAllUserTokens = async (userId) => {
  try {
    const sessions = await exports.getUserSessions(userId)

    for (const session of sessions) {
      await Promise.all([
        redisHelper.del(`session:${session.sessionId}`),
        redisHelper.del(`refresh:${session.sessionId}`),
      ])
    }

    return {
      success: true,
      message: `Revoked ${sessions.length} sessions for user ${userId}`,
    }
  } catch (error) {
    throw new AuthError(`Failed to revoke user tokens: ${error.message}`)
  }
}
