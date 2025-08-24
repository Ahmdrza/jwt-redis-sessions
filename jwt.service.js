const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const config = require('./config')
const { validateSecret, validateTokenData, constantTimeCompare } = require('./validation.util')
const {
  verifyJwtToken,
  handleJwtError,
  getUnixTimestamp,
  getISOTimestamp,
  redisKeys,
} = require('./utils')
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
    const now = getUnixTimestamp()

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
      createdAt: getISOTimestamp(),
      lastActivity: getISOTimestamp(),
    }

    await redisHelper.setWithExpiry(
      redisKeys.sessionKey(sessionId),
      JSON.stringify(sessionData),
      config.redis.sessionTTL
    )

    // Store refresh token in Redis
    await redisHelper.setWithExpiry(
      redisKeys.refreshKey(sessionId),
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

    // Verify JWT with security checks and type validation
    const decoded = verifyJwtToken(token, 'access')

    // Check if session exists in Redis
    const sessionData = await redisHelper.get(redisKeys.sessionKey(decoded.sessionId))

    if (!sessionData) {
      throw new TokenError('Session not found or expired')
    }

    // Update last activity
    const session = JSON.parse(sessionData)
    session.lastActivity = getISOTimestamp()

    await redisHelper.setWithExpiry(
      redisKeys.sessionKey(decoded.sessionId),
      JSON.stringify(session),
      config.redis.sessionTTL
    )

    return {
      valid: true,
      decoded,
      session,
    }
  } catch (error) {
    // Use the standardized JWT error handler if it's a JWT-related error
    if (
      error.name === 'JsonWebTokenError' ||
      error.name === 'TokenExpiredError' ||
      error.name === 'NotBeforeError'
    ) {
      throw handleJwtError(error, 'access')
    }
    // Pass through known errors
    if (
      error instanceof TokenError ||
      error instanceof AuthError ||
      error.name === 'ValidationError' ||
      error.name === 'RedisError'
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

    // Verify refresh token with security checks and type validation
    const decoded = verifyJwtToken(refreshToken, 'refresh')

    // Check if refresh token exists in Redis
    const storedRefreshToken = await redisHelper.get(redisKeys.refreshKey(decoded.sessionId))

    if (!storedRefreshToken || !constantTimeCompare(storedRefreshToken, refreshToken)) {
      throw new TokenError('Invalid refresh token')
    }

    // Get session data
    const sessionData = await redisHelper.get(redisKeys.sessionKey(decoded.sessionId))

    if (!sessionData) {
      throw new TokenError('Session not found or expired')
    }

    const session = JSON.parse(sessionData)

    // Delete old refresh token (rotation)
    await redisHelper.del(redisKeys.refreshKey(decoded.sessionId))

    // Generate new tokens
    const newTokens = await exports.generateToken(session)

    return newTokens
  } catch (error) {
    // Use the standardized JWT error handler if it's a JWT-related error
    if (
      error.name === 'JsonWebTokenError' ||
      error.name === 'TokenExpiredError' ||
      error.name === 'NotBeforeError'
    ) {
      throw handleJwtError(error, 'refresh')
    }
    // Pass through known errors
    if (
      error instanceof TokenError ||
      error instanceof AuthError ||
      error.name === 'ValidationError' ||
      error.name === 'RedisError'
    ) {
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
      redisHelper.del(redisKeys.sessionKey(decoded.sessionId)),
      redisHelper.del(redisKeys.refreshKey(decoded.sessionId)),
    ])

    // Add token to blacklist until it expires
    const exp = decoded.exp - getUnixTimestamp()
    if (exp > 0) {
      await redisHelper.setWithExpiry(redisKeys.blacklistKey(token), '1', exp)
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
    const exists = await redisHelper.exists(redisKeys.blacklistKey(token))
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
        redisHelper.del(redisKeys.sessionKey(session.sessionId)),
        redisHelper.del(redisKeys.refreshKey(session.sessionId)),
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
