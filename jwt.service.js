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
  addFingerprintToTokenData,
  verifyFingerprint,
  getCleanUserData,
} = require('./utils')
const { AuthError, TokenError } = require('./errors')
const redisHelper = require('./redis.config')

// Generate a unique session ID
const generateSessionId = () => {
  return crypto.randomBytes(config.security.tokenLength).toString('hex')
}

/**
 * Generates JWT access and refresh tokens for a user session
 * @param {Object} data - User data to encode in the token (e.g., userId, email, role)
 * @param {Object} [req] - Optional Express request object for device fingerprinting
 * @returns {Promise<Object>} Token response containing accessToken, refreshToken, expiresIn, and tokenType
 * @throws {ValidationError} If JWT secret is invalid or data validation fails
 * @throws {RedisError} If Redis operation fails
 * @example
 * const tokens = await generateToken({ userId: 'user123', email: 'user@example.com' })
 * // Returns: { accessToken: 'jwt...', refreshToken: 'jwt...', expiresIn: '15m', tokenType: 'Bearer' }
 */
exports.generateToken = async (data = {}, req = null) => {
  try {
    // Validate input
    validateSecret(config.jwt.secret)
    validateTokenData(data)

    // Convert null to empty object for convenience
    const userData = data || {}

    const sessionId = generateSessionId()
    const now = getUnixTimestamp()

    // Add fingerprinting to token data if available
    const tokenData = addFingerprintToTokenData(userData, req)

    // Create JWT payload with claims
    const payload = {
      ...tokenData,
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
      // Include user identifier if available (for user session management)
      ...(userData.userId && { userId: userData.userId }),
      ...(userData.id && { id: userData.id }),
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
      ...userData,
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

/**
 * Verifies and validates a JWT token
 * @param {string} token - The JWT token to verify
 * @param {Object} [req] - Optional Express request object for fingerprint verification
 * @returns {Promise<Object>} Verification result with valid flag, decoded data, and session info
 * @throws {TokenError} If token is invalid, expired, blacklisted, or fingerprint doesn't match
 * @throws {RedisError} If Redis operation fails
 * @example
 * const result = await verifyToken('jwt...')
 * // Returns: { valid: true, decoded: { userId: 'user123', ... }, session: { sessionId: '...', ... } }
 */
exports.verifyToken = async (token, req = null) => {
  try {
    validateSecret(config.jwt.secret)

    // Check if token is blacklisted first
    const isBlacklisted = await exports.isTokenBlacklisted(token)
    if (isBlacklisted) {
      throw new TokenError('Token has been revoked')
    }

    // Verify JWT with security checks and type validation
    const decoded = verifyJwtToken(token, 'access')

    // Verify fingerprint if enabled and request context available
    if (req && decoded._fp) {
      const fingerprintResult = verifyFingerprint(req, decoded._fp)
      if (!fingerprintResult.valid) {
        throw new TokenError(fingerprintResult.reason)
      }
    }

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
      decoded: getCleanUserData(decoded), // Filter out internal fields
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

/**
 * Refreshes an access token using a valid refresh token
 * @param {string} refreshToken - The refresh token
 * @param {Object} [req] - Optional Express request object for fingerprint verification
 * @returns {Promise<Object>} New token pair with accessToken, refreshToken, expiresIn, and tokenType
 * @throws {TokenError} If refresh token is invalid, expired, or blacklisted
 * @throws {RedisError} If Redis operation fails
 * @example
 * const newTokens = await refreshToken('refresh_jwt...')
 * // Returns: { accessToken: 'new_jwt...', refreshToken: 'new_refresh...', expiresIn: '15m', tokenType: 'Bearer' }
 */
exports.refreshToken = async (refreshToken, req = null) => {
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

    // Generate new tokens (with fingerprinting if available)
    const newTokens = await exports.generateToken(session, req)

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

/**
 * Revokes a token by adding it to the blacklist
 * @param {string} token - The token to revoke
 * @returns {Promise<Object>} Success status and message
 * @throws {TokenError} If token is invalid
 * @throws {RedisError} If Redis operation fails
 * @example
 * const result = await revokeToken('jwt...')
 * // Returns: { success: true, message: 'Token revoked successfully' }
 */
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

/**
 * Checks if a token has been blacklisted/revoked
 * @param {string} token - The token to check
 * @returns {Promise<boolean>} True if token is blacklisted, false otherwise
 * @throws {TokenError} If token format is invalid
 * @throws {RedisError} If Redis operation fails
 * @example
 * const isBlacklisted = await isTokenBlacklisted('jwt...')
 * // Returns: true or false
 */
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

/**
 * Retrieves all active sessions for a specific user
 * @param {string} userIdentifier - The user identifier (userId, id, or email)
 * @returns {Promise<Array>} Array of session objects with sessionId, createdAt, lastActivity, and user data
 * @throws {Error} If userIdentifier is not provided
 * @throws {RedisError} If Redis operation fails
 * @example
 * const sessions = await getUserSessions('user123')
 * // Returns: [{ sessionId: '...', createdAt: '2024-01-01T00:00:00Z', lastActivity: '...', userId: 'user123' }]
 */
exports.getUserSessions = async (userIdentifier) => {
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
          if (
            session.userId === userIdentifier ||
            session.id === userIdentifier ||
            session.email === userIdentifier
          ) {
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

/**
 * Revokes all active sessions/tokens for a specific user
 * @param {string} userIdentifier - The user identifier (can be userId, id, or email based on your token data)
 * @returns {Promise<Object>} Success status and message with count of revoked sessions
 * @throws {Error} If userIdentifier is not provided
 * @throws {RedisError} If Redis operation fails
 * @example
 * const result = await revokeAllUserTokens('user123')
 * // Returns: { success: true, message: 'Revoked 3 sessions for user user123' }
 */
exports.revokeAllUserTokens = async (userIdentifier) => {
  try {
    const sessions = await exports.getUserSessions(userIdentifier)

    for (const session of sessions) {
      await Promise.all([
        redisHelper.del(redisKeys.sessionKey(session.sessionId)),
        redisHelper.del(redisKeys.refreshKey(session.sessionId)),
      ])
    }

    return {
      success: true,
      message: `Revoked ${sessions.length} sessions for user ${userIdentifier}`,
    }
  } catch (error) {
    throw new AuthError(`Failed to revoke user tokens: ${error.message}`)
  }
}
