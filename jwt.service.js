const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const config = require('./config')
const { validateSecret, validateTokenData } = require('./validation.util')
const {
  verifyJwtToken,
  handleJwtError,
  getUnixTimestamp,
  getISOTimestamp,
  redisKeys,
  hashToken,
  addFingerprintToTokenData,
  verifyFingerprint,
  getCleanUserData,
} = require('./utils')
const { AuthError, TokenError, ValidationError } = require('./errors')
const redisHelper = require('./redis.config')

const validateToken = (token, label = 'Token') => {
  if (typeof token !== 'string' || !token) {
    throw new TokenError(`${label} must be a non-empty string`)
  }
}

const getUserIdentifiers = (data) =>
  ['userId', 'id', 'email']
    .map((field) => data[field])
    .filter((value) => typeof value === 'string' && value.length > 0)

const getTokenData = (data) => {
  const tokenData = {}
  for (const field of config.security.allowedTokenFields) {
    if (Object.prototype.hasOwnProperty.call(data, field)) {
      tokenData[field] = data[field]
    }
  }
  return tokenData
}

const getIndexKeys = (data) =>
  getUserIdentifiers(data).map((identifier) => redisKeys.userSessionsKey(identifier))

const getGenerationState = async (data) => {
  const keys = getUserIdentifiers(data).map((identifier) => redisKeys.userGenerationKey(identifier))
  const values = await Promise.all(keys.map((key) => redisHelper.getGeneration(key)))
  return keys.map((key, index) => ({ key, value: values[index] }))
}

const getStoredGenerationState = (session) =>
  Array.isArray(session._userGenerations) ? session._userGenerations : []

const getPublicSession = (session) => {
  const publicSession = { ...session }
  delete publicSession._userGenerations
  delete publicSession.sessionVersion
  return publicSession
}

const deleteSession = async (session) => {
  await redisHelper.deleteSessionAtomic({
    sessionKey: redisKeys.sessionKey(session.sessionId),
    refreshKey: redisKeys.refreshKey(session.sessionId),
    indexKeys: getIndexKeys(session),
    sessionId: session.sessionId,
  })
}

// Generate a unique session ID
const generateSessionId = () => {
  return crypto.randomBytes(config.security.tokenLength).toString('hex')
}

const createTokenPair = (userData, sessionId, sessionVersion, req) => {
  const now = getUnixTimestamp()
  const tokenData = addFingerprintToTokenData(userData, req)
  const commonClaims = {
    sessionId,
    sessionVersion,
    iat: now,
    iss: config.jwt.issuer,
    aud: config.jwt.audience,
  }
  const accessToken = jwt.sign(
    { ...tokenData, ...commonClaims, type: 'access', jti: crypto.randomUUID() },
    config.jwt.secret,
    { expiresIn: config.jwt.accessTokenExpiry, algorithm: 'HS256' }
  )
  const refreshToken = jwt.sign(
    {
      ...commonClaims,
      type: 'refresh',
      jti: crypto.randomUUID(),
      ...(userData.userId && { userId: userData.userId }),
      ...(userData.id && { id: userData.id }),
    },
    config.jwt.secret,
    { expiresIn: config.jwt.refreshTokenExpiry, algorithm: 'HS256' }
  )
  const decodedRefresh = jwt.decode(refreshToken)
  const refreshLifetime = decodedRefresh.exp - now
  return {
    accessToken,
    refreshToken,
    refreshExpiresAt: decodedRefresh.exp,
    sessionTTL: Math.max(config.redis.sessionTTL, refreshLifetime),
    refreshTTL: Math.max(config.redis.refreshTokenTTL, refreshLifetime),
  }
}

const validateSessionVersion = (version) => {
  if (!Number.isInteger(version) || version < 1) {
    throw new TokenError('Invalid token session version')
  }
}

/**
 * Generate JWT access and refresh tokens
 * @param {Object} data User data for token (userId, email, role, etc.)
 * @param {Object} [req] Optional request for fingerprinting
 * @returns {Promise<Object>} Token response with accessToken, refreshToken, expiresIn, tokenType
 */
exports.generateToken = async (data = {}, req = null) => {
  try {
    // Validate input
    validateSecret(config.jwt.secret)
    validateTokenData(data)

    // Convert null to empty object for convenience
    const userData = data || {}

    for (let attempt = 0; attempt < 3; attempt++) {
      const sessionId = generateSessionId()
      const sessionVersion = 1
      const generationState = await getGenerationState(userData)
      const tokens = createTokenPair(userData, sessionId, sessionVersion, req)
      const timestamp = getISOTimestamp()
      const sessionData = {
        ...getTokenData(userData),
        sessionId,
        sessionVersion,
        refreshExpiresAt: tokens.refreshExpiresAt,
        createdAt: timestamp,
        lastActivity: timestamp,
        _userGenerations: generationState,
      }
      const created = await redisHelper.createSessionAtomic({
        sessionKey: redisKeys.sessionKey(sessionId),
        refreshKey: redisKeys.refreshKey(sessionId),
        indexKeys: getIndexKeys(sessionData),
        generationKeys: generationState.map(({ key }) => key),
        generationValues: generationState.map(({ value }) => value),
        sessionId,
        sessionData: JSON.stringify(sessionData),
        sessionTTL: tokens.sessionTTL,
        refreshHash: hashToken(tokens.refreshToken),
        refreshTTL: tokens.refreshTTL,
      })
      if (created === 1) {
        return {
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          expiresIn: config.jwt.accessTokenExpiry,
          tokenType: 'Bearer',
        }
      }
    }
    throw new TokenError('Failed to create session because user revocation state changed')
  } catch (error) {
    if (error.name === 'ValidationError' || error.name === 'RedisError') {
      throw error
    }
    throw new TokenError(`Failed to generate token: ${error.message}`)
  }
}

/**
 * Verify and validate a JWT token
 * @param {string} token JWT token to verify
 * @param {Object} [req] Optional request for fingerprint verification
 * @returns {Promise<Object>} Verification result with valid, decoded, session
 */
exports.verifyToken = async (token, req = null) => {
  try {
    validateSecret(config.jwt.secret)
    validateToken(token)

    // Reject malformed/signature-invalid input before performing a Redis lookup.
    const decoded = verifyJwtToken(token, 'access')
    validateSessionVersion(decoded.sessionVersion)

    const isBlacklisted = await exports.isTokenBlacklisted(token)
    if (isBlacklisted) {
      throw new TokenError('Token has been revoked')
    }

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
    if (session.sessionVersion !== decoded.sessionVersion) {
      throw new TokenError('Token session has been replaced or revoked')
    }
    session.lastActivity = getISOTimestamp()

    const sessionTTL = Math.max(
      config.redis.sessionTTL,
      Number(session.refreshExpiresAt || 0) - getUnixTimestamp()
    )

    const generationState = getStoredGenerationState(session)
    const touched = await redisHelper.touchSessionAtomic({
      sessionKey: redisKeys.sessionKey(decoded.sessionId),
      indexKeys: getIndexKeys(session),
      generationKeys: generationState.map(({ key }) => key),
      generationValues: generationState.map(({ value }) => value),
      sessionId: session.sessionId,
      expectedVersion: decoded.sessionVersion,
      sessionData: JSON.stringify(session),
      sessionTTL,
    })
    if (touched !== 1) {
      throw new TokenError('Session has been replaced or revoked')
    }

    return {
      valid: true,
      decoded: getCleanUserData(decoded), // Filter out internal fields
      session: getPublicSession(session),
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
 * Refresh access token using refresh token
 * @param {string} refreshToken The refresh token
 * @param {Object} [req] Optional request for fingerprint verification
 * @returns {Promise<Object>} New token pair
 */
exports.refreshToken = async (refreshToken, req = null) => {
  try {
    validateSecret(config.jwt.secret)
    validateToken(refreshToken, 'Refresh token')

    // Verify refresh token with security checks and type validation
    const decoded = verifyJwtToken(refreshToken, 'refresh')
    validateSessionVersion(decoded.sessionVersion)

    // Get session data
    const sessionData = await redisHelper.get(redisKeys.sessionKey(decoded.sessionId))

    if (!sessionData) {
      throw new TokenError('Session not found or expired')
    }

    const session = JSON.parse(sessionData)
    if (session.sessionVersion !== decoded.sessionVersion) {
      throw new TokenError('Invalid refresh token')
    }

    const tokenData = getTokenData(session)
    const nextVersion = session.sessionVersion + 1
    const tokens = createTokenPair(tokenData, session.sessionId, nextVersion, req)
    const updatedSession = {
      ...session,
      sessionVersion: nextVersion,
      refreshExpiresAt: tokens.refreshExpiresAt,
      lastActivity: getISOTimestamp(),
    }
    const generationState = getStoredGenerationState(session)
    const rotated = await redisHelper.rotateSessionAtomic({
      sessionKey: redisKeys.sessionKey(session.sessionId),
      refreshKey: redisKeys.refreshKey(session.sessionId),
      indexKeys: getIndexKeys(session),
      generationKeys: generationState.map(({ key }) => key),
      generationValues: generationState.map(({ value }) => value),
      sessionId: session.sessionId,
      expectedVersion: decoded.sessionVersion,
      expectedRefreshHash: hashToken(refreshToken),
      sessionData: JSON.stringify(updatedSession),
      sessionTTL: tokens.sessionTTL,
      refreshHash: hashToken(tokens.refreshToken),
      refreshTTL: tokens.refreshTTL,
    })
    if (rotated !== 1) {
      throw new TokenError('Invalid refresh token or revoked session')
    }

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: config.jwt.accessTokenExpiry,
      tokenType: 'Bearer',
    }
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
 * Revoke token by blacklisting
 * @param {string} token Token to revoke
 * @returns {Promise<Object>} Success status and message
 */
exports.revokeToken = async (token) => {
  try {
    validateSecret(config.jwt.secret)
    validateToken(token)

    // Verify and decode token
    const decoded = verifyJwtToken(token, 'access')

    const sessionData = await redisHelper.get(redisKeys.sessionKey(decoded.sessionId))
    const session = sessionData ? JSON.parse(sessionData) : null

    if (session) {
      await deleteSession(session)
    } else {
      await redisHelper.deleteSessionAtomic({
        sessionKey: redisKeys.sessionKey(decoded.sessionId),
        refreshKey: redisKeys.refreshKey(decoded.sessionId),
        indexKeys: [],
        sessionId: decoded.sessionId,
      })
    }

    // Add token to blacklist until it expires
    const exp = decoded.exp - getUnixTimestamp()
    if (exp > 0) {
      await redisHelper.setWithExpiry(redisKeys.blacklistKey(token), '1', exp)
    }

    return { success: true, message: 'Token revoked successfully' }
  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error instanceof TokenError) {
      // Token is already invalid, consider it revoked
      return { success: true, message: 'Token already invalid' }
    }
    throw new AuthError(`Failed to revoke token: ${error.message}`)
  }
}

/**
 * Check if token is blacklisted
 * @param {string} token Token to check
 * @returns {Promise<boolean>} True if blacklisted
 */
exports.isTokenBlacklisted = async (token) => {
  validateToken(token)
  const exists = await redisHelper.exists(redisKeys.blacklistKey(token))
  return exists === 1
}

/**
 * Get all active sessions for user
 * @param {string} userIdentifier User identifier (userId, id, or email)
 * @returns {Promise<Array>} Array of session objects
 */
exports.getUserSessions = async (userIdentifier) => {
  try {
    if (typeof userIdentifier !== 'string' || !userIdentifier) {
      throw new ValidationError('User identifier must be a non-empty string')
    }

    const indexKey = redisKeys.userSessionsKey(userIdentifier)
    const sessionIds = await redisHelper.sMembers(indexKey)
    const sessionValues = await Promise.all(
      sessionIds.map((sessionId) => redisHelper.get(redisKeys.sessionKey(sessionId)))
    )
    const storedSessions = sessionValues.filter(Boolean).map((value) => JSON.parse(value))
    const sessions = storedSessions.map(getPublicSession)
    const liveIds = new Set(storedSessions.map((session) => session.sessionId))
    await Promise.all(
      sessionIds
        .filter((sessionId) => !liveIds.has(sessionId))
        .map((sessionId) => redisHelper.sRem(indexKey, sessionId))
    )

    return sessions
  } catch (error) {
    throw new AuthError(`Failed to get user sessions: ${error.message}`)
  }
}

/**
 * Revoke all user sessions/tokens
 * @param {string} userIdentifier User identifier (userId, id, or email)
 * @returns {Promise<Object>} Success status and revoked count
 */
exports.revokeAllUserTokens = async (userIdentifier) => {
  try {
    if (typeof userIdentifier !== 'string' || !userIdentifier) {
      throw new ValidationError('User identifier must be a non-empty string')
    }

    // Linearization point: all earlier sessions become invalid before cleanup.
    await redisHelper.incrementGeneration(redisKeys.userGenerationKey(userIdentifier))
    const sessions = await exports.getUserSessions(userIdentifier)

    await Promise.all(sessions.map((session) => deleteSession(session)))

    return {
      success: true,
      message: `Revoked ${sessions.length} sessions for user ${userIdentifier}`,
    }
  } catch (error) {
    throw new AuthError(`Failed to revoke user tokens: ${error.message}`)
  }
}
