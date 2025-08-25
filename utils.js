const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const config = require('./config')
const { TokenError } = require('./errors')

// ==================== TIME UTILITIES ====================

// Get current Unix timestamp (seconds since epoch)
exports.getUnixTimestamp = () => {
  return Math.floor(Date.now() / 1000)
}

// Get current ISO timestamp string
exports.getISOTimestamp = () => {
  return new Date().toISOString()
}

// ==================== RESPONSE UTILITIES ====================

// Common error response helper
exports.sendErrorResponse = (res, error) => {
  const statusCode = error.statusCode || 401
  const code = error.code || 'UNAUTHORIZED'

  return res.status(statusCode).json({
    status: code,
    message: error.message,
    // Only include error details in development
    ...(process.env.NODE_ENV === 'development' && { details: error.stack }),
  })
}

// Success response utility for consistent success responses
exports.sendSuccessResponse = (res, data, message = 'Success', statusCode = 200) => {
  const response = {
    status: 'SUCCESS',
    message,
  }

  // Only include data field if data is provided and not null
  if (data !== null && data !== undefined) {
    response.data = data
  }

  return res.status(statusCode).json(response)
}

// ==================== REDIS KEY UTILITIES ====================

// Redis key management utility to avoid string duplication
class RedisKeyBuilder {
  constructor() {
    this.prefix = config.redis.keyPrefix
  }

  // Session keys
  sessionKey(sessionId) {
    return `${this.prefix}session:${sessionId}`
  }

  // Refresh token keys
  refreshKey(sessionId) {
    return `${this.prefix}refresh:${sessionId}`
  }

  // Blacklist keys
  blacklistKey(token) {
    return `${this.prefix}blacklist:${token}`
  }

  // User session pattern (for SCAN operations)
  userSessionPattern(userId) {
    return `${this.prefix}session:*${userId}*`
  }

  // Get all keys pattern
  allKeysPattern() {
    return `${this.prefix}*`
  }
}

// Export singleton instance
exports.redisKeys = new RedisKeyBuilder()

// ==================== JWT UTILITIES ====================

// Common JWT verification with security checks
exports.verifyJwtToken = (token, expectedType = null) => {
  try {
    // Verify token with strict options
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

    // Validate token type if specified
    if (expectedType && decoded.type !== expectedType) {
      throw new TokenError(`Invalid token type. Expected '${expectedType}', got '${decoded.type}'`)
    }

    return decoded
  } catch (error) {
    throw exports.handleJwtError(error, expectedType)
  }
}

// Standardized JWT error handling
exports.handleJwtError = (error, tokenType = null) => {
  if (error instanceof TokenError) {
    return error // Already a TokenError, pass through
  }

  const tokenTypePrefix = tokenType
    ? `${tokenType.charAt(0).toUpperCase() + tokenType.slice(1)} token`
    : 'Token'

  switch (error.name) {
    case 'JsonWebTokenError':
      return new TokenError(tokenType === 'refresh' ? 'Invalid refresh token' : 'Invalid token')
    case 'TokenExpiredError':
      return new TokenError(tokenType === 'refresh' ? 'Refresh token expired' : 'Token expired')
    case 'NotBeforeError':
      return new TokenError(`${tokenTypePrefix} not yet valid`)
    default:
      return new TokenError(error.message || 'Token verification failed')
  }
}

// ==================== TOKEN DATA UTILITIES ====================

// Filter out internal JWT fields from decoded token
exports.getCleanUserData = (decodedToken) => {
  const internalFields = [
    // JWT standard claims
    'iat',
    'exp',
    'nbf',
    'iss',
    'aud',
    'sub',
    'jti',
    // Our internal fields
    'sessionId',
    'type',
    '_fp',
    '_fpTime',
  ]

  const cleanData = {}
  for (const [key, value] of Object.entries(decodedToken)) {
    if (!internalFields.includes(key)) {
      cleanData[key] = value
    }
  }

  return cleanData
}

// ==================== TOKEN FINGERPRINTING ====================

// Generate device/browser fingerprint
exports.generateFingerprint = (req) => {
  if (!req) {
    return null
  }

  const components = []

  // User agent (browser/device info)
  if (req.headers && req.headers['user-agent']) {
    components.push(req.headers['user-agent'])
  }

  // Accept language (user preference)
  if (req.headers && req.headers['accept-language']) {
    components.push(req.headers['accept-language'])
  }

  // Accept encoding (browser capabilities)
  if (req.headers && req.headers['accept-encoding']) {
    components.push(req.headers['accept-encoding'])
  }

  // IP address (with some flexibility for proxy/load balancer scenarios)
  const ip =
    req.ip || req.connection?.remoteAddress || req.headers?.['x-forwarded-for']?.split(',')[0]
  if (ip) {
    // Use first 3 octets for IPv4 to handle dynamic IPs
    const ipParts = ip.split('.')
    if (ipParts.length === 4) {
      components.push(`${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.x`)
    } else {
      components.push(ip) // IPv6 or other formats
    }
  }

  // Create stable hash
  const fingerprintData = components.join('|')
  return crypto.createHash('sha256').update(fingerprintData).digest('hex').substring(0, 16) // Use first 16 chars for compactness
}

// Verify token fingerprint
exports.verifyFingerprint = (req, tokenFingerprint) => {
  if (!tokenFingerprint) {
    return { valid: true, reason: null }
  }

  const currentFingerprint = exports.generateFingerprint(req)

  if (currentFingerprint === tokenFingerprint) {
    return { valid: true, reason: null }
  }

  // In strict mode, reject immediately
  if (config.security.fingerprintStrict) {
    return {
      valid: false,
      reason: 'Token fingerprint mismatch - device/network change detected',
    }
  }

  // In non-strict mode, log warning but allow (for user convenience)
  console.warn('Token fingerprint mismatch detected:', {
    expected: tokenFingerprint,
    actual: currentFingerprint,
    ip: req.ip,
    userAgent: req.headers['user-agent']?.substring(0, 100),
  })

  return {
    valid: true,
    reason: 'Fingerprint mismatch but allowed in non-strict mode',
  }
}

// Add fingerprint to token data
exports.addFingerprintToTokenData = (tokenData, req) => {
  if (!config.security.enableFingerprinting || !req) {
    return tokenData
  }

  const fingerprint = exports.generateFingerprint(req)
  if (!fingerprint) {
    return tokenData
  }

  return {
    ...tokenData,
    _fp: fingerprint, // Use short name to keep token size small
    _fpTime: exports.getUnixTimestamp(),
  }
}
