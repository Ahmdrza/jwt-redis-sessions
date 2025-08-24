const { verifyToken } = require('./jwt.service')
const { validateAuthHeader, validateSecret } = require('./validation.util')
const config = require('./config')

// Error response helper
const sendErrorResponse = (res, error) => {
  const statusCode = error.statusCode || 401
  const code = error.code || 'UNAUTHORIZED'

  return res.status(statusCode).json({
    status: code,
    message: error.message,
    // Only include error details in development
    ...(process.env.NODE_ENV === 'development' && { details: error.stack }),
  })
}

// Main authentication middleware
exports.auth = async (req, res, next) => {
  try {
    // Validate JWT secret at startup
    validateSecret(config.jwt.secret)

    // Extract and validate token
    const token = validateAuthHeader(req.headers.authorization)

    // Verify token (includes blacklist check)
    const result = await verifyToken(token)

    // Attach user and session info to request
    req.user = result.decoded
    req.session = result.session
    req.token = token

    return next()
  } catch (error) {
    return sendErrorResponse(res, error)
  }
}

// Optional authentication middleware (doesn't fail if no token)
exports.optionalAuth = async (req, res, next) => {
  try {
    // If no authorization header, just continue
    if (!req.headers.authorization) {
      return next()
    }

    // Try to authenticate
    const token = validateAuthHeader(req.headers.authorization)
    const result = await verifyToken(token)
    req.user = result.decoded
    req.session = result.session
    req.token = token
  } catch (error) {
    // Log error but don't fail the request
    console.error('Optional auth failed:', error.message)
  }

  return next()
}

// Rate limiting middleware
exports.rateLimit = (maxAttempts = 5, windowMs = 15 * 60 * 1000, maxMapSize = 10000) => {
  const attempts = new Map()

  return (req, res, next) => {
    const key = req.ip || req.connection.remoteAddress
    const now = Date.now()

    // Clean up expired entries first
    for (const [k, v] of attempts.entries()) {
      if (now - v.firstAttempt > windowMs) {
        attempts.delete(k)
      }
    }

    // Enforce max size limit to prevent memory exhaustion
    if (attempts.size >= maxMapSize) {
      // Remove oldest 25% of entries when max size reached
      const entriesToRemove = Math.floor(maxMapSize * 0.25)
      const sortedEntries = Array.from(attempts.entries()).sort(
        (a, b) => a[1].firstAttempt - b[1].firstAttempt
      )

      for (let i = 0; i < entriesToRemove; i++) {
        attempts.delete(sortedEntries[i][0])
      }
    }

    // Check current attempts
    const userAttempts = attempts.get(key)

    if (userAttempts && userAttempts.count >= maxAttempts) {
      const timeLeft = Math.ceil((userAttempts.firstAttempt + windowMs - now) / 1000)
      return res.status(429).json({
        status: 'TOO_MANY_REQUESTS',
        message: `Too many attempts. Please try again in ${timeLeft} seconds`,
      })
    }

    // Record attempt
    if (!userAttempts) {
      attempts.set(key, { count: 1, firstAttempt: now })
    } else {
      userAttempts.count++
    }

    next()
  }
}
