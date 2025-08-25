const { verifyToken } = require('./jwt.service')
const { validateAuthHeader, validateSecret } = require('./validation.util')
const { sendErrorResponse } = require('./utils')
const config = require('./config')

/**
 * Express middleware for JWT authentication
 * Validates the authorization header and verifies the token
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {Promise<void>} Calls next() if authentication succeeds, sends error response otherwise
 * @example
 * app.get('/protected', auth, (req, res) => {
 *   res.json({ message: 'Authenticated!' })
 * })
 */
exports.auth = async (req, res, next) => {
  try {
    // Validate JWT secret at startup
    validateSecret(config.jwt.secret)

    // Extract and validate token
    const token = validateAuthHeader(req.headers.authorization)

    // Verify token (includes blacklist check and fingerprinting)
    await verifyToken(token, req)

    return next()
  } catch (error) {
    return sendErrorResponse(res, error)
  }
}

/**
 * Creates rate limiting middleware to prevent brute force attacks
 * @param {number} [maxAttempts=5] - Maximum number of attempts allowed
 * @param {number} [windowMs=900000] - Time window in milliseconds (default: 15 minutes)
 * @param {number} [maxMapSize=10000] - Maximum size of the attempts map to prevent memory exhaustion
 * @returns {Function} Express middleware function
 * @example
 * app.use('/api/login', rateLimit(5, 15 * 60 * 1000)) // 5 attempts per 15 minutes
 */
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
