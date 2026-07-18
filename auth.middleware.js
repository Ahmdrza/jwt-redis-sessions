const { verifyToken } = require('./jwt.service')
const { validateAuthHeader, validateSecret } = require('./validation.util')
const { sendErrorResponse } = require('./utils')
const config = require('./config')
const redisHelper = require('./redis.config')
const crypto = require('crypto')

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

    await redisHelper.bootstrapRedis()

    // Verify once and attach the result for downstream handlers.
    const result = await verifyToken(token, req)
    req.auth = { token, ...result }

    return next()
  } catch (error) {
    return sendErrorResponse(res, error)
  }
}

/**
 * Creates rate limiting middleware to prevent brute force attacks
 * @param {number} [maxAttempts=5] - Maximum number of attempts allowed
 * @param {number} [windowMs=900000] - Time window in milliseconds (default: 15 minutes)
 * @returns {Function} Redis-backed Express middleware function
 * @example
 * app.use('/api/login', rateLimit(5, 15 * 60 * 1000)) // 5 attempts per 15 minutes
 */
exports.rateLimit = (maxAttempts = 5, windowMs = 15 * 60 * 1000) => {
  if (
    !Number.isInteger(maxAttempts) ||
    maxAttempts < 1 ||
    !Number.isFinite(windowMs) ||
    windowMs < 1
  ) {
    throw new TypeError('rateLimit requires a positive maxAttempts and windowMs')
  }

  return async (req, res, next) => {
    try {
      await redisHelper.bootstrapRedis()
      const identifier = req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress
      const digest = crypto
        .createHash('sha256')
        .update(identifier || 'unknown')
        .digest('hex')
      const key = `${config.redis.keyPrefix}rate-limit:${digest}`
      const { count, ttl } = await redisHelper.incrementWithWindow(key, windowMs)

      if (count > maxAttempts) {
        const retryAfter = Math.max(1, Math.ceil(ttl / 1000))
        res.set?.('Retry-After', String(retryAfter))
        return res.status(429).json({
          status: 'TOO_MANY_REQUESTS',
          message: `Too many attempts. Please try again in ${retryAfter} seconds`,
        })
      }

      return next()
    } catch (error) {
      return next(error)
    }
  }
}
