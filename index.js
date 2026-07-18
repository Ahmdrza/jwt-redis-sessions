const config = require('./config')
const redisConfig = require('./redis.config')
const jwtService = require('./jwt.service')
const authMiddleware = require('./auth.middleware')
const errors = require('./errors')
const { validateConfig } = require('./validation.util')
const { sendErrorResponse } = require('./utils')

// Initialize Redis connection
let isInitialized = false

const configure = (overrides = {}) => {
  if (isInitialized) {
    throw new errors.AuthError('Configuration cannot be changed after initialization', 500)
  }
  const sections = ['jwt', 'redis', 'security']
  for (const section of Object.keys(overrides)) {
    if (!sections.includes(section)) {
      throw new errors.ValidationError(`Unknown configuration section '${section}'`, 500)
    }
  }
  const candidate = {
    jwt: { ...config.jwt },
    redis: { ...config.redis },
    security: { ...config.security },
  }
  for (const section of sections) {
    if (overrides[section]) {
      for (const key of Object.keys(overrides[section])) {
        if (!Object.prototype.hasOwnProperty.call(config[section], key)) {
          throw new errors.ValidationError(`Unknown configuration option '${section}.${key}'`, 500)
        }
      }
      Object.assign(candidate[section], overrides[section])
      if (
        section === 'redis' &&
        !Object.prototype.hasOwnProperty.call(overrides.redis, 'url') &&
        (Object.prototype.hasOwnProperty.call(overrides.redis, 'host') ||
          Object.prototype.hasOwnProperty.call(overrides.redis, 'port'))
      ) {
        candidate.redis.url = `redis://${candidate.redis.host}:${candidate.redis.port}`
      }
    }
  }
  validateConfig(candidate)
  for (const section of sections) {
    Object.assign(config[section], candidate[section])
  }
  return config
}

const initialize = async (options = {}) => {
  if (!isInitialized) {
    if (options.config) {
      configure(options.config)
    }
    validateConfig(config)
    if (options.redisClient) {
      redisConfig.useRedisClient(options.redisClient)
    }
    await redisConfig.bootstrapRedis()
    isInitialized = true
  }
}

// Auto-initialize on first use
const wrapAsync = (fn) => {
  return async (...args) => {
    await initialize()
    return fn(...args)
  }
}

// JWT Service exports
exports.generateToken = wrapAsync(jwtService.generateToken)
exports.verifyToken = wrapAsync(jwtService.verifyToken)
exports.refreshToken = wrapAsync(jwtService.refreshToken)
exports.revokeToken = wrapAsync(jwtService.revokeToken)
exports.revokeAllUserTokens = wrapAsync(jwtService.revokeAllUserTokens)
exports.getUserSessions = wrapAsync(jwtService.getUserSessions)
exports.isTokenBlacklisted = wrapAsync(jwtService.isTokenBlacklisted)

// Middleware exports
exports.auth = async (req, res, next) => {
  try {
    await initialize()
    return await authMiddleware.auth(req, res, next)
  } catch (error) {
    return sendErrorResponse(res, error)
  }
}
exports.rateLimit = (...args) => {
  const middleware = authMiddleware.rateLimit(...args)
  return async (req, res, next) => {
    try {
      await initialize()
      return await middleware(req, res, next)
    } catch (error) {
      return next(error)
    }
  }
}

// Error classes exports
exports.AuthError = errors.AuthError
exports.ValidationError = errors.ValidationError
exports.TokenError = errors.TokenError
exports.RedisError = errors.RedisError

// Configuration exports
exports.config = config
exports.configure = configure
exports.initialize = initialize
exports.closeRedisConnection = async () => {
  await redisConfig.closeRedisConnection()
  isInitialized = false
}
