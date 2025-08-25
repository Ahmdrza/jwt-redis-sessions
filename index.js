/* eslint-disable no-console */
require('dotenv').config()

const config = require('./config')
const redisConfig = require('./redis.config')
const jwtService = require('./jwt.service')
const authMiddleware = require('./auth.middleware')
const errors = require('./errors')

// Initialize Redis connection
let isInitialized = false

const initialize = async () => {
  if (!isInitialized) {
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
exports.auth = authMiddleware.auth
exports.rateLimit = authMiddleware.rateLimit

// Error classes exports
exports.AuthError = errors.AuthError
exports.ValidationError = errors.ValidationError
exports.TokenError = errors.TokenError
exports.RedisError = errors.RedisError

// Configuration exports
exports.config = config
exports.initialize = initialize
exports.closeRedisConnection = redisConfig.closeRedisConnection

// Graceful shutdown handler
const gracefulShutdown = async () => {
  console.log('Shutting down jwt-redis-sessions...')
  await redisConfig.closeRedisConnection()
  process.exit(0)
}

process.on('SIGINT', gracefulShutdown)
process.on('SIGTERM', gracefulShutdown)
