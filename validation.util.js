const { ValidationError } = require('./errors')

exports.validateAuthHeader = (authHeader) => {
  if (!authHeader) {
    throw new ValidationError('Authorization header not found')
  }

  if (typeof authHeader !== 'string') {
    throw new ValidationError('Invalid authorization header structure')
  }

  const parts = authHeader.split(' ')

  if (parts.length < 2) {
    throw new ValidationError('Invalid authorization header format')
  }

  if (parts[0] !== 'Bearer') {
    throw new ValidationError('Authorization header must use Bearer scheme')
  }

  if (!parts[1] || parts[1].trim() === '') {
    throw new ValidationError('Token not provided in authorization header')
  }

  if (parts.length !== 2) {
    throw new ValidationError('Invalid authorization header format')
  }

  return parts[1]
}

exports.validateTokenData = (data) => {
  // Allow null/undefined - will be converted to empty object
  if (data == null) {
    return true
  }

  // If provided, must be a plain object
  if (typeof data !== 'object' || data.constructor !== Object) {
    throw new ValidationError('Token data must be an object')
  }

  const config = require('./config')
  const allowedFields = new Set(config.security.allowedTokenFields)
  const reservedFields = new Set([
    'iat',
    'exp',
    'nbf',
    'iss',
    'aud',
    'sub',
    'jti',
    'sessionId',
    'type',
    '_fp',
    '_fpTime',
  ])
  const sensitivePattern = /(?:password|passwd|pwd|secret|hash|token|credential|private.?key)/i

  const validateValue = (field, value) => {
    if (
      value === null ||
      typeof value === 'string' ||
      (typeof value === 'number' && Number.isFinite(value)) ||
      typeof value === 'boolean'
    ) {
      return
    }
    if (
      Array.isArray(value) &&
      value.length <= 100 &&
      value.every(
        (item) =>
          item === null ||
          typeof item === 'string' ||
          (typeof item === 'number' && Number.isFinite(item)) ||
          typeof item === 'boolean'
      )
    ) {
      return
    }
    throw new ValidationError(
      `Token data field '${field}' must be a primitive or an array of primitives`
    )
  }

  for (const [field, value] of Object.entries(data)) {
    if (reservedFields.has(field)) {
      throw new ValidationError(`Token data field '${field}' is reserved`)
    }
    if (sensitivePattern.test(field)) {
      throw new ValidationError(`Sensitive token data field '${field}' is not allowed`)
    }
    if (!allowedFields.has(field)) {
      throw new ValidationError(
        `Token data field '${field}' is not allowed; configure JWT_ALLOWED_TOKEN_FIELDS explicitly`
      )
    }
    if (['userId', 'id', 'email'].includes(field) && (typeof value !== 'string' || !value)) {
      throw new ValidationError(`Token data field '${field}' must be a non-empty string`)
    }
    validateValue(field, value)
  }

  let serialized
  try {
    serialized = JSON.stringify(data)
  } catch {
    throw new ValidationError('Token data must be JSON serializable')
  }
  if (serialized.length > 4096) {
    throw new ValidationError('Token data must not exceed 4096 bytes')
  }

  return true
}

exports.validateSecret = (secret) => {
  if (!secret) {
    throw new ValidationError('JWT_SECRET environment variable is required', 500)
  }

  if (typeof secret !== 'string') {
    throw new ValidationError('JWT_SECRET must be a string', 500)
  }

  if (secret.length < 32) {
    throw new ValidationError('JWT_SECRET must be at least 32 characters long', 500)
  }

  return true
}

exports.validateConfig = (config) => {
  exports.validateSecret(config.jwt.secret)
  for (const [name, value] of [
    ['redis.sessionTTL', config.redis.sessionTTL],
    ['redis.refreshTokenTTL', config.redis.refreshTokenTTL],
    ['security.tokenLength', config.security.tokenLength],
  ]) {
    if (!Number.isInteger(value) || value < 1) {
      throw new ValidationError(`${name} must be a positive integer`, 500)
    }
  }
  if (config.security.tokenLength < 16) {
    throw new ValidationError('security.tokenLength must be at least 16 bytes', 500)
  }
  if (!Array.isArray(config.security.allowedTokenFields)) {
    throw new ValidationError('security.allowedTokenFields must be an array', 500)
  }
  if (typeof config.redis.keyPrefix !== 'string' || !config.redis.keyPrefix) {
    throw new ValidationError('redis.keyPrefix must be a non-empty string', 500)
  }
  return true
}

// Constant-time string comparison to prevent timing attacks
exports.constantTimeCompare = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false
  }

  const aBuffer = Buffer.from(a)
  const bBuffer = Buffer.from(b)
  return aBuffer.length === bBuffer.length && require('crypto').timingSafeEqual(aBuffer, bBuffer)
}
