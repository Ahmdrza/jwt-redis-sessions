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

// Constant-time string comparison to prevent timing attacks
exports.constantTimeCompare = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false
  }

  if (a.length !== b.length) {
    return false
  }

  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }

  return result === 0
}
