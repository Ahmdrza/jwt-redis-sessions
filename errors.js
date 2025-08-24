class AuthError extends Error {
  constructor(message, statusCode = 401, code = 'AUTH_ERROR') {
    super(message)
    this.name = 'AuthError'
    this.statusCode = statusCode
    this.code = code
  }
}

class ValidationError extends Error {
  constructor(message, statusCode = 400, code = 'VALIDATION_ERROR') {
    super(message)
    this.name = 'ValidationError'
    this.statusCode = statusCode
    this.code = code
  }
}

class TokenError extends Error {
  constructor(message, statusCode = 401, code = 'TOKEN_ERROR') {
    super(message)
    this.name = 'TokenError'
    this.statusCode = statusCode
    this.code = code
  }
}

class RedisError extends Error {
  constructor(message, statusCode = 500, code = 'REDIS_ERROR') {
    super(message)
    this.name = 'RedisError'
    this.statusCode = statusCode
    this.code = code
  }
}

module.exports = {
  AuthError,
  ValidationError,
  TokenError,
  RedisError,
}
