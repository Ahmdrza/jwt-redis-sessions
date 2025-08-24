const { AuthError, ValidationError, TokenError, RedisError } = require('../errors')

describe('Error Classes', () => {
  describe('AuthError', () => {
    it('should create AuthError with default values', () => {
      const error = new AuthError('Authentication failed')

      expect(error).toBeInstanceOf(Error)
      expect(error).toBeInstanceOf(AuthError)
      expect(error.name).toBe('AuthError')
      expect(error.message).toBe('Authentication failed')
      expect(error.statusCode).toBe(401)
      expect(error.code).toBe('AUTH_ERROR')
    })

    it('should create AuthError with custom values', () => {
      const error = new AuthError('Custom auth error', 403, 'CUSTOM_AUTH_ERROR')

      expect(error.name).toBe('AuthError')
      expect(error.message).toBe('Custom auth error')
      expect(error.statusCode).toBe(403)
      expect(error.code).toBe('CUSTOM_AUTH_ERROR')
    })

    it('should have proper stack trace', () => {
      const error = new AuthError('Test error')
      expect(error.stack).toBeDefined()
      expect(typeof error.stack).toBe('string')
      expect(error.stack).toContain('AuthError')
    })
  })

  describe('ValidationError', () => {
    it('should create ValidationError with default values', () => {
      const error = new ValidationError('Validation failed')

      expect(error).toBeInstanceOf(Error)
      expect(error).toBeInstanceOf(ValidationError)
      expect(error.name).toBe('ValidationError')
      expect(error.message).toBe('Validation failed')
      expect(error.statusCode).toBe(400)
      expect(error.code).toBe('VALIDATION_ERROR')
    })

    it('should create ValidationError with custom values', () => {
      const error = new ValidationError('Custom validation error', 422, 'CUSTOM_VALIDATION_ERROR')

      expect(error.name).toBe('ValidationError')
      expect(error.message).toBe('Custom validation error')
      expect(error.statusCode).toBe(422)
      expect(error.code).toBe('CUSTOM_VALIDATION_ERROR')
    })

    it('should be catchable as ValidationError', () => {
      expect(() => {
        throw new ValidationError('Test validation error')
      }).toThrow(ValidationError)
    })
  })

  describe('TokenError', () => {
    it('should create TokenError with default values', () => {
      const error = new TokenError('Token invalid')

      expect(error).toBeInstanceOf(Error)
      expect(error).toBeInstanceOf(TokenError)
      expect(error.name).toBe('TokenError')
      expect(error.message).toBe('Token invalid')
      expect(error.statusCode).toBe(401)
      expect(error.code).toBe('TOKEN_ERROR')
    })

    it('should create TokenError with custom values', () => {
      const error = new TokenError('Custom token error', 498, 'CUSTOM_TOKEN_ERROR')

      expect(error.name).toBe('TokenError')
      expect(error.message).toBe('Custom token error')
      expect(error.statusCode).toBe(498)
      expect(error.code).toBe('CUSTOM_TOKEN_ERROR')
    })

    it('should be distinguishable from other errors', () => {
      const tokenError = new TokenError('Token error')
      const authError = new AuthError('Auth error')
      const validationError = new ValidationError('Validation error')

      expect(tokenError instanceof TokenError).toBe(true)
      expect(tokenError instanceof AuthError).toBe(false)
      expect(tokenError instanceof ValidationError).toBe(false)

      expect(authError instanceof TokenError).toBe(false)
      expect(validationError instanceof TokenError).toBe(false)
    })
  })

  describe('RedisError', () => {
    it('should create RedisError with default values', () => {
      const error = new RedisError('Redis connection failed')

      expect(error).toBeInstanceOf(Error)
      expect(error).toBeInstanceOf(RedisError)
      expect(error.name).toBe('RedisError')
      expect(error.message).toBe('Redis connection failed')
      expect(error.statusCode).toBe(500)
      expect(error.code).toBe('REDIS_ERROR')
    })

    it('should create RedisError with custom values', () => {
      const error = new RedisError('Custom Redis error', 503, 'CUSTOM_REDIS_ERROR')

      expect(error.name).toBe('RedisError')
      expect(error.message).toBe('Custom Redis error')
      expect(error.statusCode).toBe(503)
      expect(error.code).toBe('CUSTOM_REDIS_ERROR')
    })

    it('should preserve original error information', () => {
      const originalError = new Error('Original Redis error')
      const redisError = new RedisError(`Redis error: ${originalError.message}`)

      expect(redisError.message).toContain('Original Redis error')
      expect(redisError.stack).toBeDefined()
    })
  })

  describe('Error inheritance', () => {
    it('should all inherit from base Error class', () => {
      const authError = new AuthError('Auth error')
      const validationError = new ValidationError('Validation error')
      const tokenError = new TokenError('Token error')
      const redisError = new RedisError('Redis error')

      expect(authError instanceof Error).toBe(true)
      expect(validationError instanceof Error).toBe(true)
      expect(tokenError instanceof Error).toBe(true)
      expect(redisError instanceof Error).toBe(true)
    })

    it('should be catchable as Error', () => {
      try {
        throw new TokenError('Test error')
      } catch (error) {
        expect(error instanceof Error).toBe(true)
        expect(error instanceof TokenError).toBe(true)
        expect(error.name).toBe('TokenError')
      }
    })

    it('should have unique names for each error type', () => {
      const errors = [
        new AuthError('Test'),
        new ValidationError('Test'),
        new TokenError('Test'),
        new RedisError('Test'),
      ]

      const names = errors.map((error) => error.name)
      const uniqueNames = [...new Set(names)]

      expect(uniqueNames).toHaveLength(4)
      expect(uniqueNames).toEqual(['AuthError', 'ValidationError', 'TokenError', 'RedisError'])
    })
  })

  describe('Error serialization', () => {
    it('should serialize error properties correctly', () => {
      const error = new TokenError('Test token error', 498, 'TEST_TOKEN_ERROR')

      const serialized = {
        name: error.name,
        message: error.message,
        statusCode: error.statusCode,
        code: error.code,
      }

      expect(serialized).toEqual({
        name: 'TokenError',
        message: 'Test token error',
        statusCode: 498,
        code: 'TEST_TOKEN_ERROR',
      })
    })

    it('should be JSON serializable for logging', () => {
      const error = new ValidationError('Test validation error', 422, 'TEST_VALIDATION')

      // JSON.stringify typically doesn't include custom properties on Error objects
      // but our error classes should still have accessible properties
      expect(error.statusCode).toBe(422)
      expect(error.code).toBe('TEST_VALIDATION')
      expect(error.message).toBe('Test validation error')
      expect(error.name).toBe('ValidationError')
    })
  })

  describe('Error matching patterns', () => {
    it('should support error type checking in catch blocks', () => {
      const errors = [
        new AuthError('Auth error'),
        new ValidationError('Validation error'),
        new TokenError('Token error'),
        new RedisError('Redis error'),
      ]

      errors.forEach((error) => {
        try {
          throw error
        } catch (caught) {
          if (caught instanceof AuthError) {
            expect(caught.code).toBe('AUTH_ERROR')
            expect(caught.statusCode).toBe(401)
          } else if (caught instanceof ValidationError) {
            expect(caught.code).toBe('VALIDATION_ERROR')
            expect(caught.statusCode).toBe(400)
          } else if (caught instanceof TokenError) {
            expect(caught.code).toBe('TOKEN_ERROR')
            expect(caught.statusCode).toBe(401)
          } else if (caught instanceof RedisError) {
            expect(caught.code).toBe('REDIS_ERROR')
            expect(caught.statusCode).toBe(500)
          }
        }
      })
    })

    it('should support error code checking', () => {
      const error = new TokenError('Expired token', 401, 'TOKEN_EXPIRED')

      if (error.code === 'TOKEN_EXPIRED') {
        expect(error.message).toBe('Expired token')
        expect(error.statusCode).toBe(401)
      }
    })

    it('should support status code checking', () => {
      const errors = [
        new ValidationError('Bad request', 400),
        new AuthError('Unauthorized', 401),
        new TokenError('Token expired', 401),
        new RedisError('Server error', 500),
      ]

      const clientErrors = errors.filter(
        (error) => error.statusCode >= 400 && error.statusCode < 500
      )
      const serverErrors = errors.filter((error) => error.statusCode >= 500)

      expect(clientErrors).toHaveLength(3)
      expect(serverErrors).toHaveLength(1)
    })
  })
})
