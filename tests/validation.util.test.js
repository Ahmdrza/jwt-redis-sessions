const validation = require('../validation.util')
const { ValidationError } = require('../errors')

describe('Validation Utilities', () => {
  describe('validateAuthHeader', () => {
    it('should extract token from valid Bearer authorization header', () => {
      const token = validation.validateAuthHeader('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')
      expect(token).toBe('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')
    })

    it('should throw ValidationError for missing authorization header', () => {
      expect(() => validation.validateAuthHeader()).toThrow(ValidationError)
      expect(() => validation.validateAuthHeader(null)).toThrow(ValidationError)
      expect(() => validation.validateAuthHeader(undefined)).toThrow(ValidationError)
      expect(() => validation.validateAuthHeader('')).toThrow(ValidationError)
    })

    it('should throw ValidationError for non-string authorization header', () => {
      expect(() => validation.validateAuthHeader(123)).toThrow(ValidationError)
      expect(() => validation.validateAuthHeader({})).toThrow(ValidationError)
      expect(() => validation.validateAuthHeader([])).toThrow(ValidationError)
      expect(() => validation.validateAuthHeader(true)).toThrow(ValidationError)
    })

    it('should throw ValidationError for malformed authorization header', () => {
      expect(() => validation.validateAuthHeader('Bearer')).toThrow(ValidationError)
      expect(() => validation.validateAuthHeader('Bearer ')).toThrow(ValidationError)
      expect(() => validation.validateAuthHeader('InvalidScheme token')).toThrow(ValidationError)
      expect(() => validation.validateAuthHeader('Basic token')).toThrow(ValidationError)
      expect(() => validation.validateAuthHeader('token-without-scheme')).toThrow(ValidationError)
    })

    it('should throw ValidationError for Bearer with multiple spaces', () => {
      expect(() => validation.validateAuthHeader('Bearer  token  extra')).toThrow(ValidationError)
      expect(() => validation.validateAuthHeader('Bearer token extra parts')).toThrow(
        ValidationError
      )
    })

    it('should throw specific error messages', () => {
      try {
        validation.validateAuthHeader()
      } catch (error) {
        expect(error.message).toBe('Authorization header not found')
      }

      try {
        validation.validateAuthHeader(123)
      } catch (error) {
        expect(error.message).toBe('Invalid authorization header structure')
      }

      try {
        validation.validateAuthHeader('Basic token')
      } catch (error) {
        expect(error.message).toBe('Authorization header must use Bearer scheme')
      }

      try {
        validation.validateAuthHeader('Bearer ')
      } catch (error) {
        expect(error.message).toBe('Token not provided in authorization header')
      }
    })

    it('should handle edge cases', () => {
      // Valid token with special characters
      const validToken = validation.validateAuthHeader('Bearer abc.def.ghi-123_456')
      expect(validToken).toBe('abc.def.ghi-123_456')

      // Case sensitivity
      expect(() => validation.validateAuthHeader('bearer token')).toThrow(ValidationError)
      expect(() => validation.validateAuthHeader('BEARER token')).toThrow(ValidationError)
    })
  })

  describe('validateTokenData', () => {
    it('should validate correct token data with userId', () => {
      const validData = { userId: 'user123', email: 'test@example.com' }
      expect(() => validation.validateTokenData(validData)).not.toThrow()
    })

    it('should validate correct token data with id', () => {
      const validData = { id: 'user123', email: 'test@example.com' }
      expect(() => validation.validateTokenData(validData)).not.toThrow()
    })

    it('should validate correct token data with email', () => {
      const validData = { email: 'test@example.com' }
      expect(() => validation.validateTokenData(validData)).not.toThrow()
    })

    it('should throw ValidationError for null or undefined data', () => {
      expect(() => validation.validateTokenData(null)).toThrow(ValidationError)
      expect(() => validation.validateTokenData(undefined)).toThrow(ValidationError)
    })

    it('should throw ValidationError for non-object data', () => {
      expect(() => validation.validateTokenData('string')).toThrow(ValidationError)
      expect(() => validation.validateTokenData(123)).toThrow(ValidationError)
      expect(() => validation.validateTokenData(true)).toThrow(ValidationError)
      expect(() => validation.validateTokenData([])).toThrow(ValidationError)
    })

    it('should throw ValidationError for objects with wrong constructor', () => {
      class CustomClass {}
      const customInstance = new CustomClass()
      customInstance.userId = 'user123'

      expect(() => validation.validateTokenData(customInstance)).toThrow(ValidationError)
      expect(() => validation.validateTokenData(new Date())).toThrow(ValidationError)
    })

    it('should throw ValidationError for empty object', () => {
      expect(() => validation.validateTokenData({})).toThrow(ValidationError)
    })

    it('should throw ValidationError for object without required fields', () => {
      expect(() => validation.validateTokenData({ name: 'John', age: 30 })).toThrow(ValidationError)
      expect(() => validation.validateTokenData({ name: 'Admin User' })).toThrow(ValidationError)
    })

    it('should accept object with additional fields', () => {
      const validData = {
        userId: 'user123',
        email: 'test@example.com',
        profile: { name: 'John Doe', age: 30 },
        metadata: { lastLogin: new Date() },
      }

      expect(() => validation.validateTokenData(validData)).not.toThrow()
    })

    it('should throw specific error messages', () => {
      try {
        validation.validateTokenData(null)
      } catch (error) {
        expect(error.message).toBe('Token data must be an object')
      }

      try {
        validation.validateTokenData('string')
      } catch (error) {
        expect(error.message).toBe('Token data must be an object')
      }

      try {
        validation.validateTokenData(new Date())
      } catch (error) {
        expect(error.message).toBe('Invalid token data structure')
      }

      try {
        validation.validateTokenData({})
      } catch (error) {
        expect(error.message).toBe('Token data must contain userId, id, or email')
      }
    })

    it('should return true for valid data', () => {
      const validData = { userId: 'user123' }
      const result = validation.validateTokenData(validData)
      expect(result).toBe(true)
    })
  })

  describe('validateSecret', () => {
    const originalSecret = process.env.JWT_SECRET

    afterEach(() => {
      process.env.JWT_SECRET = originalSecret
    })

    it('should validate correct JWT secret', () => {
      const validSecret = 'this-is-a-valid-jwt-secret-with-32-characters'
      expect(() => validation.validateSecret(validSecret)).not.toThrow()
    })

    it('should throw ValidationError for missing secret', () => {
      expect(() => validation.validateSecret()).toThrow(ValidationError)
      expect(() => validation.validateSecret(null)).toThrow(ValidationError)
      expect(() => validation.validateSecret(undefined)).toThrow(ValidationError)
      expect(() => validation.validateSecret('')).toThrow(ValidationError)
    })

    it('should throw ValidationError for non-string secret', () => {
      expect(() => validation.validateSecret(123)).toThrow(ValidationError)
      expect(() => validation.validateSecret({})).toThrow(ValidationError)
      expect(() => validation.validateSecret([])).toThrow(ValidationError)
      expect(() => validation.validateSecret(true)).toThrow(ValidationError)
    })

    it('should throw ValidationError for short secret', () => {
      expect(() => validation.validateSecret('short')).toThrow(ValidationError)
      expect(() => validation.validateSecret('a-secret-that-is-too-short')).toThrow(ValidationError)
      expect(() => validation.validateSecret('12345678901234567890123456789012')).not.toThrow() // exactly 32 chars
      expect(() => validation.validateSecret('1234567890123456789012345678901')).toThrow(
        ValidationError
      ) // 31 chars
    })

    it('should throw specific error messages', () => {
      try {
        validation.validateSecret()
      } catch (error) {
        expect(error.message).toBe('JWT_SECRET environment variable is required')
        expect(error.statusCode).toBe(500)
      }

      try {
        validation.validateSecret(123)
      } catch (error) {
        expect(error.message).toBe('JWT_SECRET must be a string')
        expect(error.statusCode).toBe(500)
      }

      try {
        validation.validateSecret('short')
      } catch (error) {
        expect(error.message).toBe('JWT_SECRET must be at least 32 characters long')
        expect(error.statusCode).toBe(500)
      }
    })

    it('should return true for valid secret', () => {
      const validSecret = 'this-is-a-valid-jwt-secret-with-32-characters'
      const result = validation.validateSecret(validSecret)
      expect(result).toBe(true)
    })

    it('should handle very long secrets', () => {
      const longSecret = 'a'.repeat(100)
      expect(() => validation.validateSecret(longSecret)).not.toThrow()
    })

    it('should handle secrets with special characters', () => {
      const specialSecret = 'my-jwt-secret-with-special-chars-!@#$%^&*()_+-=[]{}|;:,.<>?'
      expect(() => validation.validateSecret(specialSecret)).not.toThrow()
    })
  })

  describe('ValidationError properties', () => {
    it('should create ValidationError with correct properties', () => {
      try {
        validation.validateAuthHeader()
      } catch (error) {
        expect(error).toBeInstanceOf(ValidationError)
        expect(error.name).toBe('ValidationError')
        expect(error.statusCode).toBe(400)
        expect(error.code).toBe('VALIDATION_ERROR')
      }
    })

    it('should create ValidationError with server status code for secret validation', () => {
      try {
        validation.validateSecret()
      } catch (error) {
        expect(error).toBeInstanceOf(ValidationError)
        expect(error.statusCode).toBe(500)
      }
    })

    it('should preserve stack trace', () => {
      try {
        validation.validateTokenData(null)
      } catch (error) {
        expect(error.stack).toBeDefined()
        expect(typeof error.stack).toBe('string')
        expect(error.stack).toContain('validateTokenData')
      }
    })
  })

  describe('Integration with other validation functions', () => {
    it('should work together in typical authentication flow', () => {
      const authHeader = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
      const tokenData = { userId: 'user123', email: 'test@example.com' }
      const secret = 'this-is-a-valid-jwt-secret-with-32-characters'

      expect(() => {
        validation.validateAuthHeader(authHeader)
        validation.validateTokenData(tokenData)
        validation.validateSecret(secret)
      }).not.toThrow()
    })

    it('should fail authentication flow with invalid data', () => {
      const invalidAuthHeader = 'Basic invalid-token'
      const invalidTokenData = { name: 'John' } // missing required fields
      const invalidSecret = 'short' // too short

      expect(() => validation.validateAuthHeader(invalidAuthHeader)).toThrow(ValidationError)
      expect(() => validation.validateTokenData(invalidTokenData)).toThrow(ValidationError)
      expect(() => validation.validateSecret(invalidSecret)).toThrow(ValidationError)
    })
  })

  describe('constantTimeCompare', () => {
    it('should return true for identical strings', () => {
      expect(validation.constantTimeCompare('hello', 'hello')).toBe(true)
      expect(validation.constantTimeCompare('test123', 'test123')).toBe(true)
      expect(validation.constantTimeCompare('', '')).toBe(true)
    })

    it('should return false for different strings', () => {
      expect(validation.constantTimeCompare('hello', 'world')).toBe(false)
      expect(validation.constantTimeCompare('test123', 'test456')).toBe(false)
      expect(validation.constantTimeCompare('abc', 'def')).toBe(false)
    })

    it('should return false for strings of different lengths', () => {
      expect(validation.constantTimeCompare('hello', 'hell')).toBe(false)
      expect(validation.constantTimeCompare('short', 'very long string')).toBe(false)
      expect(validation.constantTimeCompare('', 'nonempty')).toBe(false)
    })

    it('should return false for non-string inputs', () => {
      expect(validation.constantTimeCompare(123, 123)).toBe(false)
      expect(validation.constantTimeCompare('hello', 123)).toBe(false)
      expect(validation.constantTimeCompare(null, null)).toBe(false)
      expect(validation.constantTimeCompare(undefined, undefined)).toBe(false)
      expect(validation.constantTimeCompare({}, {})).toBe(false)
      expect(validation.constantTimeCompare([], [])).toBe(false)
    })

    it('should handle special characters and unicode', () => {
      expect(validation.constantTimeCompare('hello@world!', 'hello@world!')).toBe(true)
      expect(validation.constantTimeCompare('🔒🔑', '🔒🔑')).toBe(true)
      expect(validation.constantTimeCompare('åäö', 'åäö')).toBe(true)
      expect(validation.constantTimeCompare('hello@world!', 'hello@world?')).toBe(false)
    })

    it('should have constant execution time for same-length strings', () => {
      // This is more of a structural test - we can't easily measure timing in unit tests
      const str1 = 'a'.repeat(100)
      const str2 = 'b'.repeat(100)
      const str3 = 'a'.repeat(99) + 'b'

      // Both should return false, regardless of where the difference is
      expect(validation.constantTimeCompare(str1, str2)).toBe(false)
      expect(validation.constantTimeCompare(str1, str3)).toBe(false)
    })
  })
})
