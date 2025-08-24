const jwtService = require('../jwt.service')
const { TokenError, ValidationError } = require('../errors')

describe('JWT Service', () => {
  describe('generateToken', () => {
    it('should generate access and refresh tokens', async () => {
      const userData = {
        userId: 'user123',
        email: 'test@example.com',
      }

      const result = await jwtService.generateToken(userData)

      expect(result).toHaveProperty('accessToken')
      expect(result).toHaveProperty('refreshToken')
      expect(result).toHaveProperty('expiresIn', '15m')
      expect(result).toHaveProperty('tokenType', 'Bearer')
      expect(typeof result.accessToken).toBe('string')
      expect(typeof result.refreshToken).toBe('string')
    })

    it('should store session data in Redis', async () => {
      const userData = {
        userId: 'user123',
        email: 'test@example.com',
      }

      await jwtService.generateToken(userData)

      expect(mockRedisClient.set).toHaveBeenCalledTimes(2) // session + refresh token
    })

    it('should throw ValidationError for invalid data', async () => {
      await expect(jwtService.generateToken({})).rejects.toThrow(ValidationError)
      await expect(jwtService.generateToken(null)).rejects.toThrow(ValidationError)
      await expect(jwtService.generateToken('string')).rejects.toThrow(ValidationError)
    })

    it('should throw ValidationError for missing JWT secret', async () => {
      // Test validation directly since config is cached
      const validation = require('../validation.util')
      expect(() => validation.validateSecret(undefined)).toThrow(ValidationError)
      expect(() => validation.validateSecret('')).toThrow(ValidationError)
      expect(() => validation.validateSecret(null)).toThrow(ValidationError)
    })
  })

  describe('verifyToken', () => {
    let validToken

    beforeEach(async () => {
      const userData = {
        userId: 'user123',
        email: 'test@example.com',
      }
      const result = await jwtService.generateToken(userData)
      validToken = result.accessToken
    })

    it('should verify valid token and return session data', async () => {
      const result = await jwtService.verifyToken(validToken)

      expect(result).toHaveProperty('valid', true)
      expect(result).toHaveProperty('decoded')
      expect(result).toHaveProperty('session')
      expect(result.decoded).toHaveProperty('userId', 'user123')
      expect(result.decoded).toHaveProperty('type', 'access')
      expect(result.session).toHaveProperty('userId', 'user123')
    })

    it('should update last activity when verifying token', async () => {
      const result1 = await jwtService.verifyToken(validToken)
      const firstActivity = result1.session.lastActivity

      // Wait a bit and verify again
      await new Promise((resolve) => setTimeout(resolve, 10))
      const result2 = await jwtService.verifyToken(validToken)
      const secondActivity = result2.session.lastActivity

      expect(new Date(secondActivity)).toBeInstanceOf(Date)
      expect(secondActivity).not.toBe(firstActivity)
    })

    it('should throw TokenError for invalid token', async () => {
      await expect(jwtService.verifyToken('invalid-token')).rejects.toThrow(TokenError)
    })

    it('should throw TokenError for expired token', async () => {
      // Mock an expired token by manipulating JWT
      const jwt = require('jsonwebtoken')
      const expiredToken = jwt.sign(
        {
          sessionId: 'test',
          type: 'access',
          iss: 'jwt-redis-sessions',
          aud: 'jwt-redis-sessions-users',
        },
        process.env.JWT_SECRET,
        { expiresIn: '-1h' }
      )

      await expect(jwtService.verifyToken(expiredToken)).rejects.toThrow(TokenError)
    })

    it('should throw TokenError when session not found in Redis', async () => {
      // Clear Redis to simulate missing session
      mockRedisStore.clear()

      await expect(jwtService.verifyToken(validToken)).rejects.toThrow(TokenError)
    })

    it('should throw TokenError when token is blacklisted', async () => {
      // Blacklist the token first
      await jwtService.revokeToken(validToken)

      await expect(jwtService.verifyToken(validToken)).rejects.toThrow(TokenError)
      await expect(jwtService.verifyToken(validToken)).rejects.toThrow('Token has been revoked')
    })
  })

  describe('refreshToken', () => {
    let refreshToken

    beforeEach(async () => {
      const userData = {
        userId: 'user123',
        email: 'test@example.com',
      }
      const result = await jwtService.generateToken(userData)
      refreshToken = result.refreshToken
    })

    it('should generate new tokens using valid refresh token', async () => {
      const result = await jwtService.refreshToken(refreshToken)

      expect(result).toHaveProperty('accessToken')
      expect(result).toHaveProperty('refreshToken')
      expect(result.accessToken).not.toBe(refreshToken)
      expect(result.refreshToken).not.toBe(refreshToken)
    })

    it('should delete old refresh token (rotation)', async () => {
      const originalDelCalls = mockRedisClient.del.mock.calls.length

      await jwtService.refreshToken(refreshToken)

      expect(mockRedisClient.del).toHaveBeenCalledTimes(originalDelCalls + 1)
    })

    it('should throw TokenError for invalid refresh token', async () => {
      await expect(jwtService.refreshToken('invalid-token')).rejects.toThrow(TokenError)
    })

    it('should throw TokenError when refresh token not found in Redis', async () => {
      // Clear Redis to simulate missing refresh token
      mockRedisStore.clear()

      await expect(jwtService.refreshToken(refreshToken)).rejects.toThrow(TokenError)
    })
  })

  describe('revokeToken', () => {
    let accessToken

    beforeEach(async () => {
      const userData = { userId: 'user123', email: 'test@example.com' }
      const result = await jwtService.generateToken(userData)
      accessToken = result.accessToken
    })

    it('should revoke token and add to blacklist', async () => {
      const result = await jwtService.revokeToken(accessToken)

      expect(result).toHaveProperty('success', true)
      expect(result).toHaveProperty('message')
      expect(mockRedisClient.del).toHaveBeenCalledTimes(2) // session + refresh token
      expect(mockRedisClient.set).toHaveBeenCalledWith(
        expect.stringContaining('blacklist:'),
        '1',
        expect.any(Object)
      )
    })

    it('should handle invalid tokens gracefully', async () => {
      const result = await jwtService.revokeToken('invalid-token')

      expect(result).toHaveProperty('success', true)
      expect(result).toHaveProperty('message', 'Token already invalid')
    })
  })

  describe('isTokenBlacklisted', () => {
    it('should return false for non-blacklisted token', async () => {
      const result = await jwtService.isTokenBlacklisted('some-token')
      expect(result).toBe(false)
    })

    it('should return true for blacklisted token', async () => {
      // Manually add token to blacklist using the same key format the service uses
      const { redisKeys } = require('../utils')
      const blacklistKey = redisKeys.blacklistKey('some-token')
      mockRedisStore.set(blacklistKey, { value: '1' })

      const result = await jwtService.isTokenBlacklisted('some-token')
      expect(result).toBe(true)
    })

    it('should return false if Redis check fails', async () => {
      // Mock Redis error
      mockRedisClient.exists.mockRejectedValueOnce(new Error('Redis error'))

      const result = await jwtService.isTokenBlacklisted('some-token')
      expect(result).toBe(false)
    })
  })

  describe('getUserSessions', () => {
    beforeEach(async () => {
      // Create multiple sessions for the same user
      const userData = { userId: 'user123', email: 'test@example.com' }
      await jwtService.generateToken(userData)
      await jwtService.generateToken(userData)
    })

    it('should return all sessions for a user', async () => {
      const sessions = await jwtService.getUserSessions('user123')

      expect(Array.isArray(sessions)).toBe(true)
      expect(sessions.length).toBe(2)
      sessions.forEach((session) => {
        expect(session).toHaveProperty('userId', 'user123')
        expect(session).toHaveProperty('sessionId')
        expect(session).toHaveProperty('createdAt')
        expect(session).toHaveProperty('lastActivity')
      })
    })

    it('should return empty array for user with no sessions', async () => {
      const sessions = await jwtService.getUserSessions('nonexistent-user')
      expect(sessions).toEqual([])
    })
  })

  describe('revokeAllUserTokens', () => {
    beforeEach(async () => {
      const userData = { userId: 'user123', email: 'test@example.com' }
      await jwtService.generateToken(userData)
      await jwtService.generateToken(userData)
    })

    it('should revoke all tokens for a user', async () => {
      const result = await jwtService.revokeAllUserTokens('user123')

      expect(result).toHaveProperty('success', true)
      expect(result.message).toContain('Revoked 2 sessions')
      expect(mockRedisClient.del).toHaveBeenCalledTimes(4) // 2 sessions + 2 refresh tokens
    })

    it('should handle user with no sessions', async () => {
      const result = await jwtService.revokeAllUserTokens('nonexistent-user')

      expect(result).toHaveProperty('success', true)
      expect(result.message).toContain('Revoked 0 sessions')
    })
  })
})
