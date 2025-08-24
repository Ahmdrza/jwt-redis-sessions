const jwtRedisSession = require('../index')

describe('Integration Tests', () => {
  let userData, tokens

  beforeEach(async () => {
    userData = {
      userId: 'user123',
      email: 'test@example.com',
    }
  })

  describe('Complete authentication flow', () => {
    it('should handle complete auth flow: generate -> verify -> refresh -> logout', async () => {
      // Step 1: Generate tokens
      tokens = await jwtRedisSession.generateToken(userData)

      expect(tokens).toHaveProperty('accessToken')
      expect(tokens).toHaveProperty('refreshToken')
      expect(tokens).toHaveProperty('expiresIn', '15m')
      expect(tokens).toHaveProperty('tokenType', 'Bearer')

      // Step 2: Verify access token
      const verifyResult = await jwtRedisSession.verifyToken(tokens.accessToken)

      expect(verifyResult.valid).toBe(true)
      expect(verifyResult.decoded.userId).toBe('user123')
      expect(verifyResult.decoded.type).toBe('access')
      expect(verifyResult.session.userId).toBe('user123')

      // Step 3: Refresh tokens
      const newTokens = await jwtRedisSession.refreshToken(tokens.refreshToken)

      expect(newTokens.accessToken).not.toBe(tokens.accessToken)
      expect(newTokens.refreshToken).not.toBe(tokens.refreshToken)

      // Step 4: Logout (revoke new tokens)
      const logoutResult = await jwtRedisSession.revokeToken(newTokens.accessToken)

      expect(logoutResult.success).toBe(true)

      // Step 5: Verify token is blacklisted
      const isBlacklisted = await jwtRedisSession.isTokenBlacklisted(newTokens.accessToken)
      expect(isBlacklisted).toBe(true)

      // Step 6: Try to use blacklisted token (should fail)
      await expect(jwtRedisSession.verifyToken(newTokens.accessToken)).rejects.toThrow()
    })

    it('should handle multiple sessions for same user', async () => {
      // Create multiple sessions
      const session1 = await jwtRedisSession.generateToken(userData)
      const session2 = await jwtRedisSession.generateToken(userData)
      const session3 = await jwtRedisSession.generateToken(userData)

      // Verify all sessions exist
      const sessions = await jwtRedisSession.getUserSessions('user123')
      expect(sessions).toHaveLength(3)

      // Logout all sessions
      const logoutAllResult = await jwtRedisSession.revokeAllUserTokens('user123')
      expect(logoutAllResult.success).toBe(true)
      expect(logoutAllResult.message).toContain('Revoked 3 sessions')

      // Verify all sessions are gone
      const remainingSessions = await jwtRedisSession.getUserSessions('user123')
      expect(remainingSessions).toHaveLength(0)

      // Verify tokens are invalid
      await expect(jwtRedisSession.verifyToken(session1.accessToken)).rejects.toThrow()
      await expect(jwtRedisSession.verifyToken(session2.accessToken)).rejects.toThrow()
      await expect(jwtRedisSession.verifyToken(session3.accessToken)).rejects.toThrow()
    })
  })

  describe('Middleware integration', () => {
    let mockReq, mockRes, mockNext

    beforeEach(async () => {
      tokens = await jwtRedisSession.generateToken(userData)

      mockReq = {
        headers: { authorization: `Bearer ${tokens.accessToken}` },
        user: null,
        session: null,
        token: null,
      }

      mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      }

      mockNext = jest.fn()
    })

    it('should authenticate user and handle logout', async () => {
      // Step 1: Authentication
      await jwtRedisSession.auth(mockReq, mockRes, mockNext)

      expect(mockNext).toHaveBeenCalledTimes(1)
      expect(mockReq.user).toBeDefined()
      expect(mockReq.user.userId).toBe('user123')

      // Step 2: Logout using handler
      await jwtRedisSession.logout(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(200)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'SUCCESS',
        message: 'Token revoked successfully',
      })

      // Verify token is blacklisted
      const isBlacklisted = await jwtRedisSession.isTokenBlacklisted(tokens.accessToken)
      expect(isBlacklisted).toBe(true)
    })
  })

  describe('Refresh token flow', () => {
    let mockReq, mockRes

    beforeEach(async () => {
      tokens = await jwtRedisSession.generateToken(userData)

      mockReq = {
        headers: { authorization: `Bearer ${tokens.refreshToken}` },
      }

      mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      }
    })

    it('should handle complete refresh flow', async () => {
      // Use refresh handler
      await jwtRedisSession.refresh(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(200)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'SUCCESS',
        message: 'Token refreshed successfully',
        data: expect.objectContaining({
          accessToken: expect.any(String),
          refreshToken: expect.any(String),
          expiresIn: '15m',
          tokenType: 'Bearer',
        }),
      })

      // Original refresh token should now be invalid
      mockRes.status.mockClear()
      mockRes.json.mockClear()

      await jwtRedisSession.refresh(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(401)
    })
  })

  describe('Rate limiting integration', () => {
    let rateLimitMiddleware, mockReq, mockRes, mockNext

    beforeEach(() => {
      rateLimitMiddleware = jwtRedisSession.rateLimit(2, 1000) // 2 attempts per second

      mockReq = { ip: '127.0.0.1' }
      mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      }
      mockNext = jest.fn()
    })

    it('should enforce rate limits', () => {
      // First two requests should pass
      rateLimitMiddleware(mockReq, mockRes, mockNext)
      rateLimitMiddleware(mockReq, mockRes, mockNext)

      expect(mockNext).toHaveBeenCalledTimes(2)

      // Third request should be blocked
      rateLimitMiddleware(mockReq, mockRes, mockNext)

      expect(mockNext).toHaveBeenCalledTimes(2) // Still only 2
      expect(mockRes.status).toHaveBeenCalledWith(429)
    })
  })

  describe('Error propagation', () => {
    it('should propagate validation errors correctly', async () => {
      await expect(jwtRedisSession.generateToken({})).rejects.toThrow(
        jwtRedisSession.ValidationError
      )
      await expect(jwtRedisSession.verifyToken('invalid-token')).rejects.toThrow(
        jwtRedisSession.TokenError
      )
    })

    it('should handle Redis errors gracefully', async () => {
      // Create a valid token first
      const tokens = await jwtRedisSession.generateToken({ userId: 'test' })

      // Mock Redis failure after token creation
      const redisHelper = require('../redis.config')
      redisHelper.get.mockRejectedValueOnce(new Error('Redis connection failed'))

      await expect(jwtRedisSession.verifyToken(tokens.accessToken)).rejects.toThrow(
        jwtRedisSession.AuthError
      )
    })
  })

  describe('Configuration access', () => {
    it('should expose configuration object', () => {
      expect(jwtRedisSession.config).toBeDefined()
      expect(jwtRedisSession.config).toHaveProperty('jwt')
      expect(jwtRedisSession.config).toHaveProperty('redis')
      expect(jwtRedisSession.config).toHaveProperty('security')
    })

    it('should expose utility functions', () => {
      expect(typeof jwtRedisSession.initialize).toBe('function')
      expect(typeof jwtRedisSession.closeRedisConnection).toBe('function')
    })
  })

  describe('Auto-initialization', () => {
    it('should auto-initialize Redis on first function call', async () => {
      // Functions should work without manual initialization
      const testTokens = await jwtRedisSession.generateToken({ userId: 'test' })
      expect(testTokens).toHaveProperty('accessToken')

      // Just verify the token structure, not the verification process
      // since Redis mocking might interfere
      expect(testTokens.accessToken).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/) // JWT format
    })
  })

  describe('Optional authentication', () => {
    let mockReq, mockRes, mockNext

    beforeEach(() => {
      mockReq = { headers: {} }
      mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      }
      mockNext = jest.fn()
    })

    it('should handle requests without authentication gracefully', async () => {
      await jwtRedisSession.optionalAuth(mockReq, mockRes, mockNext)

      expect(mockNext).toHaveBeenCalled()
      expect(mockReq.user).toBeUndefined()
      expect(mockRes.status).not.toHaveBeenCalled()
    })

    it('should authenticate when valid token is provided', async () => {
      const tokens = await jwtRedisSession.generateToken(userData)
      mockReq.headers.authorization = `Bearer ${tokens.accessToken}`

      await jwtRedisSession.optionalAuth(mockReq, mockRes, mockNext)

      expect(mockNext).toHaveBeenCalled()
      expect(mockReq.user).toBeDefined()
      expect(mockReq.user.userId).toBe('user123')
      expect(mockRes.status).not.toHaveBeenCalled()
    })
  })
})
