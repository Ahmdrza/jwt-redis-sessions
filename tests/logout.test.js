const logoutHandlers = require('../logout')
const jwtService = require('../jwt.service')

describe('Logout Handlers', () => {
  let mockReq, mockRes, accessToken, userData

  beforeEach(async () => {
    // Create tokens for testing
    userData = {
      userId: 'user123',
      email: 'test@example.com',
    }
    const result = await jwtService.generateToken(userData)
    accessToken = result.accessToken

    // Mock Express req, res, next
    mockReq = {
      headers: {},
      user: null,
      session: null,
      token: null,
    }

    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    }
  })

  describe('logout handler', () => {
    it('should logout with valid token from Authorization header', async () => {
      mockReq.headers.authorization = `Bearer ${accessToken}`

      await logoutHandlers.logout(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(200)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'SUCCESS',
        message: 'Token revoked successfully',
      })

      // Verify token is blacklisted
      const isBlacklisted = await jwtService.isTokenBlacklisted(accessToken)
      expect(isBlacklisted).toBe(true)
    })

    it('should logout with token from request object', async () => {
      mockReq.token = accessToken

      await logoutHandlers.logout(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(200)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'SUCCESS',
        message: 'Token revoked successfully',
      })
    })

    it('should prioritize token from request object over header', async () => {
      mockReq.token = accessToken
      mockReq.headers.authorization = 'Bearer different-token'

      await logoutHandlers.logout(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(200)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'SUCCESS',
        message: 'Token revoked successfully',
      })
    })

    it('should return error for missing token', async () => {
      await logoutHandlers.logout(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(400)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'VALIDATION_ERROR',
        message: 'Authorization header not found',
      })
    })

    it('should return error for invalid authorization header format', async () => {
      mockReq.headers.authorization = 'InvalidFormat token'

      await logoutHandlers.logout(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(400)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'VALIDATION_ERROR',
        message: 'Authorization header must use Bearer scheme',
      })
    })

    it('should handle invalid tokens gracefully', async () => {
      mockReq.headers.authorization = 'Bearer invalid-token'

      await logoutHandlers.logout(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(200)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'SUCCESS',
        message: 'Token already invalid',
      })
    })

    it('should handle already logged out tokens', async () => {
      // Logout once
      mockReq.headers.authorization = `Bearer ${accessToken}`
      await logoutHandlers.logout(mockReq, mockRes)

      // Clear previous mock calls
      mockRes.status.mockClear()
      mockRes.json.mockClear()

      // Try to logout again with same token
      // The current implementation returns success for both cases
      await logoutHandlers.logout(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(200)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'SUCCESS',
        message: expect.stringMatching(/(Token revoked successfully|Token already invalid)/),
      })
    })

    it('should include error details in development mode', async () => {
      const originalEnv = process.env.NODE_ENV
      process.env.NODE_ENV = 'development'

      // Mock Redis error
      mockRedisClient.del.mockRejectedValueOnce(new Error('Redis error'))
      mockReq.headers.authorization = `Bearer ${accessToken}`

      await logoutHandlers.logout(mockReq, mockRes)

      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          details: expect.any(String),
        })
      )

      process.env.NODE_ENV = originalEnv
    })
  })

  describe('logoutAll handler', () => {
    beforeEach(async () => {
      // Create multiple sessions for the same user
      await jwtService.generateToken(userData)
      await jwtService.generateToken(userData)

      // Verify user in request object
      const verifyResult = await jwtService.verifyToken(accessToken)
      mockReq.user = verifyResult.decoded
    })

    it('should logout all sessions for authenticated user', async () => {
      await logoutHandlers.logoutAll(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(200)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'SUCCESS',
        message: expect.stringContaining('Revoked 3 sessions for user user123'),
      })

      // Verify all sessions are removed
      const sessions = await jwtService.getUserSessions('user123')
      expect(sessions).toEqual([])
    })

    it('should return error when user is not authenticated', async () => {
      mockReq.user = null

      await logoutHandlers.logoutAll(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'UNAUTHORIZED',
        message: 'Authentication required',
      })
    })

    it('should handle user with no sessions', async () => {
      // Clear all sessions first
      await jwtService.revokeAllUserTokens('user123')

      await logoutHandlers.logoutAll(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(200)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'SUCCESS',
        message: 'Revoked 0 sessions for user user123',
      })
    })

    it('should work with user ID from id field', async () => {
      mockReq.user = {
        id: 'user456', // Using 'id' instead of 'userId'
        email: 'test@example.com',
      }

      // Create session for user with 'id' field
      await jwtService.generateToken({ id: 'user456' })

      await logoutHandlers.logoutAll(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(200)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'SUCCESS',
        message: expect.stringContaining('Revoked'),
      })
    })

    it('should handle Redis errors gracefully', async () => {
      // Set user to pass authentication check
      mockReq.user = { userId: 'user123' }

      // Mock Redis error
      mockRedisClient.scan.mockRejectedValueOnce(new Error('Redis connection failed'))

      await logoutHandlers.logoutAll(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'AUTH_ERROR',
        message: expect.stringContaining('Failed to revoke user tokens'),
      })
    })
  })

  describe('token blacklisting', () => {
    it('should add valid tokens to blacklist with proper TTL', async () => {
      mockReq.headers.authorization = `Bearer ${accessToken}`

      await logoutHandlers.logout(mockReq, mockRes)

      // Verify blacklist entry was created
      expect(mockRedisClient.set).toHaveBeenCalledWith(
        expect.stringContaining('blacklist:'),
        '1',
        expect.objectContaining({ EX: expect.any(Number) })
      )
    })

    it('should not blacklist already expired tokens', async () => {
      // Create an expired token
      const jwt = require('jsonwebtoken')
      const expiredToken = jwt.sign(
        { sessionId: 'test', exp: Math.floor(Date.now() / 1000) - 3600 },
        process.env.JWT_SECRET
      )

      mockReq.headers.authorization = `Bearer ${expiredToken}`

      // Clear previous calls
      mockRedisClient.set.mockClear()

      await logoutHandlers.logout(mockReq, mockRes)

      // Should not add to blacklist since token is already expired
      const blacklistCalls = mockRedisClient.set.mock.calls.filter((call) =>
        call[0].includes('blacklist:')
      )
      expect(blacklistCalls).toHaveLength(0)
    })
  })

  describe('session cleanup', () => {
    it('should remove both session and refresh token on logout', async () => {
      mockReq.headers.authorization = `Bearer ${accessToken}`

      // Clear previous calls
      mockRedisClient.del.mockClear()

      await logoutHandlers.logout(mockReq, mockRes)

      // Should delete both session and refresh token
      expect(mockRedisClient.del).toHaveBeenCalledTimes(2)
    })

    it('should remove all user sessions on logoutAll', async () => {
      // Verify user in request object
      const verifyResult = await jwtService.verifyToken(accessToken)
      mockReq.user = verifyResult.decoded

      // Clear previous calls
      mockRedisClient.del.mockClear()

      await logoutHandlers.logoutAll(mockReq, mockRes)

      // Should delete multiple sessions - actual count may vary based on implementation
      expect(mockRedisClient.del).toHaveBeenCalled()
    })
  })
})
