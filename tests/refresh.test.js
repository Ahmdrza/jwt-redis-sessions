const refreshHandlers = require('../refresh')
const jwtService = require('../jwt.service')

describe('Refresh Handlers', () => {
  let mockReq, mockRes, refreshToken

  beforeEach(async () => {
    // Create a valid refresh token for testing
    const userData = {
      userId: 'user123',
      email: 'test@example.com',
    }
    const result = await jwtService.generateToken(userData)
    refreshToken = result.refreshToken

    // Mock Express req, res, next
    mockReq = {
      headers: {},
      newTokens: null,
    }

    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    }
  })

  describe('refresh handler', () => {
    it('should refresh tokens with valid refresh token', async () => {
      mockReq.headers.authorization = `Bearer ${refreshToken}`

      await refreshHandlers.refresh(mockReq, mockRes)

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
    })

    it('should return error for missing authorization header', async () => {
      await refreshHandlers.refresh(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(400)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'VALIDATION_ERROR',
        message: 'Authorization header not found',
      })
    })

    it('should return error for invalid authorization header format', async () => {
      mockReq.headers.authorization = 'InvalidFormat token'

      await refreshHandlers.refresh(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(400)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'VALIDATION_ERROR',
        message: 'Authorization header must use Bearer scheme',
      })
    })

    it('should return error for invalid refresh token', async () => {
      mockReq.headers.authorization = 'Bearer invalid-refresh-token'

      await refreshHandlers.refresh(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'TOKEN_ERROR',
        message: 'Invalid refresh token',
      })
    })

    it('should return error for expired refresh token', async () => {
      // Mock an expired refresh token
      const jwt = require('jsonwebtoken')
      const expiredRefreshToken = jwt.sign(
        { sessionId: 'test', type: 'refresh' },
        process.env.JWT_SECRET,
        { expiresIn: '-1h' }
      )

      mockReq.headers.authorization = `Bearer ${expiredRefreshToken}`

      await refreshHandlers.refresh(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'TOKEN_ERROR',
        message: 'Refresh token expired',
      })
    })

    it('should return error when refresh token not found in Redis', async () => {
      // Clear Redis to simulate missing refresh token
      mockRedisStore.clear()

      mockReq.headers.authorization = `Bearer ${refreshToken}`

      await refreshHandlers.refresh(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'TOKEN_ERROR',
        message: 'Invalid refresh token',
      })
    })

    it('should return error when session not found in Redis', async () => {
      // Remove session but keep refresh token
      const keys = Array.from(mockRedisStore.keys())
      const sessionKey = keys.find((key) => key.includes('session:'))
      if (sessionKey) {
        mockRedisStore.delete(sessionKey)
      }

      mockReq.headers.authorization = `Bearer ${refreshToken}`

      await refreshHandlers.refresh(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'TOKEN_ERROR',
        message: 'Session not found or expired',
      })
    })

    it('should include error details in development mode', async () => {
      const originalEnv = process.env.NODE_ENV
      process.env.NODE_ENV = 'development'

      mockReq.headers.authorization = 'Bearer invalid-refresh-token'

      await refreshHandlers.refresh(mockReq, mockRes)

      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          details: expect.any(String),
        })
      )

      process.env.NODE_ENV = originalEnv
    })
  })

  describe('token rotation', () => {
    it('should generate different tokens on refresh', async () => {
      const originalTokens = {
        accessToken: (
          await jwtService.verifyToken(
            (await jwtService.generateToken({ userId: 'user123' })).accessToken
          )
        ).decoded,
        refreshToken,
      }

      mockReq.headers.authorization = `Bearer ${refreshToken}`
      await refreshHandlers.refresh(mockReq, mockRes)

      const responseData = mockRes.json.mock.calls[0][0].data

      expect(responseData.accessToken).not.toBe(originalTokens.accessToken)
      expect(responseData.refreshToken).not.toBe(originalTokens.refreshToken)
    })

    it('should invalidate old refresh token after refresh', async () => {
      const oldRefreshToken = refreshToken

      // Use the refresh token once
      mockReq.headers.authorization = `Bearer ${refreshToken}`
      await refreshHandlers.refresh(mockReq, mockRes)

      // Try to use the same refresh token again
      mockReq.headers.authorization = `Bearer ${oldRefreshToken}`
      mockRes.status.mockClear()
      mockRes.json.mockClear()

      await refreshHandlers.refresh(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'TOKEN_ERROR',
        message: 'Invalid refresh token',
      })
    })
  })

  describe('error handling', () => {
    it('should handle Redis connection errors gracefully', async () => {
      // Mock Redis error on the helper function
      const redisHelper = require('../redis.config')
      redisHelper.get.mockRejectedValueOnce(new Error('Redis connection failed'))

      mockReq.headers.authorization = `Bearer ${refreshToken}`

      await refreshHandlers.refresh(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'AUTH_ERROR',
        message: expect.stringContaining('Token refresh failed'),
      })
    })

    it('should handle JWT verification errors', async () => {
      // Mock JWT with wrong secret
      const jwt = require('jsonwebtoken')
      const wrongSecretToken = jwt.sign({ sessionId: 'test', type: 'refresh' }, 'wrong-secret')

      mockReq.headers.authorization = `Bearer ${wrongSecretToken}`

      await refreshHandlers.refresh(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'TOKEN_ERROR',
        message: 'Invalid refresh token',
      })
    })
  })
})
