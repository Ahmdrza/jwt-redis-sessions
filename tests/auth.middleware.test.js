const authMiddleware = require('../auth.middleware')
const jwtService = require('../jwt.service')

describe('Auth Middleware', () => {
  let mockReq, mockRes, mockNext, validToken

  beforeEach(async () => {
    // Create a valid token for testing
    const userData = {
      userId: 'user123',
      email: 'test@example.com',
    }
    const result = await jwtService.generateToken(userData)
    validToken = result.accessToken

    // Mock Express req, res, next
    mockReq = {
      headers: {},
    }

    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    }

    mockNext = jest.fn()
  })

  describe('auth middleware', () => {
    it('should authenticate valid token', async () => {
      mockReq.headers.authorization = `Bearer ${validToken}`

      await authMiddleware.auth(mockReq, mockRes, mockNext)

      expect(mockNext).toHaveBeenCalled()
      expect(mockRes.status).not.toHaveBeenCalled()
      expect(mockRes.json).not.toHaveBeenCalled()
    })

    it('should reject request with missing authorization header', async () => {
      await authMiddleware.auth(mockReq, mockRes, mockNext)

      expect(mockNext).not.toHaveBeenCalled()
      expect(mockRes.status).toHaveBeenCalledWith(400)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'VALIDATION_ERROR',
        message: 'Authorization header not found',
      })
    })

    it('should reject request with invalid authorization header format', async () => {
      mockReq.headers.authorization = 'InvalidFormat token'

      await authMiddleware.auth(mockReq, mockRes, mockNext)

      expect(mockNext).not.toHaveBeenCalled()
      expect(mockRes.status).toHaveBeenCalledWith(400)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'VALIDATION_ERROR',
        message: 'Authorization header must use Bearer scheme',
      })
    })

    it('should reject request with malformed Bearer token', async () => {
      mockReq.headers.authorization = 'Bearer'

      await authMiddleware.auth(mockReq, mockRes, mockNext)

      expect(mockNext).not.toHaveBeenCalled()
      expect(mockRes.status).toHaveBeenCalledWith(400)
    })

    it('should reject request with invalid token', async () => {
      mockReq.headers.authorization = 'Bearer invalid-token'

      await authMiddleware.auth(mockReq, mockRes, mockNext)

      expect(mockNext).not.toHaveBeenCalled()
      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'TOKEN_ERROR',
        message: 'Invalid token',
      })
    })

    it('should reject blacklisted token', async () => {
      // Blacklist the token first
      await jwtService.revokeToken(validToken)

      mockReq.headers.authorization = `Bearer ${validToken}`

      await authMiddleware.auth(mockReq, mockRes, mockNext)

      expect(mockNext).not.toHaveBeenCalled()
      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'TOKEN_ERROR',
        message: 'Token has been revoked',
      })
    })

    it('should include error details in development mode', async () => {
      const originalEnv = process.env.NODE_ENV
      process.env.NODE_ENV = 'development'

      mockReq.headers.authorization = 'Bearer invalid-token'

      await authMiddleware.auth(mockReq, mockRes, mockNext)

      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          details: expect.any(String),
        })
      )

      process.env.NODE_ENV = originalEnv
    })
  })

  describe('rateLimit middleware', () => {
    let rateLimitMiddleware

    beforeEach(() => {
      mockReq.ip = '127.0.0.1'
      rateLimitMiddleware = authMiddleware.rateLimit(3, 1000) // 3 attempts per second
    })

    it('should allow requests within rate limit', () => {
      rateLimitMiddleware(mockReq, mockRes, mockNext)
      rateLimitMiddleware(mockReq, mockRes, mockNext)
      rateLimitMiddleware(mockReq, mockRes, mockNext)

      expect(mockNext).toHaveBeenCalledTimes(3)
      expect(mockRes.status).not.toHaveBeenCalled()
    })

    it('should block requests exceeding rate limit', () => {
      // Make 4 requests (limit is 3)
      rateLimitMiddleware(mockReq, mockRes, mockNext)
      rateLimitMiddleware(mockReq, mockRes, mockNext)
      rateLimitMiddleware(mockReq, mockRes, mockNext)
      rateLimitMiddleware(mockReq, mockRes, mockNext)

      expect(mockNext).toHaveBeenCalledTimes(3)
      expect(mockRes.status).toHaveBeenCalledWith(429)
      expect(mockRes.json).toHaveBeenCalledWith({
        status: 'TOO_MANY_REQUESTS',
        message: expect.stringContaining('Too many attempts'),
      })
    })

    it('should use different counters for different IPs', () => {
      const req2 = { ...mockReq, ip: '192.168.1.1' }

      // Use up limit for first IP
      rateLimitMiddleware(mockReq, mockRes, mockNext)
      rateLimitMiddleware(mockReq, mockRes, mockNext)
      rateLimitMiddleware(mockReq, mockRes, mockNext)
      rateLimitMiddleware(mockReq, mockRes, mockNext) // Should be blocked

      // Second IP should still work
      rateLimitMiddleware(req2, mockRes, mockNext)

      expect(mockNext).toHaveBeenCalledTimes(4) // 3 + 1
      expect(mockRes.status).toHaveBeenCalledTimes(1) // Only first IP blocked
    })

    it('should use default values when no parameters provided', () => {
      const defaultRateLimit = authMiddleware.rateLimit()

      // This should not throw and should create a working middleware
      expect(typeof defaultRateLimit).toBe('function')

      defaultRateLimit(mockReq, mockRes, mockNext)
      expect(mockNext).toHaveBeenCalled()
    })

    it('should fall back to connection.remoteAddress when no IP', () => {
      mockReq.ip = undefined
      mockReq.connection = { remoteAddress: '127.0.0.1' }

      rateLimitMiddleware(mockReq, mockRes, mockNext)

      expect(mockNext).toHaveBeenCalled()
    })
  })
})
