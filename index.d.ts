declare module 'jwt-redis-sessions' {
  // Token data interface - completely flexible, any shape allowed
  interface TokenData {
    [key: string]: any
  }

  // Token response interface
  interface TokenResponse {
    accessToken: string
    refreshToken: string
    expiresIn: string
    tokenType: 'Bearer'
  }

  // Session data interface
  interface SessionData extends TokenData {
    sessionId: string
    createdAt: string
    lastActivity: string
  }

  // Token payload interface
  interface TokenPayload extends TokenData {
    sessionId: string
    iat: number
    exp?: number
    iss: string
    aud: string
    type: 'access' | 'refresh'
  }

  // Verify token result interface
  interface VerifyTokenResult {
    valid: boolean
    decoded: TokenData // Clean user data only (internal fields filtered out)
    session: SessionData
  }

  // Configuration interfaces
  interface JWTConfig {
    secret: string
    accessTokenExpiry: string
    refreshTokenExpiry: string
    issuer: string
    audience: string
  }

  interface RedisConfig {
    url: string
    host: string
    port: number
    password?: string
    db: number
    keyPrefix: string
    sessionTTL: number
    refreshTokenTTL: number
  }

  interface SecurityConfig {
    tokenLength: number
    enableFingerprinting: boolean
    fingerprintStrict: boolean
  }

  interface Config {
    jwt: JWTConfig
    redis: RedisConfig
    security: SecurityConfig
  }

  // Error classes
  class AuthError extends Error {
    statusCode: number
    code: string
    constructor(message: string, statusCode?: number, code?: string)
  }

  class ValidationError extends Error {
    statusCode: number
    code: string
    constructor(message: string, statusCode?: number, code?: string)
  }

  class TokenError extends Error {
    statusCode: number
    code: string
    constructor(message: string, statusCode?: number, code?: string)
  }

  class RedisError extends Error {
    statusCode: number
    code: string
    constructor(message: string, statusCode?: number, code?: string)
  }

  // Main functions

  /**
   * Generate JWT access and refresh tokens
   * @param data User data for token (include userId, id, or email for revokeAllUserTokens)
   * @param req Optional request for fingerprinting
   */
  function generateToken(data?: TokenData | null, req?: any): Promise<TokenResponse>

  /**
   * Verify and validate JWT token
   * @param token JWT token to verify
   * @param req Optional request for fingerprint verification
   */
  function verifyToken(token: string, req?: any): Promise<VerifyTokenResult>

  /**
   * Refresh access token using refresh token
   * @param refreshToken The refresh token
   * @param req Optional request for fingerprint verification
   */
  function refreshToken(refreshToken: string, req?: any): Promise<TokenResponse>

  /**
   * Revoke token by blacklisting
   * @param token Token to revoke
   */
  function revokeToken(token: string): Promise<{ success: boolean; message: string }>

  /**
   * Revoke all user sessions/tokens
   * @param userIdentifier User identifier (userId, id, or email)
   */
  function revokeAllUserTokens(
    userIdentifier: string
  ): Promise<{ success: boolean; message: string }>

  /**
   * Get all active sessions for user
   * @param userIdentifier User identifier (userId, id, or email)
   */
  function getUserSessions(userIdentifier: string): Promise<SessionData[]>

  /**
   * Check if token is blacklisted
   * @param token Token to check
   */
  function isTokenBlacklisted(token: string): Promise<boolean>

  // Middleware functions (Express-compatible)

  /**
   * Express middleware for JWT authentication
   * @param req Express request object
   * @param res Express response object
   * @param next Express next function
   */
  function auth(req: any, res: any, next: any): Promise<void>

  /**
   * Rate limiting middleware to prevent brute force attacks
   * @param maxAttempts Max attempts allowed (default: 5)
   * @param windowMs Time window in ms (default: 15 min)
   * @param maxMapSize Max map size (default: 10000)
   */
  function rateLimit(
    maxAttempts?: number,
    windowMs?: number,
    maxMapSize?: number
  ): (req: any, res: any, next: any) => void

  // Utility functions

  /** Configuration object */
  const config: Config

  /**
   * Manually initialize Redis connection
   * Note: Auto-initialized on first use
   */
  function initialize(): Promise<void>

  /**
   * Close Redis connection gracefully
   * Use when shutting down application
   */
  function closeRedisConnection(): Promise<void>
}
