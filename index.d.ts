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
   * Generates JWT access and refresh tokens for a user session
   * @param data - User data to encode in the token. For logoutAll to work, include userId, id, or email
   * @param req - Optional Express request object for device fingerprinting
   * @returns Token response containing accessToken, refreshToken, expiresIn, and tokenType
   * @throws {ValidationError} If JWT secret is invalid or data validation fails
   * @throws {RedisError} If Redis operation fails
   * @example
   * const tokens = await generateToken({ userId: 'user123', email: 'user@example.com' })
   * // Returns: { accessToken: 'jwt...', refreshToken: 'jwt...', expiresIn: '15m', tokenType: 'Bearer' }
   */
  function generateToken(data?: TokenData | null, req?: any): Promise<TokenResponse>

  /**
   * Verifies and validates a JWT token
   * @param token - The JWT token to verify
   * @param req - Optional Express request object for fingerprint verification
   * @returns Verification result with valid flag, decoded data, and session info
   * @throws {TokenError} If token is invalid, expired, blacklisted, or fingerprint doesn't match
   * @throws {RedisError} If Redis operation fails
   * @example
   * const result = await verifyToken('jwt...')
   * // Returns: { valid: true, decoded: { userId: 'user123', ... }, session: { sessionId: '...', ... } }
   */
  function verifyToken(token: string, req?: any): Promise<VerifyTokenResult>

  /**
   * Refreshes an access token using a valid refresh token
   * @param refreshToken - The refresh token
   * @param req - Optional Express request object for fingerprint verification
   * @returns New token pair with accessToken, refreshToken, expiresIn, and tokenType
   * @throws {TokenError} If refresh token is invalid, expired, or blacklisted
   * @throws {RedisError} If Redis operation fails
   * @example
   * const newTokens = await refreshToken('refresh_jwt...')
   * // Returns: { accessToken: 'new_jwt...', refreshToken: 'new_refresh...', expiresIn: '15m', tokenType: 'Bearer' }
   */
  function refreshToken(refreshToken: string, req?: any): Promise<TokenResponse>

  /**
   * Revokes a token by adding it to the blacklist
   * @param token - The token to revoke
   * @returns Success status and message
   * @throws {TokenError} If token is invalid
   * @throws {RedisError} If Redis operation fails
   * @example
   * const result = await revokeToken('jwt...')
   * // Returns: { success: true, message: 'Token revoked successfully' }
   */
  function revokeToken(token: string): Promise<{ success: boolean; message: string }>

  /**
   * Revokes all active sessions/tokens for a specific user
   * @param userIdentifier - The user identifier (can be userId, id, or email based on your token data)
   * @returns Success status and message with count of revoked sessions
   * @throws {Error} If userIdentifier is not provided
   * @throws {RedisError} If Redis operation fails
   * @example
   * const result = await revokeAllUserTokens('user123')
   * // Returns: { success: true, message: 'Revoked 3 sessions for user user123' }
   */
  function revokeAllUserTokens(
    userIdentifier: string
  ): Promise<{ success: boolean; message: string }>

  /**
   * Retrieves all active sessions for a specific user
   * @param userIdentifier - The user identifier (userId, id, or email)
   * @returns Array of session objects with sessionId, createdAt, lastActivity, and user data
   * @throws {Error} If userIdentifier is not provided
   * @throws {RedisError} If Redis operation fails
   * @example
   * const sessions = await getUserSessions('user123')
   * // Returns: [{ sessionId: '...', createdAt: '2024-01-01T00:00:00Z', lastActivity: '...', userId: 'user123' }]
   */
  function getUserSessions(userIdentifier: string): Promise<SessionData[]>

  /**
   * Checks if a token has been blacklisted/revoked
   * @param token - The token to check
   * @returns True if token is blacklisted, false otherwise
   * @throws {TokenError} If token format is invalid
   * @throws {RedisError} If Redis operation fails
   * @example
   * const isBlacklisted = await isTokenBlacklisted('jwt...')
   * // Returns: true or false
   */
  function isTokenBlacklisted(token: string): Promise<boolean>

  // Middleware functions (Express-compatible)

  /**
   * Express middleware for JWT authentication
   * Validates the authorization header and verifies the token
   * @param req - Express request object
   * @param res - Express response object
   * @param next - Express next middleware function
   * @returns Calls next() if authentication succeeds, sends error response otherwise
   * @example
   * app.get('/protected', auth, (req, res) => {
   *   res.json({ message: 'Authenticated!' })
   * })
   */
  function auth(req: any, res: any, next: any): Promise<void>

  /**
   * Creates rate limiting middleware to prevent brute force attacks
   * @param maxAttempts - Maximum number of attempts allowed (default: 5)
   * @param windowMs - Time window in milliseconds (default: 15 minutes)
   * @param maxMapSize - Maximum size of attempts map to prevent memory exhaustion (default: 10000)
   * @returns Express middleware function
   * @example
   * app.use('/api/login', rateLimit(5, 15 * 60 * 1000)) // 5 attempts per 15 minutes
   */
  function rateLimit(
    maxAttempts?: number,
    windowMs?: number,
    maxMapSize?: number
  ): (req: any, res: any, next: any) => void

  // Utility functions

  /**
   * Configuration object containing JWT, Redis, and security settings
   */
  const config: Config

  /**
   * Manually initialize Redis connection
   * Note: Connection is auto-initialized on first use, so this is usually not needed
   * @returns Promise that resolves when connection is established
   * @example
   * await initialize()
   */
  function initialize(): Promise<void>

  /**
   * Close Redis connection gracefully
   * Use this when shutting down your application
   * @returns Promise that resolves when connection is closed
   * @example
   * process.on('SIGTERM', async () => {
   *   await closeRedisConnection()
   *   process.exit(0)
   * })
   */
  function closeRedisConnection(): Promise<void>
}
