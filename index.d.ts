declare module 'jwt-redis-sessions' {
  // Token data interface
  interface TokenData {
    userId?: string
    id?: string
    email?: string
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
    decoded: TokenPayload
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
    bcryptRounds: number
    maxLoginAttempts: number
    lockoutTime: number
    tokenLength: number
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
  function generateToken(data: TokenData): Promise<TokenResponse>
  function verifyToken(token: string): Promise<VerifyTokenResult>
  function refreshToken(refreshToken: string): Promise<TokenResponse>
  function revokeToken(token: string): Promise<{ success: boolean; message: string }>
  function revokeAllUserTokens(userId: string): Promise<{ success: boolean; message: string }>
  function getUserSessions(userId: string): Promise<SessionData[]>
  function isTokenBlacklisted(token: string): Promise<boolean>

  // Middleware functions (Express-compatible)
  function auth(req: any, res: any, next: any): Promise<void>
  function optionalAuth(req: any, res: any, next: any): Promise<void>
  function rateLimit(
    maxAttempts?: number,
    windowMs?: number
  ): (req: any, res: any, next: any) => void

  // Handler functions
  function refresh(req: any, res: any): Promise<void>
  function logout(req: any, res: any): Promise<void>
  function logoutAll(req: any, res: any): Promise<void>

  // Utility functions
  const config: Config
  function initialize(): Promise<void>
  function closeRedisConnection(): Promise<void>

  // Extended Express Request interface for TypeScript users
  interface AuthRequest {
    user?: TokenPayload
    session?: SessionData
    token?: string
    newTokens?: TokenResponse
    [key: string]: any
  }
}
