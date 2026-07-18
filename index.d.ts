import type { NextFunction, Request, RequestHandler, Response } from 'express'
import type { RedisClientType } from 'redis'

export type TokenPrimitive = string | number | boolean | null

export interface TokenData {
  userId?: string
  id?: string
  email?: string
  role?: TokenPrimitive
  permissions?: TokenPrimitive[]
  [key: string]: TokenPrimitive | TokenPrimitive[] | undefined
}

export interface TokenResponse {
  accessToken: string
  refreshToken: string
  expiresIn: string | number
  tokenType: 'Bearer'
}

export interface SessionData extends TokenData {
  sessionId: string
  refreshExpiresAt: number
  createdAt: string
  lastActivity: string
}

export interface VerifyTokenResult<T extends TokenData = TokenData> {
  valid: true
  decoded: T
  session: SessionData & T
}

export interface AuthContext<T extends TokenData = TokenData> extends VerifyTokenResult<T> {
  token: string
}

export interface JWTConfig {
  secret?: string
  accessTokenExpiry: string | number
  refreshTokenExpiry: string | number
  issuer: string
  audience: string
}

export interface RedisConfig {
  url: string
  host: string
  port: number
  password?: string
  db: number
  keyPrefix: string
  sessionTTL: number
  refreshTokenTTL: number
}

export interface SecurityConfig {
  tokenLength: number
  allowedTokenFields: string[]
  enableFingerprinting: boolean
  fingerprintStrict: boolean
}

export interface Config {
  jwt: JWTConfig
  redis: RedisConfig
  security: SecurityConfig
}

export type ConfigOverrides = {
  [Section in keyof Config]?: Partial<Config[Section]>
}

export class AuthError extends Error {
  statusCode: number
  code: string
  constructor(message: string, statusCode?: number, code?: string)
}

export class ValidationError extends Error {
  statusCode: number
  code: string
  constructor(message: string, statusCode?: number, code?: string)
}

export class TokenError extends Error {
  statusCode: number
  code: string
  constructor(message: string, statusCode?: number, code?: string)
}

export class RedisError extends Error {
  statusCode: number
  code: string
  constructor(message: string, statusCode?: number, code?: string)
}

export function generateToken<T extends TokenData = TokenData>(
  data?: T | null,
  req?: Request | null
): Promise<TokenResponse>
export function verifyToken<T extends TokenData = TokenData>(
  token: string,
  req?: Request | null
): Promise<VerifyTokenResult<T>>
export function refreshToken(refreshToken: string, req?: Request | null): Promise<TokenResponse>
export function revokeToken(token: string): Promise<{ success: true; message: string }>
export function revokeAllUserTokens(
  userIdentifier: string
): Promise<{ success: true; message: string }>
export function getUserSessions(userIdentifier: string): Promise<SessionData[]>
export function isTokenBlacklisted(token: string): Promise<boolean>

export function auth(req: Request, res: Response, next: NextFunction): Promise<void>
export function rateLimit(maxAttempts?: number, windowMs?: number): RequestHandler

export const config: Config
export function configure(overrides?: ConfigOverrides): Config
export function initialize(options?: {
  config?: ConfigOverrides
  redisClient?: RedisClientType
}): Promise<void>
export function closeRedisConnection(): Promise<void>

declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext
    }
  }
}
