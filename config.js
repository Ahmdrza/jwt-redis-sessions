const refreshTokenTTL = Number.parseInt(process.env.REFRESH_TOKEN_TTL || '604800', 10)
const redisHost = process.env.REDIS_HOST || 'localhost'
const redisPort = Number.parseInt(process.env.REDIS_PORT || '6379', 10)

module.exports = {
  jwt: {
    secret: process.env.JWT_SECRET,
    accessTokenExpiry: process.env.JWT_ACCESS_TOKEN_EXPIRY || '15m',
    refreshTokenExpiry: process.env.JWT_REFRESH_TOKEN_EXPIRY || '7d',
    issuer: process.env.JWT_ISSUER || 'jwt-redis-sessions',
    audience: process.env.JWT_AUDIENCE || 'jwt-redis-sessions-users',
  },
  redis: {
    url: process.env.REDIS_URL || `redis://${redisHost}:${redisPort}`,
    host: redisHost,
    port: redisPort,
    password: process.env.REDIS_PASSWORD,
    db: Number.parseInt(process.env.REDIS_DB || '0', 10),
    keyPrefix: process.env.REDIS_KEY_PREFIX || 'jwt-redis-sessions:',
    // A session must live at least as long as its refresh token. Callers can
    // still choose a longer sliding session lifetime.
    sessionTTL: Number.parseInt(process.env.SESSION_TTL || String(refreshTokenTTL), 10),
    refreshTokenTTL,
  },
  security: {
    tokenLength: Number.parseInt(process.env.TOKEN_LENGTH || '32', 10),
    allowedTokenFields: (process.env.JWT_ALLOWED_TOKEN_FIELDS || 'userId,id,email,role,permissions')
      .split(',')
      .map((field) => field.trim())
      .filter(Boolean),
    // Token fingerprinting settings
    enableFingerprinting: process.env.ENABLE_TOKEN_FINGERPRINTING !== 'false', // Default enabled
    fingerprintStrict: process.env.FINGERPRINT_STRICT_MODE === 'true', // Default disabled for flexibility
  },
}
