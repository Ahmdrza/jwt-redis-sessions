module.exports = {
  jwt: {
    secret: process.env.JWT_SECRET,
    accessTokenExpiry: process.env.JWT_ACCESS_TOKEN_EXPIRY || '15m',
    refreshTokenExpiry: process.env.JWT_REFRESH_TOKEN_EXPIRY || '7d',
    issuer: process.env.JWT_ISSUER || 'jwt-redis-sessions',
    audience: process.env.JWT_AUDIENCE || 'jwt-redis-sessions-users',
  },
  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
    password: process.env.REDIS_PASSWORD,
    db: process.env.REDIS_DB || 0,
    keyPrefix: process.env.REDIS_KEY_PREFIX || 'jwt-redis-sessions:',
    sessionTTL: parseInt(process.env.SESSION_TTL || '86400'), // 24 hours in seconds
    refreshTokenTTL: parseInt(process.env.REFRESH_TOKEN_TTL || '604800'), // 7 days in seconds
  },
  security: {
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS || '10'),
    maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5'),
    lockoutTime: parseInt(process.env.LOCKOUT_TIME || '900'), // 15 minutes in seconds
    tokenLength: parseInt(process.env.TOKEN_LENGTH || '32'),
  },
}
