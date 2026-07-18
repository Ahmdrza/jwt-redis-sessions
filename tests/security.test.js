const { execFileSync } = require('node:child_process')
const jwtService = require('../jwt.service')
const authMiddleware = require('../auth.middleware')
const config = require('../config')
const redisHelper = require('../redis.config')

const deferred = () => {
  let resolve
  const promise = new Promise((done) => {
    resolve = done
  })
  return { promise, resolve }
}

describe('Security regressions', () => {
  it('stores a refresh digest instead of a reusable token', async () => {
    const tokens = await jwtService.generateToken({ userId: 'digest-user' })
    const refreshEntry = Array.from(mockRedisStore.entries()).find(([key]) =>
      key.includes('refresh:')
    )

    expect(refreshEntry).toBeDefined()
    expect(refreshEntry[1].value).not.toBe(tokens.refreshToken)
    expect(refreshEntry[1].value).toMatch(/^[a-f0-9]{64}$/)
    expect(JSON.stringify(Array.from(mockRedisStore.entries()))).not.toContain(tokens.refreshToken)
  })

  it('allows exactly one winner when a refresh token is replayed concurrently', async () => {
    const { refreshToken } = await jwtService.generateToken({ userId: 'race-user' })
    const attempts = await Promise.allSettled([
      jwtService.refreshToken(refreshToken),
      jwtService.refreshToken(refreshToken),
      jwtService.refreshToken(refreshToken),
    ])

    expect(attempts.filter(({ status }) => status === 'fulfilled')).toHaveLength(1)
    expect(attempts.filter(({ status }) => status === 'rejected')).toHaveLength(2)
    expect(redisHelper.rotateSessionAtomic).toHaveBeenCalledTimes(3)
  })

  it('invalidates the prior access session during refresh rotation', async () => {
    const oldTokens = await jwtService.generateToken({ userId: 'rotation-user' })
    await jwtService.refreshToken(oldTokens.refreshToken)

    await expect(jwtService.verifyToken(oldTokens.accessToken)).rejects.toThrow(
      'Token session has been replaced or revoked'
    )
  })

  it('does not let an in-flight refresh survive logout', async () => {
    const tokens = await jwtService.generateToken({ userId: 'refresh-logout-race' })
    const entered = deferred()
    const release = deferred()
    const originalRotate = redisHelper.rotateSessionAtomic.getMockImplementation()
    redisHelper.rotateSessionAtomic.mockImplementationOnce(async (options) => {
      entered.resolve()
      await release.promise
      return originalRotate(options)
    })

    const refresh = jwtService.refreshToken(tokens.refreshToken)
    await entered.promise
    await jwtService.revokeToken(tokens.accessToken)
    release.resolve()

    await expect(refresh).rejects.toThrow('Invalid refresh token or revoked session')
  })

  it('does not let an in-flight verification resurrect logout-all sessions', async () => {
    const tokens = await jwtService.generateToken({ userId: 'verify-logout-all-race' })
    const entered = deferred()
    const release = deferred()
    const originalTouch = redisHelper.touchSessionAtomic.getMockImplementation()
    redisHelper.touchSessionAtomic.mockImplementationOnce(async (options) => {
      entered.resolve()
      await release.promise
      return originalTouch(options)
    })

    const verification = jwtService.verifyToken(tokens.accessToken)
    await entered.promise
    await jwtService.revokeAllUserTokens('verify-logout-all-race')
    release.resolve()

    await expect(verification).rejects.toThrow('Session has been replaced or revoked')
    await expect(jwtService.verifyToken(tokens.accessToken)).rejects.toThrow()
  })

  it('never includes a complete access token in a blacklist key', async () => {
    const { accessToken } = await jwtService.generateToken({ userId: 'logout-user' })
    await jwtService.revokeToken(accessToken)

    const blacklistKey = Array.from(mockRedisStore.keys()).find((key) => key.includes('blacklist:'))
    expect(blacklistKey).toMatch(/blacklist:[a-f0-9]{64}$/)
    expect(blacklistKey).not.toContain(accessToken)
  })

  it('uses per-user indexes without scanning the Redis keyspace', async () => {
    await jwtService.generateToken({ userId: 'indexed-user', email: 'index@example.com' })
    await jwtService.generateToken({ userId: 'indexed-user' })

    await expect(jwtService.getUserSessions('indexed-user')).resolves.toHaveLength(2)
    expect(mockRedisClient.sMembers).toHaveBeenCalledTimes(1)
    expect(mockRedisClient.scan).not.toHaveBeenCalled()
  })

  it('shares rate-limit counters between middleware instances', async () => {
    const firstInstance = authMiddleware.rateLimit(1, 60_000)
    const secondInstance = authMiddleware.rateLimit(1, 60_000)
    const request = { ip: '203.0.113.42' }
    const response = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      set: jest.fn(),
    }
    const next = jest.fn()

    await firstInstance(request, response, next)
    await secondInstance(request, response, next)

    expect(next).toHaveBeenCalledTimes(1)
    expect(response.status).toHaveBeenCalledWith(429)
  })

  it('keeps the default session TTL at least as long as refresh state', () => {
    expect(config.redis.sessionTTL).toBeGreaterThanOrEqual(config.redis.refreshTokenTTL)
  })

  it('builds keys from the current configured prefix instead of caching import-time state', () => {
    const { redisKeys } = require('../utils')
    const originalPrefix = config.redis.keyPrefix
    config.redis.keyPrefix = 'changed-prefix:'
    try {
      expect(redisKeys.sessionKey('session-id')).toBe('changed-prefix:session:session-id')
    } finally {
      config.redis.keyPrefix = originalPrefix
    }
  })

  it('does not load dotenv or install host process handlers on import', () => {
    const script = `
      const before = [process.listenerCount('SIGINT'), process.listenerCount('SIGTERM')]
      const library = require('./index')
      const after = [process.listenerCount('SIGINT'), process.listenerCount('SIGTERM')]
      process.stdout.write(JSON.stringify({ before, after, secret: library.config.jwt.secret || null }))
    `
    const env = { ...process.env }
    delete env.JWT_SECRET
    const result = JSON.parse(
      execFileSync(process.execPath, ['-e', script], {
        cwd: process.cwd(),
        env,
        encoding: 'utf8',
      })
    )

    expect(result.after).toEqual(result.before)
    expect(result.secret).toBeNull()
  })

  it('applies programmatic Redis host and port configuration to the connection URL', () => {
    const script = `
      const library = require('./index')
      library.configure({
        jwt: { secret: 'configured-secret-that-is-at-least-32-characters' },
        redis: { host: 'redis.internal', port: 6380 }
      })
      process.stdout.write(library.config.redis.url)
    `
    const result = execFileSync(process.execPath, ['-e', script], {
      cwd: process.cwd(),
      encoding: 'utf8',
    })

    expect(result).toBe('redis://redis.internal:6380')
  })
})
