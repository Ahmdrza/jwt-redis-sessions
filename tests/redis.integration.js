const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const jwt = require('jsonwebtoken')
const { createClient } = require('redis')
const sessions = require('..')
const redisHelper = require('../redis.config')

const prefix = `jwt-redis-sessions:test:${crypto.randomUUID()}:`
const client = createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' })

function deferred() {
  let resolve
  const promise = new Promise((done) => {
    resolve = done
  })
  return { promise, resolve }
}

async function getTestKeys() {
  const keys = []
  for await (const result of client.scanIterator({ MATCH: `${prefix}*`, COUNT: 100 })) {
    if (Array.isArray(result)) {
      keys.push(...result)
    } else {
      keys.push(result)
    }
  }
  return keys
}

async function run() {
  await client.connect()
  sessions.configure({
    jwt: { secret: 'integration-secret-that-is-at-least-32-characters' },
    redis: { keyPrefix: prefix },
  })
  await sessions.initialize({ redisClient: client })

  try {
    const original = await sessions.generateToken({
      userId: 'redis-user',
      email: 'redis@example.com',
    })
    const verified = await sessions.verifyToken(original.accessToken)
    assert.equal(verified.decoded.userId, 'redis-user')
    assert.equal((await sessions.getUserSessions('redis-user')).length, 1)

    const refreshPayload = jwt.decode(original.refreshToken)
    const refreshKey = `${prefix}refresh:${refreshPayload.sessionId}`
    const sessionKey = `${prefix}session:${refreshPayload.sessionId}`
    const storedRefresh = await client.get(refreshKey)
    assert.match(storedRefresh, /^[a-f0-9]{64}$/)
    assert.notEqual(storedRefresh, original.refreshToken)
    assert.ok((await client.ttl(refreshKey)) > 0)
    assert.ok((await client.ttl(sessionKey)) >= (await client.ttl(refreshKey)) - 1)

    const authRequest = {
      headers: { authorization: `Bearer ${original.accessToken}` },
    }
    const authResponse = {
      status() {
        return this
      },
      json() {
        return this
      },
    }
    let authenticated = false
    await sessions.auth(authRequest, authResponse, (error) => {
      assert.ifError(error)
      authenticated = true
    })
    assert.equal(authenticated, true)
    assert.equal(authRequest.auth.decoded.userId, 'redis-user')
    assert.equal(authRequest.auth.session.sessionId, refreshPayload.sessionId)

    const limiter = sessions.rateLimit(1, 60_000)
    const rateRequest = { ip: '192.0.2.10' }
    const rateResponse = {
      statusCode: 200,
      body: null,
      headers: {},
      set(name, value) {
        this.headers[name] = value
      },
      status(code) {
        this.statusCode = code
        return this
      },
      json(body) {
        this.body = body
        return this
      },
    }
    let allowedRequests = 0
    const rateNext = (error) => {
      assert.ifError(error)
      allowedRequests += 1
    }
    await limiter(rateRequest, rateResponse, rateNext)
    await limiter(rateRequest, rateResponse, rateNext)
    assert.equal(allowedRequests, 1)
    assert.equal(rateResponse.statusCode, 429)
    assert.equal(rateResponse.body.status, 'TOO_MANY_REQUESTS')
    assert.ok(Number(rateResponse.headers['Retry-After']) >= 1)

    const refreshAttempts = await Promise.allSettled([
      sessions.refreshToken(original.refreshToken),
      sessions.refreshToken(original.refreshToken),
    ])
    assert.equal(refreshAttempts.filter((result) => result.status === 'fulfilled').length, 1)
    assert.equal(refreshAttempts.filter((result) => result.status === 'rejected').length, 1)
    await assert.rejects(
      sessions.verifyToken(original.accessToken),
      /Token session has been replaced or revoked/
    )

    const replacement = refreshAttempts.find((result) => result.status === 'fulfilled').value
    await sessions.revokeToken(replacement.accessToken)
    assert.equal(await sessions.isTokenBlacklisted(replacement.accessToken), true)

    const refreshLogoutTokens = await sessions.generateToken({ userId: 'refresh-logout-race' })
    const rotateEntered = deferred()
    const rotateRelease = deferred()
    const originalRotate = redisHelper.rotateSessionAtomic
    redisHelper.rotateSessionAtomic = async (options) => {
      rotateEntered.resolve()
      await rotateRelease.promise
      return originalRotate(options)
    }
    try {
      const inFlightRefresh = sessions.refreshToken(refreshLogoutTokens.refreshToken)
      await rotateEntered.promise
      await sessions.revokeToken(refreshLogoutTokens.accessToken)
      rotateRelease.resolve()
      await assert.rejects(inFlightRefresh, /Invalid refresh token or revoked session/)
    } finally {
      rotateRelease.resolve()
      redisHelper.rotateSessionAtomic = originalRotate
    }

    const verifyLogoutTokens = await sessions.generateToken({ userId: 'verify-logout-all-race' })
    const touchEntered = deferred()
    const touchRelease = deferred()
    const originalTouch = redisHelper.touchSessionAtomic
    redisHelper.touchSessionAtomic = async (options) => {
      touchEntered.resolve()
      await touchRelease.promise
      return originalTouch(options)
    }
    try {
      const inFlightVerification = sessions.verifyToken(verifyLogoutTokens.accessToken)
      await touchEntered.promise
      await sessions.revokeAllUserTokens('verify-logout-all-race')
      touchRelease.resolve()
      await assert.rejects(inFlightVerification, /Session has been replaced or revoked/)
      await assert.rejects(sessions.verifyToken(verifyLogoutTokens.accessToken))
    } finally {
      touchRelease.resolve()
      redisHelper.touchSessionAtomic = originalTouch
    }

    const redisKeys = await getTestKeys()
    assert.equal(
      redisKeys.some((key) => key.includes(original.accessToken)),
      false
    )
    assert.equal(
      redisKeys.some((key) => key.includes(original.refreshToken)),
      false
    )

    process.stdout.write('Redis 7 integration checks passed\n')
  } finally {
    const keys = await getTestKeys()
    if (keys.length) {
      await client.del(keys)
    }
    await sessions.closeRedisConnection()
    await client.quit()
  }
}

run().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`)
  process.exitCode = 1
})
