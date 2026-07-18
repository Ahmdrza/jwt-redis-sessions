/* eslint-disable no-console */
const redis = require('redis')
const config = require('./config')
const { RedisError } = require('./errors')

let redisClient = null
let isConnected = false
let ownsRedisClient = false
let connectionPromise = null

const createRedisClient = () => {
  const client = redis.createClient({
    url: config.redis.url,
    socket: {
      reconnectStrategy: (retries) => {
        if (retries > 10) {
          console.error('Redis: Maximum reconnection attempts reached')
          return new Error('Maximum reconnection attempts reached')
        }
        return Math.min(retries * 100, 3000)
      },
    },
    password: config.redis.password,
    database: config.redis.db,
    legacyMode: false,
  })

  client.on('error', (err) => {
    console.error('Redis Client Error:', err)
    isConnected = false
  })

  client.on('connect', () => {
    console.log('Redis Client Connected')
    isConnected = true
  })

  client.on('ready', () => {
    console.log('Redis Client Ready')
    isConnected = true
  })

  client.on('end', () => {
    console.log('Redis Client Disconnected')
    isConnected = false
  })

  return client
}

exports.bootstrapRedis = async () => {
  try {
    if (!redisClient) {
      redisClient = createRedisClient()
      ownsRedisClient = true
    }

    if (!isConnected) {
      connectionPromise ||= redisClient.connect().then(() => {
        isConnected = true
        return redisClient
      })
      try {
        await connectionPromise
      } finally {
        connectionPromise = null
      }
    }

    return redisClient
  } catch (error) {
    throw new RedisError(`Failed to connect to Redis: ${error.message}`)
  }
}

exports.useRedisClient = (client) => {
  if (!client || typeof client.get !== 'function' || typeof client.set !== 'function') {
    throw new RedisError('A compatible connected Redis client is required')
  }
  if (redisClient && redisClient !== client) {
    throw new RedisError('Redis client is already initialized')
  }
  if (client.isReady === false || client.isOpen === false) {
    throw new RedisError('The supplied Redis client must already be connected')
  }
  redisClient = client
  ownsRedisClient = false
  isConnected = client.isReady !== false && client.isOpen !== false
  return redisClient
}

exports.getRedisClient = () => {
  if (!redisClient || !isConnected) {
    throw new RedisError('Redis client not initialized or not connected')
  }
  return redisClient
}

exports.closeRedisConnection = async () => {
  if (redisClient && isConnected && ownsRedisClient) {
    await redisClient.quit()
  }
  if (redisClient) {
    redisClient = null
    isConnected = false
    ownsRedisClient = false
    connectionPromise = null
  }
}

exports.isRedisConnected = () => isConnected

// Helper functions for common Redis operations
// Note: These functions expect keys that are already prefixed (from redisKeys utility)
exports.setWithExpiry = async (key, value, ttl) => {
  try {
    const client = exports.getRedisClient()
    return await client.set(key, value, { EX: ttl })
  } catch (error) {
    throw new RedisError(`Failed to set key in Redis: ${error.message}`)
  }
}

exports.get = async (key) => {
  try {
    const client = exports.getRedisClient()
    return await client.get(key)
  } catch (error) {
    throw new RedisError(`Failed to get key from Redis: ${error.message}`)
  }
}

exports.getDel = async (key) => {
  try {
    const client = exports.getRedisClient()
    return await client.getDel(key)
  } catch (error) {
    throw new RedisError(`Failed to atomically consume key in Redis: ${error.message}`)
  }
}

exports.del = async (key) => {
  try {
    const client = exports.getRedisClient()
    return await client.del(key)
  } catch (error) {
    throw new RedisError(`Failed to delete key from Redis: ${error.message}`)
  }
}

exports.exists = async (key) => {
  try {
    const client = exports.getRedisClient()
    return await client.exists(key)
  } catch (error) {
    throw new RedisError(`Failed to check key existence in Redis: ${error.message}`)
  }
}

exports.sAdd = async (key, member, ttl) => {
  try {
    const client = exports.getRedisClient()
    const result = await client.sAdd(key, member)
    if (ttl) {
      await client.expire(key, ttl)
    }
    return result
  } catch (error) {
    throw new RedisError(`Failed to index session in Redis: ${error.message}`)
  }
}

exports.sMembers = async (key) => {
  try {
    return await exports.getRedisClient().sMembers(key)
  } catch (error) {
    throw new RedisError(`Failed to read session index in Redis: ${error.message}`)
  }
}

exports.sRem = async (key, member) => {
  try {
    return await exports.getRedisClient().sRem(key, member)
  } catch (error) {
    throw new RedisError(`Failed to update session index in Redis: ${error.message}`)
  }
}

exports.getGeneration = async (key) => {
  try {
    const value = await exports.getRedisClient().get(key)
    return value === null ? 0 : Number(value)
  } catch (error) {
    throw new RedisError(`Failed to read user revocation generation: ${error.message}`)
  }
}

exports.incrementGeneration = async (key) => {
  try {
    return Number(await exports.getRedisClient().incr(key))
  } catch (error) {
    throw new RedisError(`Failed to increment user revocation generation: ${error.message}`)
  }
}

const generationCheckLua = `
  local firstGenerationKey = tonumber(ARGV[1])
  local generationCount = tonumber(ARGV[2])
  for i = 1, generationCount do
    local current = redis.call('GET', KEYS[firstGenerationKey + i - 1]) or '0'
    if tostring(current) ~= tostring(ARGV[2 + i]) then return false end
  end
`

exports.createSessionAtomic = async ({
  sessionKey,
  refreshKey,
  indexKeys,
  generationKeys,
  generationValues,
  sessionId,
  sessionData,
  sessionTTL,
  refreshHash,
  refreshTTL,
}) => {
  try {
    const script = `
      if redis.call('EXISTS', KEYS[1]) == 1 or redis.call('EXISTS', KEYS[2]) == 1 then
        return -1
      end
      ${generationCheckLua}
      redis.call('SET', KEYS[1], ARGV[3 + tonumber(ARGV[2])], 'EX', ARGV[4 + tonumber(ARGV[2])])
      redis.call('SET', KEYS[2], ARGV[5 + tonumber(ARGV[2])], 'EX', ARGV[6 + tonumber(ARGV[2])])
      local indexCount = tonumber(ARGV[7 + tonumber(ARGV[2])])
      local sessionId = ARGV[8 + tonumber(ARGV[2])]
      for i = 1, indexCount do
        redis.call('SADD', KEYS[2 + i], sessionId)
        redis.call('EXPIRE', KEYS[2 + i], ARGV[4 + tonumber(ARGV[2])])
      end
      return 1
    `
    const generationCount = generationKeys.length
    const result = await exports.getRedisClient().eval(script, {
      keys: [sessionKey, refreshKey, ...indexKeys, ...generationKeys],
      arguments: [
        String(3 + indexKeys.length),
        String(generationCount),
        ...generationValues.map(String),
        sessionData,
        String(sessionTTL),
        refreshHash,
        String(refreshTTL),
        String(indexKeys.length),
        sessionId,
      ],
    })
    return Number(result)
  } catch (error) {
    throw new RedisError(`Failed to atomically create session: ${error.message}`)
  }
}

exports.touchSessionAtomic = async ({
  sessionKey,
  indexKeys,
  generationKeys,
  generationValues,
  sessionId,
  expectedVersion,
  sessionData,
  sessionTTL,
}) => {
  try {
    const script = `
      local currentJson = redis.call('GET', KEYS[1])
      if not currentJson then return 0 end
      local ok, current = pcall(cjson.decode, currentJson)
      if not ok or tostring(current.sessionVersion or 1) ~= tostring(ARGV[3 + tonumber(ARGV[2])]) then
        return -1
      end
      ${generationCheckLua}
      local generationCount = tonumber(ARGV[2])
      local updatedData = ARGV[4 + generationCount]
      local ttl = ARGV[5 + generationCount]
      local indexCount = tonumber(ARGV[6 + generationCount])
      local sessionId = ARGV[7 + generationCount]
      redis.call('SET', KEYS[1], updatedData, 'EX', ttl, 'XX')
      for i = 1, indexCount do
        redis.call('SADD', KEYS[1 + i], sessionId)
        redis.call('EXPIRE', KEYS[1 + i], ttl)
      end
      return 1
    `
    const result = await exports.getRedisClient().eval(script, {
      keys: [sessionKey, ...indexKeys, ...generationKeys],
      arguments: [
        String(2 + indexKeys.length),
        String(generationKeys.length),
        ...generationValues.map(String),
        String(expectedVersion),
        sessionData,
        String(sessionTTL),
        String(indexKeys.length),
        sessionId,
      ],
    })
    return Number(result)
  } catch (error) {
    throw new RedisError(`Failed to atomically update session activity: ${error.message}`)
  }
}

exports.rotateSessionAtomic = async ({
  sessionKey,
  refreshKey,
  indexKeys,
  generationKeys,
  generationValues,
  sessionId,
  expectedVersion,
  expectedRefreshHash,
  sessionData,
  sessionTTL,
  refreshHash,
  refreshTTL,
}) => {
  try {
    const script = `
      local currentJson = redis.call('GET', KEYS[1])
      local currentRefresh = redis.call('GET', KEYS[2])
      if not currentJson or not currentRefresh then return 0 end
      if tostring(currentRefresh) ~= tostring(ARGV[3 + tonumber(ARGV[2])]) then return -1 end
      local ok, current = pcall(cjson.decode, currentJson)
      if not ok or tostring(current.sessionVersion or 1) ~= tostring(ARGV[4 + tonumber(ARGV[2])]) then
        return -1
      end
      ${generationCheckLua}
      local generationCount = tonumber(ARGV[2])
      local updatedData = ARGV[5 + generationCount]
      local sessionTTL = ARGV[6 + generationCount]
      local refreshHash = ARGV[7 + generationCount]
      local refreshTTL = ARGV[8 + generationCount]
      local indexCount = tonumber(ARGV[9 + generationCount])
      local sessionId = ARGV[10 + generationCount]
      redis.call('SET', KEYS[1], updatedData, 'EX', sessionTTL, 'XX')
      redis.call('SET', KEYS[2], refreshHash, 'EX', refreshTTL, 'XX')
      for i = 1, indexCount do
        redis.call('SADD', KEYS[2 + i], sessionId)
        redis.call('EXPIRE', KEYS[2 + i], sessionTTL)
      end
      return 1
    `
    const result = await exports.getRedisClient().eval(script, {
      keys: [sessionKey, refreshKey, ...indexKeys, ...generationKeys],
      arguments: [
        String(3 + indexKeys.length),
        String(generationKeys.length),
        ...generationValues.map(String),
        expectedRefreshHash,
        String(expectedVersion),
        sessionData,
        String(sessionTTL),
        refreshHash,
        String(refreshTTL),
        String(indexKeys.length),
        sessionId,
      ],
    })
    return Number(result)
  } catch (error) {
    throw new RedisError(`Failed to atomically rotate session: ${error.message}`)
  }
}

exports.deleteSessionAtomic = async ({ sessionKey, refreshKey, indexKeys, sessionId }) => {
  try {
    const script = `
      redis.call('DEL', KEYS[1], KEYS[2])
      for i = 3, #KEYS do redis.call('SREM', KEYS[i], ARGV[1]) end
      return 1
    `
    return Number(
      await exports.getRedisClient().eval(script, {
        keys: [sessionKey, refreshKey, ...indexKeys],
        arguments: [sessionId],
      })
    )
  } catch (error) {
    throw new RedisError(`Failed to atomically delete session: ${error.message}`)
  }
}

exports.incrementWithWindow = async (key, windowMs) => {
  try {
    const script = `
      local count = redis.call('INCR', KEYS[1])
      if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
      local ttl = redis.call('PTTL', KEYS[1])
      return {count, ttl}
    `
    const result = await exports.getRedisClient().eval(script, {
      keys: [key],
      arguments: [String(windowMs)],
    })
    return { count: Number(result[0]), ttl: Number(result[1]) }
  } catch (error) {
    throw new RedisError(`Failed to apply rate limit in Redis: ${error.message}`)
  }
}
