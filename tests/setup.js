// Mock Redis client
const mockRedisStore = new Map()
const mockRedisClient = {
  set: jest.fn(async (key, value, options) => {
    mockRedisStore.set(key, { value, options })
    return 'OK'
  }),
  get: jest.fn(async (key) => {
    const item = mockRedisStore.get(key)
    return item ? item.value : null
  }),
  getDel: jest.fn(async (key) => {
    const item = mockRedisStore.get(key)
    mockRedisStore.delete(key)
    return item ? item.value : null
  }),
  del: jest.fn(async (key) => {
    const existed = mockRedisStore.has(key)
    mockRedisStore.delete(key)
    return existed ? 1 : 0
  }),
  exists: jest.fn(async (key) => {
    return mockRedisStore.has(key) ? 1 : 0
  }),
  incr: jest.fn(async (key) => {
    const current = Number(mockRedisStore.get(key)?.value || 0) + 1
    mockRedisStore.set(key, { value: String(current) })
    return current
  }),
  sAdd: jest.fn(async (key, member) => {
    const item = mockRedisStore.get(key)
    const members = item?.members || new Set()
    const existed = members.has(member)
    members.add(member)
    mockRedisStore.set(key, { members })
    return existed ? 0 : 1
  }),
  sMembers: jest.fn(async (key) => Array.from(mockRedisStore.get(key)?.members || [])),
  sRem: jest.fn(async (key, member) => {
    const members = mockRedisStore.get(key)?.members
    if (!members) return 0
    return members.delete(member) ? 1 : 0
  }),
  expire: jest.fn(async () => 1),
  eval: jest.fn(async (_script, { keys, arguments: args }) => {
    const key = keys[0]
    const item = mockRedisStore.get(key) || { count: 0 }
    item.count += 1
    item.expiresAt ||= Date.now() + Number(args[0])
    mockRedisStore.set(key, item)
    return [item.count, Math.max(0, item.expiresAt - Date.now())]
  }),
  keys: jest.fn(async (pattern) => {
    const keys = Array.from(mockRedisStore.keys())
    if (pattern.includes('*')) {
      const regex = new RegExp(pattern.replace(/\*/g, '.*'))
      return keys.filter((key) => regex.test(key))
    }
    return keys.filter((key) => key === pattern)
  }),
  scan: jest.fn(async (cursor, options = {}) => {
    const keys = Array.from(mockRedisStore.keys())
    let filteredKeys = keys

    if (options.MATCH) {
      const pattern = options.MATCH.replace(/\*/g, '.*')
      const regex = new RegExp(pattern)
      filteredKeys = keys.filter((key) => regex.test(key))
    }

    // Simulate cursor-based pagination
    const startIndex = parseInt(cursor) || 0
    const count = options.COUNT || 10
    const endIndex = Math.min(startIndex + count, filteredKeys.length)
    const resultKeys = filteredKeys.slice(startIndex, endIndex)
    const nextCursor = endIndex >= filteredKeys.length ? '0' : endIndex.toString()

    return {
      cursor: nextCursor,
      keys: resultKeys,
    }
  }),
  ping: jest.fn(async () => 'PONG'),
  connect: jest.fn(async () => {}),
  quit: jest.fn(async () => {}),
  on: jest.fn(),
}

// Mock Redis module
jest.mock('redis', () => ({
  createClient: jest.fn(() => mockRedisClient),
}))

// Create mock Redis helper functions that also call the client methods for test verification
const createMockRedisHelper = () => {
  const config = require('../config')

  const setWithExpiry = jest.fn(async (key, value, ttl) => {
    // Handle both prefixed and non-prefixed keys
    const finalKey = key.startsWith(config.redis.keyPrefix)
      ? key
      : `${config.redis.keyPrefix}${key}`
    mockRedisStore.set(finalKey, { value, ttl })
    // Also call the client method for test verification
    await mockRedisClient.set(finalKey, value, { EX: ttl })
    return 'OK'
  })

  const get = jest.fn(async (key) => {
    // Handle both prefixed and non-prefixed keys
    const finalKey = key.startsWith(config.redis.keyPrefix)
      ? key
      : `${config.redis.keyPrefix}${key}`
    const item = mockRedisStore.get(finalKey)
    // Also call the client method for test verification
    await mockRedisClient.get(finalKey)
    return item ? item.value : null
  })

  const getDel = jest.fn(async (key) => {
    const finalKey = key.startsWith(config.redis.keyPrefix)
      ? key
      : `${config.redis.keyPrefix}${key}`
    const item = mockRedisStore.get(finalKey)
    mockRedisStore.delete(finalKey)
    await mockRedisClient.getDel(finalKey)
    return item ? item.value : null
  })

  const del = jest.fn(async (key) => {
    // Handle both prefixed and non-prefixed keys
    const finalKey = key.startsWith(config.redis.keyPrefix)
      ? key
      : `${config.redis.keyPrefix}${key}`
    const existed = mockRedisStore.has(finalKey)
    mockRedisStore.delete(finalKey)
    // Also call the client method for test verification
    await mockRedisClient.del(finalKey)
    return existed ? 1 : 0
  })

  const exists = jest.fn(async (key) => {
    // Handle both prefixed and non-prefixed keys
    const finalKey = key.startsWith(config.redis.keyPrefix)
      ? key
      : `${config.redis.keyPrefix}${key}`
    const result = mockRedisStore.has(finalKey) ? 1 : 0
    // Also call the client method for test verification
    await mockRedisClient.exists(finalKey)
    return result
  })

  const sAdd = jest.fn(async (key, member, ttl) => {
    const item = mockRedisStore.get(key)
    const members = item?.members || new Set()
    const existed = members.has(member)
    members.add(member)
    mockRedisStore.set(key, { members, ttl })
    await mockRedisClient.sAdd(key, member)
    return existed ? 0 : 1
  })

  const sMembers = jest.fn(async (key) => {
    await mockRedisClient.sMembers(key)
    return Array.from(mockRedisStore.get(key)?.members || [])
  })

  const sRem = jest.fn(async (key, member) => {
    const members = mockRedisStore.get(key)?.members
    const result = members?.delete(member) ? 1 : 0
    await mockRedisClient.sRem(key, member)
    return result
  })

  const incrementWithWindow = jest.fn(async (key, windowMs) => {
    const result = await mockRedisClient.eval('', {
      keys: [key],
      arguments: [String(windowMs)],
    })
    return { count: Number(result[0]), ttl: Number(result[1]) }
  })

  const getGeneration = jest.fn(async (key) => {
    const value = mockRedisStore.get(key)?.value
    return value === undefined ? 0 : Number(value)
  })

  const incrementGeneration = jest.fn(async (key) => mockRedisClient.incr(key))

  const generationsMatch = (generationKeys, generationValues) =>
    generationKeys.every(
      (key, index) =>
        String(mockRedisStore.get(key)?.value ?? 0) === String(generationValues[index])
    )

  const addIndexes = async (indexKeys, sessionId, ttl) => {
    for (const key of indexKeys) {
      await sAdd(key, sessionId, ttl)
    }
  }

  const createSessionAtomic = jest.fn(async (options) => {
    if (mockRedisStore.has(options.sessionKey) || mockRedisStore.has(options.refreshKey)) {
      return -1
    }
    if (!generationsMatch(options.generationKeys, options.generationValues)) return 0

    await setWithExpiry(options.sessionKey, options.sessionData, options.sessionTTL)
    await setWithExpiry(options.refreshKey, options.refreshHash, options.refreshTTL)
    await addIndexes(options.indexKeys, options.sessionId, options.sessionTTL)
    return 1
  })

  const touchSessionAtomic = jest.fn(async (options) => {
    const currentJson = mockRedisStore.get(options.sessionKey)?.value
    if (!currentJson) return 0
    const current = JSON.parse(currentJson)
    if (current.sessionVersion !== options.expectedVersion) return -1
    if (!generationsMatch(options.generationKeys, options.generationValues)) return 0

    await setWithExpiry(options.sessionKey, options.sessionData, options.sessionTTL)
    await addIndexes(options.indexKeys, options.sessionId, options.sessionTTL)
    return 1
  })

  const rotateSessionAtomic = jest.fn(async (options) => {
    const currentJson = mockRedisStore.get(options.sessionKey)?.value
    const currentRefresh = mockRedisStore.get(options.refreshKey)?.value
    if (!currentJson || !currentRefresh) return 0
    const current = JSON.parse(currentJson)
    if (
      current.sessionVersion !== options.expectedVersion ||
      currentRefresh !== options.expectedRefreshHash
    ) {
      return -1
    }
    if (!generationsMatch(options.generationKeys, options.generationValues)) return 0

    await setWithExpiry(options.sessionKey, options.sessionData, options.sessionTTL)
    await setWithExpiry(options.refreshKey, options.refreshHash, options.refreshTTL)
    await addIndexes(options.indexKeys, options.sessionId, options.sessionTTL)
    return 1
  })

  const deleteSessionAtomic = jest.fn(async (options) => {
    await del(options.sessionKey)
    await del(options.refreshKey)
    for (const key of options.indexKeys) {
      await sRem(key, options.sessionId)
    }
    return 1
  })

  return {
    bootstrapRedis: jest.fn(async () => mockRedisClient),
    getRedisClient: jest.fn(() => mockRedisClient),
    closeRedisConnection: jest.fn(async () => {}),
    useRedisClient: jest.fn(),
    isRedisConnected: jest.fn(() => true),
    setWithExpiry,
    get,
    getDel,
    del,
    exists,
    sAdd,
    sMembers,
    sRem,
    getGeneration,
    incrementGeneration,
    createSessionAtomic,
    touchSessionAtomic,
    rotateSessionAtomic,
    deleteSessionAtomic,
    incrementWithWindow,
  }
}

// Mock the Redis config helper functions
jest.mock('../redis.config', () => createMockRedisHelper())

// Set test environment variables
process.env.JWT_SECRET = 'test-secret-key-that-is-at-least-32-characters-long'
process.env.NODE_ENV = 'test'
process.env.REDIS_URL = 'redis://localhost:6379'

// Global test utilities
global.mockRedisClient = mockRedisClient
global.mockRedisStore = mockRedisStore

// Clear mocks before each test
beforeEach(() => {
  mockRedisStore.clear()
  jest.clearAllMocks()
  // Silence console.error for cleaner test output
  jest.spyOn(console, 'error').mockImplementation(() => {})
})

// Restore console after each test
afterEach(() => {
  jest.restoreAllMocks()
})
