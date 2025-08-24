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
  del: jest.fn(async (key) => {
    const existed = mockRedisStore.has(key)
    mockRedisStore.delete(key)
    return existed ? 1 : 0
  }),
  exists: jest.fn(async (key) => {
    return mockRedisStore.has(key) ? 1 : 0
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
    const prefixedKey = `${config.redis.keyPrefix}${key}`
    mockRedisStore.set(prefixedKey, { value, ttl })
    // Also call the client method for test verification
    await mockRedisClient.set(prefixedKey, value, { EX: ttl })
    return 'OK'
  })

  const get = jest.fn(async (key) => {
    const prefixedKey = `${config.redis.keyPrefix}${key}`
    const item = mockRedisStore.get(prefixedKey)
    // Also call the client method for test verification
    await mockRedisClient.get(prefixedKey)
    return item ? item.value : null
  })

  const del = jest.fn(async (key) => {
    const prefixedKey = `${config.redis.keyPrefix}${key}`
    const existed = mockRedisStore.has(prefixedKey)
    mockRedisStore.delete(prefixedKey)
    // Also call the client method for test verification
    await mockRedisClient.del(prefixedKey)
    return existed ? 1 : 0
  })

  const exists = jest.fn(async (key) => {
    const prefixedKey = `${config.redis.keyPrefix}${key}`
    const result = mockRedisStore.has(prefixedKey) ? 1 : 0
    // Also call the client method for test verification
    await mockRedisClient.exists(prefixedKey)
    return result
  })

  return {
    bootstrapRedis: jest.fn(async () => mockRedisClient),
    getRedisClient: jest.fn(() => mockRedisClient),
    closeRedisConnection: jest.fn(async () => {}),
    isRedisConnected: jest.fn(() => true),
    setWithExpiry,
    get,
    del,
    exists,
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
