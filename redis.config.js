/* eslint-disable no-console */
const redis = require('redis')
const config = require('./config')
const { RedisError } = require('./errors')

let redisClient = null
let isConnected = false

const createRedisClient = () => {
  const client = redis.createClient({
    url: config.redis.url,
    socket: {
      host: config.redis.host,
      port: config.redis.port,
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
    }

    if (!isConnected) {
      await redisClient.connect()
    }

    return redisClient
  } catch (error) {
    throw new RedisError(`Failed to connect to Redis: ${error.message}`)
  }
}

exports.getRedisClient = () => {
  if (!redisClient || !isConnected) {
    throw new RedisError('Redis client not initialized or not connected')
  }
  return redisClient
}

exports.closeRedisConnection = async () => {
  if (redisClient && isConnected) {
    await redisClient.quit()
    redisClient = null
    isConnected = false
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
