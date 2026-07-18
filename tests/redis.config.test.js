jest.unmock('../redis.config')

const redis = require('redis')
const redisConfig = require('../redis.config')
const { RedisError } = require('../errors')

describe('Redis adapter', () => {
  afterEach(async () => {
    await redisConfig.closeRedisConnection()
  })

  it('coalesces concurrent connection attempts', async () => {
    await Promise.all([
      redisConfig.bootstrapRedis(),
      redisConfig.bootstrapRedis(),
      redisConfig.bootstrapRedis(),
    ])

    expect(redis.createClient).toHaveBeenCalledTimes(1)
    expect(mockRedisClient.connect).toHaveBeenCalledTimes(1)
    expect(redisConfig.isRedisConnected()).toBe(true)
  })

  it('implements atomic and indexed Redis operations', async () => {
    await redisConfig.bootstrapRedis()
    await redisConfig.setWithExpiry('test:string', 'value', 60)
    await expect(redisConfig.get('test:string')).resolves.toBe('value')
    await expect(redisConfig.exists('test:string')).resolves.toBe(1)
    await expect(redisConfig.getDel('test:string')).resolves.toBe('value')
    await expect(redisConfig.exists('test:string')).resolves.toBe(0)

    await redisConfig.sAdd('test:set', 'one', 60)
    await redisConfig.sAdd('test:set', 'two', 60)
    await expect(redisConfig.sMembers('test:set')).resolves.toEqual(['one', 'two'])
    await expect(redisConfig.sRem('test:set', 'one')).resolves.toBe(1)

    await expect(redisConfig.incrementWithWindow('test:limit', 10_000)).resolves.toEqual(
      expect.objectContaining({ count: 1 })
    )
    await expect(redisConfig.del('test:set')).resolves.toBe(1)
  })

  it('does not close an application-owned connected client', async () => {
    const externalClient = { ...mockRedisClient, isOpen: true, isReady: true }
    redisConfig.useRedisClient(externalClient)

    await redisConfig.bootstrapRedis()
    await redisConfig.closeRedisConnection()

    expect(externalClient.connect).not.toHaveBeenCalled()
    expect(externalClient.quit).not.toHaveBeenCalled()
  })

  it('rejects disconnected or incompatible supplied clients', () => {
    expect(() => redisConfig.useRedisClient({})).toThrow(RedisError)
    expect(() =>
      redisConfig.useRedisClient({ ...mockRedisClient, isOpen: false, isReady: false })
    ).toThrow('must already be connected')
  })

  it('wraps command failures without exposing adapter errors', async () => {
    await redisConfig.bootstrapRedis()
    mockRedisClient.get.mockRejectedValueOnce(new Error('socket unavailable'))

    await expect(redisConfig.get('test:key')).rejects.toThrow(RedisError)
    await expect(redisConfig.get('test:key')).resolves.toBeNull()
  })
})
