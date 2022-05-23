const redis = require('redis')

const redisClient = redis.createClient()

redisClient.on('error', (err) => console.log('Redis Client Error', err))

exports.bootstrapRedis = async () => {
  await redisClient.connect()
}

exports.redisClient = redisClient
