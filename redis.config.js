const redis = require('redis')

const redisClient = redis.createClient()

exports.redisClient = async () => await redisClient.connect()
