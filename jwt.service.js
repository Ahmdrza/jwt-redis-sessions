var jwt = require('jsonwebtoken')

const { redisClient } = require('./redis.config')

exports.generateToken = (data = {}) => {
  return new Promise(async (resolve, reject) => {
    if (!process.env.JWT_SECRET) {
      reject({ message: 'Secret is required' })
    }

    if (typeof process.env.JWT_SECRET !== 'string') {
      reject({ message: 'Secret should be a string' })
    }

    const token = jwt.sign({}, process.env.JWT_SECRET)
    const expTime = 60 * 60 * 24

    try {
      await redisClient.connect()
      await redisClient.set(token, JSON.stringify({ ...data }), {
        EX: expTime,
      })
      resolve(token)
    } catch (error) {
      reject({ message: 'Redis encountered an error', details: err })
    }
  })
}

exports.verifyToken = (token) => {
  return new Promise(async (resolve, reject) => {
    jwt.verify(token, process.env.JWT_SECRET)

    try {
      await redisClient.connect()
      const reply = await redisClient.get(token)
      if (reply) {
        resolve('success')
      } else {
        reject({ message: 'Token not found' })
      }
    } catch (error) {
      reject({ message: 'Redis encountered an error', details: err })
    }
  })
}

exports.refreshToken = (token) => {
  return new Promise(async (resolve, reject) => {
    jwt.verify(token, process.env.JWT_SECRET)

    try {
      await redisClient.connect()
      const reply = await redisClient.get(token)
      if (reply) {
        const data = JSON.parse(reply)
        await redisClient.del(token)
        const newToken = await this.generateToken(data)
        resolve(newToken)
      } else {
        reject({ message: 'Token not found' })
      }
    } catch (error) {
      reject({ message: 'Redis encountered an error', details: err })
    }
  })
}
