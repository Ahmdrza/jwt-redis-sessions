var jwt = require('jsonwebtoken')

const { redisClient } = require('./redis.config')

exports.generateToken = async (data = {}) => {
  if (!process.env.JWT_SECRET) {
    throw { message: 'Secret is required' }
  }

  if (typeof process.env.JWT_SECRET !== 'string') {
    throw { message: 'Secret should be a string' }
  }

  const token = jwt.sign({}, process.env.JWT_SECRET)
  const expTime = 60 * 60 * 24

  try {
    await redisClient.set(token, JSON.stringify({ ...data }), {
      EX: expTime,
    })
    return token
  } catch (error) {
    throw { message: 'Redis encountered an error', details: error }
  }
}

exports.verifyToken = async (token) => {
  jwt.verify(token, process.env.JWT_SECRET)

  try {
    const reply = await redisClient.get(token)
    if (reply) {
      return 'success'
    } else {
      throw { message: 'Token not found' }
    }
  } catch (error) {
    throw { message: 'Redis encountered an error', details: error }
  }
}

exports.refreshToken = async (token) => {
  jwt.verify(token, process.env.JWT_SECRET)

  try {
    const reply = await redisClient.get(token)
    if (reply) {
      const data = JSON.parse(reply)
      await redisClient.del(token)
      const newToken = await this.generateToken(data)
      return newToken
    } else {
      throw { message: 'Token not found' }
    }
  } catch (error) {
    throw { message: 'Redis encountered an error', details: error }
  }
}
