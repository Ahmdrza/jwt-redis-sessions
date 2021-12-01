var jwt = require('jsonwebtoken')

const { redisClient } = require('./redis.config')

exports.generateToken = (data = {}) => {
  return new Promise((resolve, reject) => {
    if (!process.env.JWT_SECRET) {
      reject({ message: 'Secret is required' })
    }

    if (typeof process.env.JWT_SECRET !== 'string') {
      reject({ message: 'Secret should be a string' })
    }

    const token = jwt.sign({}, process.env.JWT_SECRET)
    const expTime = 60 * 60 * 24

    redisClient.set(
      token,
      JSON.stringify({ ...data }),
      'EX',
      expTime,
      (err) => {
        if (err) {
          reject({ message: 'Redis encountered an error', details: err })
        }
        resolve(token)
      }
    )
  })
}

exports.verifyToken = (token) => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, process.env.JWT_SECRET)

    redisClient.get(token, (err, reply) => {
      if (err) reject({ message: 'Token not found' })
      if (reply) {
        resolve('success')
      } else {
        reject({ message: 'Token not found' })
      }
    })
  })
}

exports.refreshToken = (token) => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, process.env.JWT_SECRET)
    redisClient.get(token, async (err, reply) => {
      if (err) reject({ message: 'Token not found' })
      if (reply) {
        const data = JSON.parse(reply)
        redisClient.del(token)
        const newToken = await this.generateToken(data)
        resolve(newToken)
      } else {
        reject({ message: 'Token not found' })
      }
    })
  })
}
