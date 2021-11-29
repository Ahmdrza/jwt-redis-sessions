var jwt = require('jsonwebtoken')

const { redisClient } = require('./redis.config')

exports.generateToken = (secret, data = {}, dataToStoreInToken = {}) => {
  return new Promise((resolve, reject) => {
    if (!secret) {
      reject({ message: 'Secret is required' })
    }

    if (typeof secret !== 'string') {
      reject({ message: 'Secret should be a string' })
    }

    const msBeforeTokenGenerated = new Date().getTime()
    const token = jwt.sign(dataToStoreInToken, secret)

    const msAfterTokenGenerated = new Date().getTime()
    let timeElapsed = msAfterTokenGenerated - msBeforeTokenGenerated
    timeElapsed = ((timeElapsed % 60000) / 1000).toFixed(0) //convert ms to sec
    let expTime = 60 * 60 * 24
    expTime = expTime - timeElapsed

    const _data = { ...data }
    _data.lastRefresh = Math.floor(new Date().getTime() / 1000)

    redisClient.set(token, JSON.stringify(_data), 'EX', expTime, (err) => {
      if (err) {
        reject({ message: 'Redis encountered an error', details: err })
      }
      resolve(token)
    })
  })
}

exports.verifyToken = (token) => {
  return new Promise((resolve, reject) => {
    if (!process.env.JWT_SECRET) {
      reject({ message: 'Secret is required' })
    }

    jwt.verify(token, process.env.JWT_SECRET)

    redisClient.get(token, function (err, reply) {
      if (err) reject({ message: 'Token not found' })
      if (reply) {
        const tokenData = JSON.parse(reply)
        let lastRefresh = tokenData.lastRefresh
        var currentTime = Math.floor(new Date().getTime() / 1000)
        const diff = lastRefresh - currentTime

        if (diff < 0) {
          reject({ message: 'Authorization token expired' })
        }

        if (diff < 3600) {
          const newCurrentTime = Math.floor(new Date().getTime() / 1000)
          expiryTime = newCurrentTime + 86400
        }

        const updatedData = {
          ...tokenData,
          lastRefresh: Math.floor(new Date().getTime() / 1000),
          expiryTime: expiryTime,
        }

        redisClient.set(
          token,
          JSON.stringify(updatedData),
          'EX',
          expiryTime,
          (err) => {
            if (err) {
              reject({ message: 'Redis encountered an error', details: err })
            }
            resolve('success')
          }
        )
      } else {
        reject({ message: 'Authorization token not found' })
      }
    })
  })
}
