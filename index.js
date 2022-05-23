require('dotenv').config()

const config = require('./redis.config')
const service = require('./jwt.service')
const middleware = require('./auth.middleware')

config.bootstrapRedis()

exports.generateToken = service.generateToken
exports.auth = middleware.auth
