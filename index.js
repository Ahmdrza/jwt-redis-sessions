require('dotenv').config()

const service = require('./jwt.service')
const middleware = require('./auth.middleware')

exports.generateToken = service.generateToken
exports.auth = middleware.auth
