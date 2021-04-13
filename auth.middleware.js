const { verifyToken } = require('./jwt.service')

exports.auth = async (req, res, next) => {
  let message = null

  if (!req.jrs || !req.jrs.secret) {
    message = 'Secret is required'
  } else if (typeof req.jrs.secret !== 'string') {
    message = 'Secret should be a string'
  } else if (!req.headers.authorization) {
    message = 'Authorization header not found'
  } else if (typeof req.headers.authorization !== 'string') {
    message = 'Invalid authorization header structure'
  }

  if (message) {
    res.status(401).json({
      status: 'UNAUTHORIZED',
      message: message,
    })
  }

  let splitHeaderData = req.headers.authorization.split(' ')

  if (splitHeaderData.length < 1) {
    res.status(401).json({
      status: 'UNAUTHORIZED',
      message: 'Invalid authorization header structure',
    })
  }

  try {
    await verifyToken(req.jrs.secret, splitHeaderData[1])
    next()
  } catch (error) {
    res.status(401).json({
      status: 'UNAUTHORIZED',
      message: error.message,
    })
  }
}
