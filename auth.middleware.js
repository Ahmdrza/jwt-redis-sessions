const { verifyToken } = require('./jwt.service')

exports.auth = async (req, res, next) => {
  let errorMessage = null

  if (!req.jrs || !req.jrs.secret) {
    errorMessage = 'Secret is required'
  } else if (req.jrs.secret === '') {
    errorMessage = 'Secret cannot be empty'
  } else if (typeof req.jrs.secret !== 'string') {
    errorMessage = 'Secret should be a string'
  } else if (!req.headers.authorization) {
    errorMessage = 'Authorization header not found'
  } else if (req.headers.authorization === '') {
    errorMessage = 'Authorization header cannot be empty'
  } else if (typeof req.headers.authorization !== 'string') {
    errorMessage = 'Invalid authorization header structure'
  }

  if (errorMessage) {
    res.status(401).json({
      status: 'UNAUTHORIZED',
      message: errorMessage,
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
