const { refreshToken } = require('./jwt.service')
const { validateAuthHeader, validateSecret } = require('./validation.util')
const config = require('./config')

// Error response helper
const sendErrorResponse = (res, error) => {
  const statusCode = error.statusCode || 401
  const code = error.code || 'UNAUTHORIZED'

  return res.status(statusCode).json({
    status: code,
    message: error.message,
    // Only include error details in development
    ...(process.env.NODE_ENV === 'development' && { details: error.stack }),
  })
}

// Refresh token endpoint handler
exports.refresh = async (req, res) => {
  try {
    // Validate JWT secret
    validateSecret(config.jwt.secret)

    // Extract and validate refresh token
    const token = validateAuthHeader(req.headers.authorization)

    // Refresh the token
    const newTokens = await refreshToken(token)

    return res.status(200).json({
      status: 'SUCCESS',
      data: newTokens,
    })
  } catch (error) {
    return sendErrorResponse(res, error)
  }
}
