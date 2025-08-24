const { refreshToken } = require('./jwt.service')
const { validateAuthHeader, validateSecret } = require('./validation.util')
const { sendErrorResponse, sendSuccessResponse } = require('./utils')
const config = require('./config')

// Refresh token endpoint handler
exports.refresh = async (req, res) => {
  try {
    // Validate JWT secret
    validateSecret(config.jwt.secret)

    // Extract and validate refresh token
    const token = validateAuthHeader(req.headers.authorization)

    // Refresh the token
    const newTokens = await refreshToken(token)

    return sendSuccessResponse(res, newTokens, 'Token refreshed successfully')
  } catch (error) {
    return sendErrorResponse(res, error)
  }
}
