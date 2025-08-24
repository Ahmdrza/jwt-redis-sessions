const { revokeToken, revokeAllUserTokens } = require('./jwt.service')
const { validateAuthHeader } = require('./validation.util')
const { sendErrorResponse, sendSuccessResponse } = require('./utils')

// Logout current session
exports.logout = async (req, res) => {
  try {
    // Get token from header or request object (if auth middleware was used)
    const token = req.token || validateAuthHeader(req.headers.authorization)

    // Revoke the token
    const result = await revokeToken(token)

    return sendSuccessResponse(res, null, result.message)
  } catch (error) {
    return sendErrorResponse(res, error)
  }
}

// Logout all sessions for a user
exports.logoutAll = async (req, res) => {
  try {
    // Ensure user is authenticated
    if (!req.user) {
      throw new Error('Authentication required')
    }

    // Get user ID
    const userId = req.user.userId || req.user.id

    // Revoke all tokens for the user
    const result = await revokeAllUserTokens(userId)

    return sendSuccessResponse(res, null, result.message)
  } catch (error) {
    return sendErrorResponse(res, error)
  }
}
