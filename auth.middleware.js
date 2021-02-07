const { verifyToken } = require('./jwt.service')

exports.auth = async (req, res, next) => {
    if (req.jrs && req.jrs.secret) {
        if (typeof secret !== 'string') {
            res.status(401).json({
                status: 'INTERNAL_ERROR',
                message: 'Secret should be a string'
            })
        }

        if (secret === '') {
            res.status(401).json({
                status: 'INTERNAL_ERROR',
                message: 'Secret cannot be empty'
            })
        }
        try {
            await verifyToken(req.jrs.secret, req.body.token)
            next()
        } catch (error) {
            res.status(401).json({
                status: 'UNAUTHORIZED',
                message: error.message
            })
        }       
    } else {
        res.status(401).json({
            status: 'INTERNAL_ERROR',
            message: 'Secret Not Found'
        })
    }
}