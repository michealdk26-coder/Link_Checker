/**
 * JWT Utility Functions
 * Handles token generation and cookie management
 */

const jwt = require('jsonwebtoken');

/**
 * Generate JWT Token
 * @param {String} userId - User's MongoDB _id
 * @returns {String} - Signed JWT token
 */
const generateToken = (user) => {
    // Payload contains id when using MongoDB, or minimal identity when using memory store
    const payload = {
        id: user._id || user.id || undefined,
        email: user.email,
        fullName: user.fullName,
    };
    return jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRE || '7d',
    });
};

/**
 * Send Token Response
 * Creates JWT, sets HTTP-only cookie, and sends response
 * @param {Object} user - User object
 * @param {Number} statusCode - HTTP status code
 * @param {Object} res - Express response object
 */
const sendTokenResponse = (user, statusCode, res) => {
    // Generate token
    const token = generateToken(user);

    // Cookie options
    const cookieOptions = {
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        httpOnly: true, // Prevents XSS attacks
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        sameSite: 'strict' // CSRF protection
    };

    // Remove password from output
    user.password = undefined;

    res.status(statusCode)
        .cookie('token', token, cookieOptions)
        .json({
            success: true,
            token,
            user: {
                id: user._id || user.id,
                fullName: user.fullName,
                email: user.email,
                createdAt: user.createdAt
            }
        });
};

module.exports = { generateToken, sendTokenResponse };
