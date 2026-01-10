/**
 * Authentication Middleware
 * Protects routes by verifying JWT tokens
 * Redirects unauthorized users to login
 */

const jwt = require('jsonwebtoken');
const memoryStore = require('../utils/memoryStore');

/**
 * AUTHENTICATION FLOW:
 * 1. Extract JWT token from cookies or Authorization header
 * 2. Verify token signature and expiration
 * 3. Decode token to get user ID
 * 4. Fetch user from database
 * 5. Attach user object to request
 * 6. Allow access to protected route
 */

const protect = async (req, res, next) => {
    try {
        let token;

        // Check for token in cookies (HTTP-only - more secure)
        if (req.cookies.token) {
            token = req.cookies.token;
        }
        // Fallback: Check Authorization header (Bearer token)
        else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        }

        // No token found
        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Access denied. Please log in to continue.',
                redirect: '/login'
            });
        }

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // JS-only: resolve user from memory store using email
        if (!decoded.email) {
            return res.status(401).json({ success: false, message: 'Invalid token payload' });
        }
        const mUser = await memoryStore.findByEmail(decoded.email);
        const user = mUser ? { id: mUser.id, fullName: mUser.fullName, email: mUser.email, isActive: true } : null;

        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'User not found. Please log in again.',
                redirect: '/login'
            });
        }

        // Check if user is active
        if (!user.isActive) {
            return res.status(403).json({
                success: false,
                message: 'Your account has been deactivated. Please contact support.'
            });
        }

        // Attach user to request object
        req.user = user;
        next();

    } catch (error) {
        // Token expired or invalid
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                message: 'Invalid token. Please log in again.',
                redirect: '/login'
            });
        }

        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Session expired. Please log in again.',
                redirect: '/login'
            });
        }

        return res.status(500).json({
            success: false,
            message: 'Authentication error occurred.'
        });
    }
};

module.exports = { protect };
