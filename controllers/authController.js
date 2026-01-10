/**
 * Authentication Controller
 * Handles user signup, login, logout, and profile operations
 */

const memoryStore = require('../utils/memoryStore');
const { sendTokenResponse } = require('../utils/jwtUtils');
const { validateSignup, validateLogin, sanitizeInput } = require('../utils/validation');

/**
 * @route   POST /api/auth/signup
 * @desc    Register a new user
 * @access  Public
 */
const signup = async (req, res) => {
    try {
        const { fullName, email, password, confirmPassword } = req.body;

        // Validate input
        const validation = validateSignup(fullName, email, password, confirmPassword);
        if (!validation.isValid) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: validation.errors
            });
        }

        // Sanitize inputs
        const sanitizedName = sanitizeInput(fullName);
        // JS-only: create user in memory store
        try {
            const existing = await memoryStore.findByEmail(email.toLowerCase());
            if (existing) {
                return res.status(409).json({ success: false, message: 'An account with this email already exists' });
            }
            const user = await memoryStore.createUser({
                fullName: sanitizedName,
                email: email.toLowerCase(),
                password
            });
            return sendTokenResponse(user, 201, res);
        } catch (err) {
            if (err && err.message === 'duplicate_email') {
                return res.status(409).json({ success: false, message: 'An account with this email already exists' });
            }
            throw err;
        }

    } catch (error) {
        console.error('Signup Error:', error);

        // More detailed error message
        let errorMessage = 'Unable to connect to database. Please contact administrator.';

        if (error.name === 'MongooseError' && error.message.includes('buffering timed out')) {
            errorMessage = '⚠️ Database not connected. MongoDB needs to be setup. Check QUICK_MONGODB_FIX.md';
        } else if (error.name === 'ValidationError') {
            errorMessage = 'Validation error: ' + Object.values(error.errors).map(e => e.message).join(', ');
        } else if (error.code === 11000) {
            errorMessage = 'An account with this email already exists';
        } else if (error.message) {
            console.log('Detailed error:', error.message);
        }

        res.status(500).json({
            success: false,
            message: errorMessage
        });
    }
};

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        const validation = validateLogin(email, password);
        if (!validation.isValid) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: validation.errors
            });
        }

        // JS-only: use memory store
        const mUser = await memoryStore.findByEmail(email.toLowerCase());
        if (!mUser) {
            return res.status(401).json({ success: false, message: 'Invalid email or password' });
        }
        const ok = await memoryStore.comparePassword(password, mUser.password);
        if (!ok) {
            return res.status(401).json({ success: false, message: 'Invalid email or password' });
        }
        await memoryStore.updateLastLogin(mUser.email);
        const user = { id: mUser.id, fullName: mUser.fullName, email: mUser.email, createdAt: mUser.createdAt };
        return sendTokenResponse(user, 200, res);

    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred during login. Please try again.'
        });
    }
};

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user (clear cookie)
 * @access  Private
 */
const logout = async (req, res) => {
    try {
        res.cookie('token', 'none', {
            expires: new Date(Date.now() + 10 * 1000),
            httpOnly: true
        });

        res.status(200).json({
            success: true,
            message: 'Logged out successfully'
        });
    } catch (error) {
        console.error('Logout Error:', error);
        res.status(500).json({
            success: false,
            message: 'Logout failed'
        });
    }
};

/**
 * @route   GET /api/auth/me
 * @desc    Get current logged in user
 * @access  Private
 */
const getMe = async (req, res) => {
    try {
        // JS-only: Use data from memory store
        const mUser = await memoryStore.findByEmail(req.user.email);
        if (!mUser) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        return res.status(200).json({
            success: true,
            user: {
                id: mUser.id,
                fullName: mUser.fullName,
                email: mUser.email,
                createdAt: mUser.createdAt,
                lastLogin: mUser.lastLogin
            }
        });
    } catch (error) {
        console.error('Get User Error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve user information'
        });
    }
};

module.exports = {
    signup,
    login,
    logout,
    getMe
};
