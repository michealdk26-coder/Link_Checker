/**
 * Input Validation Utility
 * Validates and sanitizes user inputs
 */

const validator = require('validator');

/**
 * Validate signup data
 */
const validateSignup = (fullName, email, password, confirmPassword) => {
    const errors = [];

    // Validate full name
    if (!fullName || fullName.trim().length < 2) {
        errors.push('Full name must be at least 2 characters long');
    }

    if (fullName && fullName.trim().length > 100) {
        errors.push('Full name cannot exceed 100 characters');
    }

    // Validate email
    if (!email) {
        errors.push('Email is required');
    } else if (!validator.isEmail(email)) {
        errors.push('Please provide a valid email address');
    }

    // Validate password
    if (!password) {
        errors.push('Password is required');
    } else if (password.length < 8) {
        errors.push('Password must be at least 8 characters long');
    }

    // Password strength check (optional but recommended)
    if (password && password.length >= 8) {
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumber = /[0-9]/.test(password);

        // Make this a warning, not an error - don't block signup
        if (!hasUpperCase || !hasLowerCase || !hasNumber) {
            // Just log it, don't add to errors
            console.log('Password could be stronger with uppercase, lowercase, and numbers');
        }
    }

    // Validate password confirmation
    if (password !== confirmPassword) {
        errors.push('Passwords do not match');
    }

    return {
        isValid: errors.length === 0,
        errors
    };
};

/**
 * Validate login data
 */
const validateLogin = (email, password) => {
    const errors = [];

    if (!email) {
        errors.push('Email is required');
    } else if (!validator.isEmail(email)) {
        errors.push('Please provide a valid email address');
    }

    if (!password) {
        errors.push('Password is required');
    }

    return {
        isValid: errors.length === 0,
        errors
    };
};

/**
 * Validate URL format
 */
const validateURL = (url) => {
    if (!url) {
        return { isValid: false, error: 'URL is required' };
    }

    // Add protocol if missing
    let formattedURL = url.trim();
    if (!formattedURL.startsWith('http://') && !formattedURL.startsWith('https://')) {
        formattedURL = 'https://' + formattedURL;
    }

    // Validate URL format
    if (!validator.isURL(formattedURL, { require_protocol: true })) {
        return { isValid: false, error: 'Please provide a valid URL' };
    }

    return { isValid: true, url: formattedURL };
};

/**
 * Sanitize string input (prevent XSS)
 */
const sanitizeInput = (input) => {
    if (!input) return '';
    return validator.escape(input.trim());
};

module.exports = {
    validateSignup,
    validateLogin,
    validateURL,
    sanitizeInput
};
