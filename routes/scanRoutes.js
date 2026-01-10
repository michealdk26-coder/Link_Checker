/**
 * URL Scan Routes
 * Protected routes for URL security checking
 */

const express = require('express');
const router = express.Router();
const { scanURL } = require('../controllers/scanController');
const { protect } = require('../middleware/authMiddleware');

// All scan routes require authentication
router.post('/check', protect, scanURL);

module.exports = router;
