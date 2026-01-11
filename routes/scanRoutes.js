/**
 * URL Scan Routes
 * Protected routes for URL security checking
 */

const express = require('express');
const router = express.Router();
const { scanURL } = require('../controllers/scanController');

// Public scan route
router.post('/check', scanURL);

module.exports = router;
