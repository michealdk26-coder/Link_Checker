/**
 * SecureLink Checker - Main Server File
 * Authentication-based URL Security Scanner
 * Built by Dike Micheal
 * 
 * Tech Stack:
 * - Node.js + Express.js
 * - MongoDB (Mongoose)
 * - JWT Authentication
 * - bcrypt for password hashing
 */

const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Import routes
const authRoutes = require('./routes/authRoutes');
const scanRoutes = require('./routes/scanRoutes');

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    credentials: true
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Decide whether to use MongoDB or in-memory fallback
const shouldUseMongo = () => {
    if (process.env.USE_IN_MEMORY === 'true') return false;
    const uri = process.env.MONGODB_URI;
    if (!uri) return false;
    if (uri.includes('<db_password>')) return false; // placeholder not filled
    return true;
};

if (shouldUseMongo()) {
    mongoose.connect(process.env.MONGODB_URI)
        .then(() => console.log('✅ MongoDB Connected Successfully'))
        .catch(err => {
            console.error('❌ MongoDB Connection Error:', err.message);
            console.log('⚠️  Using in-memory store instead. Set USE_IN_MEMORY=true to skip MongoDB.');
        });
} else {
    console.log('ℹ️ Skipping MongoDB connection. Using in-memory store for auth.');
}
// Routes
app.use('/api/auth', authRoutes);
app.use('/api/scan', scanRoutes);

// Serve HTML pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Route not found'
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 SecureLink Checker Server running on port ${PORT}`);
    console.log(`📍 http://localhost:${PORT}`);
});
