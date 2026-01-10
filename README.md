# SecureLink Checker 🛡️

**Professional URL Security Scanner with Authentication**

A full-stack web application that allows authenticated users to scan URLs for security threats, malware, phishing attempts, and SSL vulnerabilities.

Built by **Dike Micheal** - Senior Cybersecurity & Full Stack Engineer

---

## 🚀 Features

### Authentication System
- ✅ **Secure Signup** - Email validation, password hashing with bcrypt
- ✅ **JWT Authentication** - Token-based session management
- ✅ **Protected Routes** - Middleware-based access control
- ✅ **Session Management** - Secure logout and token expiration

### URL Security Scanner
- 🔒 **HTTPS/SSL Check** - Verifies encryption status
- 📋 **Security Headers Analysis** - Checks for HSTS, CSP, XSS protection, etc.
- 🌐 **Domain Reputation** - Identifies trusted and suspicious domains
- ⚠️ **Phishing Detection** - Pattern matching for malicious URLs
- 📊 **Risk Scoring** - Overall security assessment (0-100)
- 💡 **Recommendations** - Actionable security advice

### User Experience
- 🎨 **Professional UI** - Bootstrap-based responsive design
- ⚡ **Real-time Results** - Instant security reports
- 🔐 **Privacy First** - No URL storage, complete anonymity
- 📱 **Mobile Responsive** - Works on all devices

---

## 🛠️ Tech Stack

**Frontend:**
- HTML5
- CSS3
- Bootstrap 5.3
- Vanilla JavaScript
- Font Awesome Icons

**Backend:**
- Node.js
- Express.js
- MongoDB (Mongoose)
- JWT (JSON Web Tokens)
- bcrypt.js (Password hashing)

**Security:**
- Password hashing with bcrypt
- JWT-based authentication
- HTTP-only cookies
- Input validation & sanitization
- Protected API routes

---

## 📁 Project Structure

```
Securelink/
├── server.js                 # Main Express server
├── package.json              # Dependencies
├── .env.example              # Environment variables template
├── .gitignore                # Git ignore rules
│
├── models/
│   └── User.js               # User schema with bcrypt
│
├── controllers/
│   ├── authController.js     # Signup, login, logout logic
│   └── scanController.js     # URL scanning logic
│
├── routes/
│   ├── authRoutes.js         # Authentication endpoints
│   └── scanRoutes.js         # Scan endpoints (protected)
│
├── middleware/
│   └── authMiddleware.js     # JWT verification middleware
│
├── utils/
│   ├── jwtUtils.js           # Token generation & management
│   └── validation.js         # Input validation functions
│
└── public/
    ├── index.html            # Landing page
    ├── signup.html           # Registration page
    ├── login.html            # Login page
    ├── dashboard.html        # Protected dashboard
    │
    ├── css/
    │   └── style.css         # Custom styles
    │
    └── js/
        ├── auth.js           # Authentication logic
        └── dashboard.js      # Dashboard & scanning logic
```

---

## 🔧 Installation & Setup

### Prerequisites
- Node.js (v14 or higher)
- MongoDB (local or Atlas)
- Git

### Step 1: Clone Repository
```bash
cd Desktop
cd Securelink
```

### Step 2: Install Dependencies
```bash
npm install
```

### Step 3: Configure Environment Variables
```bash
# Copy the example env file
copy .env.example .env

# Edit .env and add your configuration:
# - MONGODB_URI (your MongoDB connection string)
# - JWT_SECRET (generate a strong secret key)
# - PORT (default: 3000)
```

### Step 4: Start MongoDB
Make sure MongoDB is running:
```bash
# If using local MongoDB
mongod

# Or use MongoDB Atlas (cloud)
```

### Step 5: Run the Application
```bash
# Development mode (with auto-restart)
npm run dev

# Or production mode
npm start
```

### Step 6: Access the Application
Open your browser and navigate to:
```
http://localhost:3000
```

---

## 🔐 Authentication Flow

```
1. USER REGISTRATION (Signup)
   ├─> Validate input (name, email, password)
   ├─> Check for duplicate email
   ├─> Hash password with bcrypt
   ├─> Save user to MongoDB
   └─> Generate JWT token → Store in localStorage → Redirect to dashboard

2. USER LOGIN
   ├─> Validate credentials
   ├─> Compare password with bcrypt
   ├─> Generate JWT token
   └─> Store token → Redirect to dashboard

3. ACCESSING PROTECTED ROUTES
   ├─> Extract JWT from Authorization header or cookies
   ├─> Verify token signature
   ├─> Decode user ID from token
   ├─> Fetch user from database
   └─> Allow access OR redirect to login

4. LOGOUT
   ├─> Clear JWT token from localStorage
   └─> Redirect to login page
```

---

## 🔍 URL Scanning Process

The scanner performs **4 comprehensive security checks**:

### 1. HTTPS/SSL Certificate
- Checks if the website uses HTTPS encryption
- Score: 25 points if secure

### 2. Security Headers
- Analyzes HTTP security headers:
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options (Clickjacking protection)
  - X-Content-Type-Options (MIME sniffing protection)
  - X-XSS-Protection
  - Content-Security-Policy (CSP)
- Score: 0-25 points based on headers found

### 3. Domain Reputation
- Checks against known trusted domains
- Identifies suspicious TLDs (.tk, .ml, .ga, etc.)
- Score: 0-25 points

### 4. URL Pattern Analysis
- Detects phishing keywords (login, verify, account, etc.)
- Checks for IP addresses instead of domains
- Identifies unusual characters
- Score: 0-25 points

**Final Risk Assessment:**
- **75-100**: Safe (Low risk)
- **50-74**: Caution (Medium risk)
- **0-49**: Dangerous (High risk)

---

## 🌐 API Endpoints

### Authentication Routes (Public)
```
POST /api/auth/signup
- Register new user
- Body: { fullName, email, password, confirmPassword }

POST /api/auth/login
- Login existing user
- Body: { email, password }
```

### Protected Routes (Requires JWT)
```
GET /api/auth/me
- Get current user info
- Headers: Authorization: Bearer <token>

POST /api/auth/logout
- Logout user
- Headers: Authorization: Bearer <token>

POST /api/scan/check
- Scan URL for security threats
- Body: { url }
- Headers: Authorization: Bearer <token>
```

---

## 🔒 Security Best Practices Implemented

1. **Password Security**
   - Minimum 8 characters
   - Must contain uppercase, lowercase, and numbers
   - Hashed with bcrypt (10 salt rounds)

2. **JWT Security**
   - Signed with secret key
   - 7-day expiration
   - HTTP-only cookies (optional)
   - Secure flag in production

3. **Input Validation**
   - Email format validation
   - URL format validation
   - XSS prevention with input sanitization
   - SQL injection protection (Mongoose)

4. **Route Protection**
   - Middleware-based authentication
   - Token verification on every protected request
   - Automatic redirect for unauthenticated users

5. **Error Handling**
   - User-friendly error messages
   - No sensitive data exposure
   - Proper HTTP status codes

---

## 📊 Security Scan Report Example

```json
{
  "url": "https://example.com",
  "domain": "example.com",
  "scannedAt": "2026-01-09T12:00:00.000Z",
  "scannedBy": "John Doe",
  "checks": {
    "https": {
      "status": "Secure",
      "message": "Website uses HTTPS encryption",
      "score": 25,
      "icon": "✓"
    },
    "securityHeaders": {
      "status": "Good",
      "message": "4 of 5 security headers found",
      "score": 20,
      "icon": "✓"
    },
    "domainReputation": {
      "status": "Trusted",
      "message": "Domain is well-known and trusted",
      "score": 25,
      "icon": "✓"
    },
    "urlPattern": {
      "status": "Safe",
      "message": "No suspicious patterns detected",
      "score": 25,
      "icon": "✓"
    }
  },
  "overallRisk": "Safe",
  "riskLevel": "low",
  "riskPercentage": 95,
  "recommendations": [
    "Website appears safe, but always exercise caution",
    "Verify the URL matches the intended destination"
  ]
}
```

---

## ⚠️ Important Disclaimer

**This tool provides a security assessment based on publicly available data and does not guarantee absolute safety.**

- Always exercise caution when visiting unfamiliar websites
- SecureLink Checker analyzes publicly available information
- Should be used as one of several security measures
- We are not responsible for any damages resulting from visiting scanned websites

---

## 🚀 Future Enhancements

- [ ] Integration with VirusTotal API
- [ ] Google Safe Browsing API integration
- [ ] PhishTank database lookup
- [ ] Rate limiting for API protection
- [ ] Email verification on signup
- [ ] Password reset functionality
- [ ] Two-factor authentication (2FA)
- [ ] Scan history for logged-in users
- [ ] Bulk URL scanning
- [ ] API key generation for developers

---

## 🐛 Troubleshooting

### MongoDB Connection Error
```bash
# Make sure MongoDB is running
mongod

# Or check your MONGODB_URI in .env
```

### JWT Token Error
```bash
# Generate a new JWT_SECRET in .env
# Use a strong random string
```

### Port Already in Use
```bash
# Change PORT in .env to another port (e.g., 3001)
PORT=3001
```

### Dependencies Installation Error
```bash
# Clear npm cache and reinstall
npm cache clean --force
rm -rf node_modules package-lock.json
npm install
```

---

## 📝 License

MIT License - feel free to use this project for learning or commercial purposes.

---

## 👨‍💻 Author

**Dike Micheal**  
Senior Cybersecurity Engineer & Full Stack Developer

- Specialization: Authentication Systems, Security Analysis, Full Stack Development
- Tech Stack: Node.js, Express, MongoDB, React, Next.js, Cybersecurity Tools

---

## 🙏 Acknowledgments

- Bootstrap for UI components
- Font Awesome for icons
- MongoDB for database
- Express.js community
- JWT for authentication standards

---

**Built with ❤️ for cybersecurity and secure web applications**

© 2026 SecureLink Checker. All rights reserved.
