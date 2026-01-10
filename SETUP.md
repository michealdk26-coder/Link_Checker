# SecureLink Checker - Setup Guide

## Quick Start (5 minutes)

### 1. Install Node.js Dependencies
```powershell
npm install
```

### 2. Create Environment File
```powershell
# Copy the example file
copy .env.example .env

# Edit .env with your settings:
# - Generate a strong JWT_SECRET (random string)
# - Set your MongoDB connection string
```

**Example .env configuration:**
```env
MONGODB_URI=mongodb://localhost:27017/securelink
JWT_SECRET=your_super_secret_random_key_here_12345
JWT_EXPIRE=7d
PORT=3000
NODE_ENV=development
```

### 3. Start MongoDB
**Option A: Local MongoDB**
```powershell
# Start MongoDB service
mongod
```

**Option B: MongoDB Atlas (Cloud)**
1. Create free account at https://www.mongodb.com/cloud/atlas
2. Create a cluster
3. Get connection string
4. Update MONGODB_URI in .env

### 4. Run the Application
```powershell
# Development mode (auto-restart)
npm run dev

# OR Production mode
npm start
```

### 5. Access the Application
Open browser: http://localhost:3000

---

## Testing the Application

### Test Flow:
1. **Visit Homepage** → http://localhost:3000
2. **Sign Up** → Create a new account
3. **Login** → Use your credentials
4. **Dashboard** → Scan URLs for security

### Test URLs:
- Safe: https://google.com
- Safe: https://github.com
- Test: https://example.com

---

## Project Structure Overview

```
Securelink/
├── server.js              # Main entry point
├── package.json           # Dependencies
├── .env                   # Configuration (create from .env.example)
│
├── models/                # Database schemas
├── controllers/           # Business logic
├── routes/                # API endpoints
├── middleware/            # Authentication guards
├── utils/                 # Helper functions
│
└── public/                # Frontend files
    ├── index.html         # Landing page
    ├── signup.html        # Registration
    ├── login.html         # Login
    ├── dashboard.html     # Protected dashboard
    ├── css/style.css      # Styles
    └── js/                # Client-side scripts
```

---

## Common Issues & Solutions

### Issue: MongoDB Connection Failed
**Solution:**
- Ensure MongoDB is running: `mongod`
- Check MONGODB_URI in .env
- For Atlas: Whitelist your IP address

### Issue: JWT Token Error
**Solution:**
- Set JWT_SECRET in .env to a random string
- Example: `JWT_SECRET=mySecretKey123456789`

### Issue: Port Already in Use
**Solution:**
- Change PORT in .env: `PORT=3001`
- Or kill process using port 3000

### Issue: Dependencies Installation Failed
**Solution:**
```powershell
npm cache clean --force
Remove-Item -Recurse -Force node_modules
Remove-Item package-lock.json
npm install
```

---

## Development Tips

### Auto-restart on Changes
```powershell
npm run dev
```

### Check MongoDB Connection
```javascript
// In MongoDB Compass or Shell
use securelink
db.users.find()
```

### Generate Strong JWT Secret
```powershell
# PowerShell command to generate random string
-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | % {[char]$_})
```

---

## Deployment Checklist

Before deploying to production:

- [ ] Change JWT_SECRET to a strong random key
- [ ] Set NODE_ENV=production
- [ ] Use MongoDB Atlas or production database
- [ ] Enable HTTPS
- [ ] Set secure cookie flags
- [ ] Add rate limiting
- [ ] Configure CORS properly
- [ ] Set up error logging
- [ ] Add monitoring

---

## Environment Variables Explained

```env
# Database
MONGODB_URI=mongodb://localhost:27017/securelink
# Your MongoDB connection string

# JWT Authentication
JWT_SECRET=your_random_secret_key
# Strong random string for signing tokens

JWT_EXPIRE=7d
# Token expiration (7d = 7 days, 24h = 24 hours)

# Server
PORT=3000
# Application port

NODE_ENV=development
# Environment (development/production)

# CORS
CLIENT_URL=http://localhost:3000
# Frontend URL for CORS
```

---

## Security Checklist

✅ Passwords hashed with bcrypt  
✅ JWT tokens for authentication  
✅ Protected routes with middleware  
✅ Input validation on all forms  
✅ XSS prevention with sanitization  
✅ MongoDB injection protection  
✅ HTTP-only cookies support  
✅ Secure password requirements  
✅ No sensitive data in responses  

---

## Need Help?

### Documentation
- See README.md for full documentation
- Check comments in source code

### MongoDB Resources
- Official Docs: https://docs.mongodb.com
- MongoDB Atlas: https://www.mongodb.com/cloud/atlas

### Node.js Resources
- Express.js: https://expressjs.com
- Mongoose: https://mongoosejs.com

---

**Built by Dike Micheal - Senior Cybersecurity & Full Stack Engineer**

Good luck with your SecureLink Checker application! 🛡️
