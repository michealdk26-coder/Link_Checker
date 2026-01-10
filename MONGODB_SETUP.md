# MongoDB Setup Guide

## ⚠️ Current Issue
**MongoDB is not running on your system.**

You have **2 options**:

---

## Option 1: Install & Run MongoDB Locally (Recommended for Development)

### Step 1: Download MongoDB
1. Go to: https://www.mongodb.com/try/download/community
2. Download MongoDB Community Server for Windows
3. Install with default settings

### Step 2: Start MongoDB
Open PowerShell as Administrator and run:
```powershell
# Start MongoDB service
net start MongoDB

# OR if that doesn't work, run MongoDB manually:
"C:\Program Files\MongoDB\Server\7.0\bin\mongod.exe" --dbpath="C:\data\db"
```

### Step 3: Verify MongoDB is Running
```powershell
# Check if MongoDB is listening on port 27017
Test-NetConnection -ComputerName localhost -Port 27017
```

### Step 4: Restart Your Application
```powershell
cd C:\Users\HomePC\Desktop\Securelink
npm start
```

---

## Option 2: Use MongoDB Atlas (Cloud - Free & Easy)

### Step 1: Create Free Account
1. Go to: https://www.mongodb.com/cloud/atlas/register
2. Sign up for free account
3. Create a FREE cluster (M0 tier)

### Step 2: Setup Cluster
1. Choose a cloud provider (AWS recommended)
2. Select a region close to you
3. Name your cluster (e.g., "SecureLinkCluster")
4. Click "Create Cluster" (takes 3-5 minutes)

### Step 3: Create Database User
1. Go to "Database Access" in left menu
2. Click "Add New Database User"
3. Username: `securelinkuser`
4. Password: Create a strong password (save it!)
5. User Privileges: "Read and write to any database"
6. Click "Add User"

### Step 4: Whitelist Your IP
1. Go to "Network Access" in left menu
2. Click "Add IP Address"
3. Click "Allow Access from Anywhere" (for development)
4. Click "Confirm"

### Step 5: Get Connection String
1. Go back to "Database" (clusters view)
2. Click "Connect" on your cluster
3. Choose "Connect your application"
4. Copy the connection string (looks like):
   ```
   mongodb+srv://securelinkuser:<password>@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority
   ```

### Step 6: Update Your .env File
Open `C:\Users\HomePC\Desktop\Securelink\.env` and replace:
```env
MONGODB_URI=mongodb://localhost:27017/securelink
```

With your Atlas connection string (replace `<password>` with your actual password):
```env
MONGODB_URI=mongodb+srv://securelinkuser:YOUR_PASSWORD_HERE@cluster0.xxxxx.mongodb.net/securelink?retryWrites=true&w=majority
```

### Step 7: Restart Application
```powershell
cd C:\Users\HomePC\Desktop\Securelink
npm start
```

You should see: ✅ MongoDB Connected Successfully

---

## Quick Test

After setting up either option, test signup:
1. Go to: http://localhost:3000/signup
2. Fill in the form:
   - Name: Test User
   - Email: test@example.com
   - Password: Test1234
   - Confirm Password: Test1234
3. Click "Create Account"
4. If successful, you'll be redirected to dashboard!

---

## Troubleshooting

### Error: "ECONNREFUSED"
- **Solution:** MongoDB is not running. Use Option 1 or 2 above.

### Error: "Authentication failed"
- **Solution:** Check your MongoDB Atlas username and password in .env

### Error: "IP not whitelisted"
- **Solution:** Add your IP address in MongoDB Atlas Network Access

---

## Recommended: Use MongoDB Atlas
- ✅ No installation needed
- ✅ Always available (cloud-hosted)
- ✅ Free tier (512MB storage)
- ✅ Automatic backups
- ✅ Easy to use
- ✅ Works from anywhere

---

**Need help? Check the error messages in your terminal for specific issues.**
