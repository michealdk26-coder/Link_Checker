# 🚀 QUICK FIX - Setup MongoDB in 2 Minutes

## MongoDB Atlas (Cloud - FREE & FASTEST)

### Step 1: Create Account (30 seconds)
1. Open: https://www.mongodb.com/cloud/atlas/register
2. Sign up with Google or Email (fastest with Google)

### Step 2: Create FREE Cluster (1 minute - automatic)
1. Choose: **M0 FREE** tier
2. Provider: **AWS**
3. Region: Choose closest to you
4. Cluster Name: `Cluster0` (default)
5. Click **"Create Deployment"**
6. **IMPORTANT**: Save the username and password shown!
   - Username: (save this)
   - Password: (save this)

### Step 3: Get Connection String (30 seconds)
1. Click **"Connect"** button
2. Choose **"Drivers"**
3. Copy the connection string (looks like):
   ```
   mongodb+srv://<username>:<password>@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority
   ```

### Step 4: Update .env File
Open: `C:\Users\HomePC\Desktop\Securelink\.env`

Replace this line:
```
MONGODB_URI=mongodb://localhost:27017/securelink
```

With your connection string (replace <username> and <password>):
```
MONGODB_URI=mongodb+srv://YOUR_USERNAME:YOUR_PASSWORD@cluster0.xxxxx.mongodb.net/securelink?retryWrites=true&w=majority
```

### Step 5: Restart Server
In PowerShell:
```powershell
# Stop current server (Ctrl+C)
# Then restart:
cd C:\Users\HomePC\Desktop\Securelink
node server.js
```

You should see: ✅ MongoDB Connected Successfully

---

## Test Signup
1. Go to: http://localhost:3000/signup
2. Fill form and click "Create Account"
3. Should work immediately! ✅

---

## Still Having Issues?

**If you see "IP not whitelisted":**
1. Go to MongoDB Atlas
2. Click "Network Access" (left menu)
3. Click "Add IP Address"
4. Click "Allow Access from Anywhere"
5. Click "Confirm"

Then restart your server!

---

**This is the FASTEST solution - takes only 2 minutes total!**
