# AI-Powered URL Credibility Analysis - Setup Guide

## 🤖 What's New?

Your SecureLink Checker now includes **AI-powered credibility analysis** using OpenAI's GPT-4o-mini model. The AI provides:

- **Accurate credibility scoring** (0-100) for any URL
- **Intelligent risk assessment** based on contextual understanding
- **Detailed analysis** of legitimacy indicators and risk factors
- **Smart recommendations** for users
- **Detection of phishing, malware, and scam patterns**

## 🚀 How to Enable AI Analysis

### Step 1: Get Your OpenAI API Key

1. Visit [OpenAI Platform](https://platform.openai.com/api-keys)
2. Sign up or log in to your account
3. Click **"Create new secret key"**
4. Copy your API key (starts with `sk-...`)

### Step 2: Add API Key to Your Project

1. Open the `.env` file in your project root
2. Find the line: `OPENAI_API_KEY=your_openai_api_key_here`
3. Replace `your_openai_api_key_here` with your actual API key:
   ```
   OPENAI_API_KEY=sk-proj-abc123...your-actual-key
   ```
4. Save the file

### Step 3: Restart Your Server

```bash
npm start
```

## 📊 What the AI Analyzes

The AI evaluates URLs based on:

1. **Domain Credibility** - Is the domain trustworthy?
2. **URL Structure** - Does the URL contain suspicious patterns?
3. **Protocol Security** - Is the site using HTTPS?
4. **Known Threats** - Does it match known phishing/malware patterns?
5. **Context Analysis** - Overall legitimacy assessment

## 💡 How It Works

When a user scans a URL:

1. **Traditional checks** run first (HTTPS, headers, domain reputation, etc.)
2. **AI analysis** runs in parallel, providing intelligent assessment
3. **Results are combined** for a comprehensive security report
4. Users see:
   - Overall security score (0-100)
   - AI credibility score
   - Risk factors identified by AI
   - Legitimacy indicators
   - Smart recommendations

## 🎯 Benefits of AI Integration

### Before (Traditional Scanning)
- Basic pattern matching
- Simple keyword detection
- Limited context understanding
- Fixed rules only

### After (AI-Powered)
- ✅ Contextual understanding of URLs
- ✅ Detection of sophisticated phishing attempts
- ✅ Learning from latest threat patterns
- ✅ More accurate risk assessment
- ✅ Better recommendations for users

## 📈 Example Results

### Safe URL (e.g., https://github.com)
```
AI Credibility Score: 95/100
Status: Trusted
Risk Factors: None
Legitimacy Indicators:
  - Well-known legitimate domain
  - Strong security practices
  - HTTPS with valid certificate
Recommendation: Safe to proceed
```

### Suspicious URL (e.g., https://paypa1-security-verify.tk)
```
AI Credibility Score: 15/100
Status: Dangerous
Risk Factors:
  - Domain spoofing (paypa1 vs paypal)
  - Suspicious TLD (.tk)
  - Phishing keywords detected
Recommendation: ⚠ Do not proceed - high phishing risk
```

## 💰 Cost Information

- Using **GPT-4o-mini** (cost-effective model)
- Typical cost: ~$0.001-0.002 per URL scan
- 1000 scans ≈ $1-2
- You can monitor usage at [OpenAI Usage Dashboard](https://platform.openai.com/usage)

## ⚠️ Without API Key

If no API key is configured, the system will:
- Still work with traditional security checks
- Display: "AI analysis is not configured"
- All other features remain functional

## 🔧 Troubleshooting

### Issue: "AI analysis failed"
**Solution:** Check your API key in `.env` file and ensure you have credits

### Issue: "Rate limit exceeded"
**Solution:** You've hit OpenAI's rate limit. Wait a few minutes or upgrade your plan

### Issue: API key not working
**Solution:** 
1. Verify the key is correct (no extra spaces)
2. Check if the key is active on OpenAI platform
3. Ensure you have available credits

## 🎉 Testing Your Integration

1. Start your server: `npm start`
2. Visit: http://localhost:3000/dashboard
3. Scan a URL (e.g., https://google.com)
4. Look for the **"AI Credibility Analysis"** section with the blue "AI-Powered" badge
5. You should see detailed AI analysis with risk factors and recommendations

## 📝 Technical Details

- **Model:** GPT-4o-mini (fast and cost-effective)
- **Temperature:** 0.3 (consistent, reliable results)
- **Response Format:** JSON
- **Max Tokens:** 1000
- **Integration:** Seamless with existing security checks
- **Scoring:** Normalizes AI score (0-100) to system score (0-20)

---

**Need Help?** Check the OpenAI documentation or reach out to support.

**Built with ❤️ by Dike Micheal**
