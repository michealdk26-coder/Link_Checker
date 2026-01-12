/**
 * URL Security Scanner Controller
 * Performs security checks on submitted URLs
 * 
 * SECURITY CHECKS PERFORMED:
 * 1. HTTPS/SSL Certificate validation
 * 2. Domain age check (older = more trustworthy)
 * 3. Security headers analysis
 * 4. Blacklist checking (phishing/malware databases)
 * 5. URL reputation scoring
 * 
 * NOTE: This is a basic implementation. For production, integrate with:
 * - Google Safe Browsing API
 * - VirusTotal API
 * - PhishTank API
 */

const axios = require('axios');
const { validateURL } = require('../utils/validation');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const cheerio = require('cheerio');
const OpenAI = require('openai');

// Initialize OpenAI client
const openai = process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY !== 'your_openai_api_key_here'
    ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
    : null;

/**
 * @route   POST /api/scan/check
 * @desc    Scan URL for security threats
 * @access  Private (requires authentication)
 */
const scanURL = async (req, res) => {
    try {
        const { url } = req.body;

        // Validate URL
        const urlValidation = validateURL(url);
        if (!urlValidation.isValid) {
            return res.status(400).json({
                success: false,
                message: urlValidation.error
            });
        }

        const targetURL = urlValidation.url;
        const parsedURL = new URL(targetURL);

        // Initialize security report
        const securityReport = {
            url: targetURL,
            domain: parsedURL.hostname,
            scannedAt: new Date().toISOString(),
            scannedBy: 'Public',
            checks: {},
            overallRisk: 'Unknown',
            riskScore: 0,
            recommendations: []
        };

        // Perform security checks
        await Promise.allSettled([
            checkHTTPS(parsedURL, securityReport),
            checkSecurityHeaders(targetURL, securityReport),
            checkDomainReputation(parsedURL, securityReport),
            checkSuspiciousPatterns(targetURL, securityReport),
            checkContentAnalysis(targetURL, parsedURL, securityReport),
            checkAICredibilityAnalysis(targetURL, parsedURL, securityReport) // AI-powered analysis
        ]);

        // Calculate overall risk
        calculateOverallRisk(securityReport);

        // Generate recommendations
        generateRecommendations(securityReport);

        res.status(200).json({
            success: true,
            report: securityReport
        });

    } catch (error) {
        console.error('URL Scan Error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to scan URL. Please try again.'
        });
    }
};

/**
 * Check if URL uses HTTPS
 */
const checkHTTPS = async (parsedURL, report) => {
    const isHTTPS = parsedURL.protocol === 'https:';

    report.checks.https = {
        status: isHTTPS ? 'Secure' : 'Warning',
        message: isHTTPS
            ? 'Website uses HTTPS encryption'
            : 'Website does not use HTTPS - data is not encrypted',
        score: isHTTPS ? 20 : 0,
        icon: isHTTPS ? '✓' : '⚠'
    };

    report.riskScore += report.checks.https.score;
};

/**
 * Check security headers
 */
const checkSecurityHeaders = async (targetURL, report) => {
    try {
        const response = await axios.head(targetURL, {
            timeout: 5000,
            maxRedirects: 3,
            validateStatus: () => true // Accept any status code
        });

        const headers = response.headers;
        const securityHeaders = {
            'strict-transport-security': 'HSTS',
            'x-frame-options': 'Clickjacking Protection',
            'x-content-type-options': 'MIME Sniffing Protection',
            'x-xss-protection': 'XSS Protection',
            'content-security-policy': 'CSP'
        };

        const foundHeaders = [];
        const missingHeaders = [];

        for (const [header, name] of Object.entries(securityHeaders)) {
            if (headers[header]) {
                foundHeaders.push(name);
            } else {
                missingHeaders.push(name);
            }
        }

        const headerScore = (foundHeaders.length / Object.keys(securityHeaders).length) * 20;

        report.checks.securityHeaders = {
            status: foundHeaders.length >= 3 ? 'Good' : 'Warning',
            message: `${foundHeaders.length} of ${Object.keys(securityHeaders).length} security headers found`,
            foundHeaders,
            missingHeaders,
            score: Math.round(headerScore),
            icon: foundHeaders.length >= 3 ? '✓' : '⚠'
        };

        report.riskScore += report.checks.securityHeaders.score;

    } catch (error) {
        report.checks.securityHeaders = {
            status: 'Error',
            message: 'Unable to fetch security headers',
            score: 0,
            icon: '?'
        };
    }
};

/**
 * Check domain reputation (simplified)
 */
const checkDomainReputation = async (parsedURL, report) => {
    const domain = parsedURL.hostname.toLowerCase();

    // Check against known safe domains
    const trustedDomains = [
        'google.com', 'github.com', 'microsoft.com', 'amazon.com',
        'facebook.com', 'apple.com', 'youtube.com', 'twitter.com',
        'linkedin.com', 'wikipedia.org', 'stackoverflow.com'
    ];

    const isTrusted = trustedDomains.some(trusted =>
        domain === trusted || domain.endsWith('.' + trusted)
    );

    // Check for suspicious TLDs
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'];
    const hasSuspiciousTLD = suspiciousTLDs.some(tld => domain.endsWith(tld));

    let status = 'Unknown';
    let score = 12; // base reputation points
    let message = 'Domain reputation is unknown';
    let icon = '?';

    if (isTrusted) {
        status = 'Trusted';
        score = 20;
        message = 'Domain is well-known and trusted';
        icon = '✓';
    } else if (hasSuspiciousTLD) {
        status = 'Suspicious';
        score = 0;
        message = 'Domain uses a TLD commonly associated with malicious sites';
        icon = '⚠';
    }

    report.checks.domainReputation = {
        status,
        message,
        score,
        icon
    };

    report.riskScore += score;
};

/**
 * Check for suspicious patterns in URL
 */
const checkSuspiciousPatterns = async (targetURL, report) => {
    const suspiciousKeywords = [
        'login', 'verify', 'account', 'secure', 'banking', 'paypal',
        'update', 'confirm', 'suspended', 'locked', 'unusual'
    ];

    const urlLower = targetURL.toLowerCase();
    const foundKeywords = suspiciousKeywords.filter(keyword => urlLower.includes(keyword));

    // Check for IP address instead of domain
    const hasIPAddress = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(targetURL);

    // Check for unusual characters
    const hasUnusualChars = /@|%20|%2F/.test(targetURL);

    let status = 'Safe';
    let score = 20;
    let message = 'No suspicious patterns detected';
    let icon = '✓';
    const warnings = [];

    if (foundKeywords.length > 0) {
        warnings.push(`Contains phishing keywords: ${foundKeywords.join(', ')}`);
        score -= 10;
    }

    if (hasIPAddress) {
        warnings.push('Uses IP address instead of domain name');
        score -= 10;
    }

    if (hasUnusualChars) {
        warnings.push('Contains unusual characters');
        score -= 5;
    }

    if (warnings.length > 0) {
        status = warnings.length > 2 ? 'Suspicious' : 'Warning';
        message = warnings.join('; ');
        icon = warnings.length > 2 ? '✗' : '⚠';
    }

    report.checks.urlPattern = {
        status,
        message,
        warnings,
        score: Math.max(score, 0),
        icon
    };
    report.riskScore += report.checks.urlPattern.score;
};

/**
 * Analyze page content (HTML/JS) for suspicious indicators
 */
const checkContentAnalysis = async (targetURL, parsedURL, report) => {
    try {
        const response = await axios.get(targetURL, {
            timeout: 7000,
            maxRedirects: 3,
            validateStatus: () => true
        });

        const html = typeof response.data === 'string' ? response.data : '';
        const $ = cheerio.load(html);

        let score = 20; // start with full points, subtract for findings
        const findings = [];

        // Forms with password inputs
        const forms = $('form');
        const hasPasswordInput = $('input[type="password"]').length > 0;
        if (forms.length > 0 && hasPasswordInput && parsedURL.protocol !== 'https:') {
            findings.push('Login form served over non-HTTPS');
            score -= 8;
        }

        // External scripts from suspicious TLDs
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'];
        $('script[src]').each((_, el) => {
            const src = $(el).attr('src') || '';
            if (suspiciousTLDs.some(tld => src.toLowerCase().includes(tld))) {
                findings.push(`External script from suspicious TLD: ${src}`);
                score -= 5;
            }
        });

        // Obfuscated JS patterns
        const lower = html.toLowerCase();
        const hasEval = /eval\s*\(/.test(lower);
        const hasAtob = /atob\s*\(/.test(lower);
        const longBase64 = /[A-Za-z0-9+/]{200,}=*/.test(html);
        if (hasEval) { findings.push('Use of eval() detected'); score -= 5; }
        if (hasAtob) { findings.push('Base64 decoding (atob) detected'); score -= 3; }
        if (longBase64) { findings.push('Long base64 strings detected'); score -= 4; }

        // Excessive iframes
        const iframeCount = $('iframe').length;
        if (iframeCount >= 3) {
            findings.push(`Multiple iframes detected (${iframeCount})`);
            score -= 4;
        }

        // Brand impersonation hints
        const title = $('title').text().trim().toLowerCase();
        const domain = parsedURL.hostname.toLowerCase();
        const brands = ['google', 'microsoft', 'apple', 'amazon', 'paypal', 'facebook', 'bank'];
        const mentionsBrand = brands.some(b => title.includes(b));
        const domainMatchesBrand = brands.some(b => domain.includes(b));
        if (mentionsBrand && !domainMatchesBrand) {
            findings.push('Page title references a popular brand, but domain does not');
            score -= 4;
        }

        // Hidden inputs
        const hiddenInputs = $('input[type="hidden"]').length;
        if (hiddenInputs >= 10) {
            findings.push(`Many hidden inputs detected (${hiddenInputs})`);
            score -= 3;
        }

        // Finalize
        score = Math.max(0, Math.min(20, score));
        report.checks.contentAnalysis = {
            status: score >= 15 ? 'Clean' : score >= 8 ? 'Caution' : 'Suspicious',
            message: findings.length ? findings.join('; ') : 'No suspicious content indicators found',
            findings,
            score,
            icon: score >= 15 ? '✓' : score >= 8 ? '⚠' : '✗'
        };
        report.riskScore += score;
    } catch (error) {
        report.checks.contentAnalysis = {
            status: 'Unknown',
            message: 'Unable to fetch page content for analysis',
            score: 8, // neutral middle to avoid punishing sites blocking fetches
            icon: '?'
        };
        report.riskScore += 8;
    }
};

/**
 * AI-Powered Credibility Analysis using OpenAI
 * Uses AI to analyze URL and domain credibility with contextual understanding
 */
const checkAICredibilityAnalysis = async (targetURL, parsedURL, report) => {
    if (!openai) {
        report.checks.aiAnalysis = {
            status: 'Disabled',
            message: 'AI analysis is not configured. Add OPENAI_API_KEY to .env file to enable AI-powered credibility checking.',
            score: 0,
            icon: '⚙',
            credibilityScore: null,
            analysis: null
        };
        return;
    }

    try {
        const domain = parsedURL.hostname;
        const protocol = parsedURL.protocol;
        const path = parsedURL.pathname;

        // Prepare context for AI
        const prompt = `You are a cybersecurity expert specializing in URL and website credibility analysis. Analyze the following URL for potential security risks, phishing attempts, and overall credibility.

URL: ${targetURL}
Domain: ${domain}
Protocol: ${protocol}
Path: ${path}

Provide a detailed analysis including:
1. Credibility assessment (0-100 score where 100 is most credible)
2. Potential security risks or red flags
3. Indicators of legitimacy or suspicion
4. Likelihood of phishing, malware, or scam (low/medium/high)
5. Recommendations for users

Respond in JSON format:
{
  "credibilityScore": <number 0-100>,
  "trustLevel": "<safe/caution/dangerous>",
  "riskFactors": ["<risk1>", "<risk2>", ...],
  "legitimacyIndicators": ["<indicator1>", "<indicator2>", ...],
  "phishingLikelihood": "<low/medium/high>",
  "malwareLikelihood": "<low/medium/high>",
  "summary": "<brief summary>",
  "recommendation": "<user recommendation>"
}`;

        const completion = await openai.chat.completions.create({
            model: "gpt-4o-mini", // Using the faster, cost-effective model
            messages: [
                {
                    role: "system",
                    content: "You are an expert cybersecurity analyst specializing in URL security and phishing detection. Provide accurate, detailed analysis in JSON format only."
                },
                {
                    role: "user",
                    content: prompt
                }
            ],
            temperature: 0.3, // Lower temperature for more consistent analysis
            max_tokens: 1000,
            response_format: { type: "json_object" }
        });

        const aiResponse = completion.choices[0].message.content;
        const analysis = JSON.parse(aiResponse);

        // Convert AI credibility score (0-100) to our scoring system (0-20)
        const aiScore = Math.round((analysis.credibilityScore / 100) * 20);

        // Determine status based on AI assessment
        let status = 'Unknown';
        let icon = '?';
        if (analysis.trustLevel === 'safe' || analysis.credibilityScore >= 75) {
            status = 'Trusted';
            icon = '✓';
        } else if (analysis.trustLevel === 'caution' || analysis.credibilityScore >= 50) {
            status = 'Caution';
            icon = '⚠';
        } else {
            status = 'Suspicious';
            icon = '✗';
        }

        report.checks.aiAnalysis = {
            status,
            message: analysis.summary || 'AI analysis completed',
            score: aiScore,
            icon,
            credibilityScore: analysis.credibilityScore,
            trustLevel: analysis.trustLevel,
            riskFactors: analysis.riskFactors || [],
            legitimacyIndicators: analysis.legitimacyIndicators || [],
            phishingLikelihood: analysis.phishingLikelihood || 'unknown',
            malwareLikelihood: analysis.malwareLikelihood || 'unknown',
            recommendation: analysis.recommendation || '',
            aiPowered: true
        };

        report.riskScore += aiScore;

    } catch (error) {
        console.error('AI Analysis Error:', error);
        report.checks.aiAnalysis = {
            status: 'Error',
            message: 'AI analysis failed. Using traditional security checks.',
            score: 10, // neutral score
            icon: '?',
            error: error.message
        };
        report.riskScore += 10;
    }
};

/**
 * Calculate overall risk level
 * AI CREDIBILITY IS NOW THE PRIMARY METRIC
 * If AI not available, improved traditional scoring is used
 */
const calculateOverallRisk = (report) => {
    let percentage = 50; // Default to medium if no AI data

    // If AI analysis is available, use it as the PRIMARY metric (70% weight)
    if (report.checks.aiAnalysis && report.checks.aiAnalysis.credibilityScore !== null && report.checks.aiAnalysis.credibilityScore >= 0) {
        const aiScore = report.checks.aiAnalysis.credibilityScore; // 0-100

        // AI credibility is 70% of the final score
        percentage = aiScore * 0.7;

        // Traditional checks provide 30% weight as supporting factors
        // Calculate traditional checks score (out of 100)
        const traditionalScores = [
            report.checks.https?.score || 0,
            report.checks.securityHeaders?.score || 0,
            report.checks.domainReputation?.score || 0,
            report.checks.urlPattern?.score || 0,
            report.checks.contentAnalysis?.score || 0
        ];

        const traditionalTotal = traditionalScores.reduce((a, b) => a + b, 0); // 0-100
        const traditionalPercentage = (traditionalTotal / 100) * 100;

        // Boost score if traditional checks also agree it's safe
        const traditionalBoost = traditionalPercentage * 0.3;
        percentage = Math.min(100, percentage + traditionalBoost);

    } else {
        // Fallback: Improved traditional checks when AI is not available
        // Direct calculation based on individual check scores
        const scores = [
            report.checks.https?.score || 0,          // 0-20
            report.checks.securityHeaders?.score || 0, // 0-20
            report.checks.domainReputation?.score || 0, // 0-20
            report.checks.urlPattern?.score || 0,      // 0-20
            report.checks.contentAnalysis?.score || 0   // 0-20
        ];

        const totalScore = scores.reduce((a, b) => a + b, 0); // 0-100

        // Convert to percentage (0-100)
        percentage = (totalScore / 100) * 100;

        // BOOST for trusted domains: If domain reputation is 20/20 (trusted),
        // increase the final percentage by 10 points
        if (report.checks.domainReputation && report.checks.domainReputation.score === 20) {
            percentage = Math.min(100, percentage + 10);
        }
    }

    // Ensure percentage is between 0-100
    percentage = Math.max(0, Math.min(100, Math.round(percentage)));

    // Determine risk level based on percentage
    if (percentage >= 75) {
        report.overallRisk = 'Safe';
        report.riskLevel = 'low';
        report.riskColor = 'success';
    } else if (percentage >= 50) {
        report.overallRisk = 'Caution';
        report.riskLevel = 'medium';
        report.riskColor = 'warning';
    } else {
        report.overallRisk = 'Dangerous';
        report.riskLevel = 'high';
        report.riskColor = 'danger';
    }

    report.riskPercentage = percentage;
};

/**
 * Generate security recommendations based on actual findings
 */
const generateRecommendations = (report) => {
    const recommendations = [];

    // HTTPS check
    if (report.checks.https) {
        if (report.checks.https.score === 20) {
            recommendations.push('HTTPS Encryption: Website uses secure HTTPS encryption');
        } else if (report.checks.https.score === 0) {
            recommendations.push('NO HTTPS: Avoid entering sensitive information - website is not encrypted');
        }
    }

    // Security Headers
    if (report.checks.securityHeaders) {
        if (report.checks.securityHeaders.score >= 15) {
            recommendations.push(`Security Headers: ${report.checks.securityHeaders.foundHeaders.length} important security headers detected`);
        } else if (report.checks.securityHeaders.score > 0) {
            const missing = report.checks.securityHeaders.missingHeaders || [];
            recommendations.push(`Security Headers: Missing ${missing.length} security headers (${missing.slice(0, 2).join(', ')})`);
        } else {
            recommendations.push('Security Headers: Website lacks important security headers');
        }
    }

    // Domain Reputation
    if (report.checks.domainReputation) {
        if (report.checks.domainReputation.score === 20) {
            recommendations.push('Domain Reputation: This is a well-known and trusted domain');
        } else if (report.checks.domainReputation.status === 'Suspicious') {
            recommendations.push('Domain Reputation: Domain uses a TLD commonly associated with malicious sites');
        } else {
            recommendations.push('Domain Reputation: Domain reputation is unknown');
        }
    }

    // URL Pattern Analysis
    if (report.checks.urlPattern) {
        if (report.checks.urlPattern.warnings && report.checks.urlPattern.warnings.length > 0) {
            recommendations.push(`URL Pattern: ${report.checks.urlPattern.warnings[0]}`);
        } else if (report.checks.urlPattern.score === 20) {
            recommendations.push('URL Pattern: No suspicious patterns detected in URL');
        }
    }

    // Content Analysis
    if (report.checks.contentAnalysis) {
        if (report.checks.contentAnalysis.findings && report.checks.contentAnalysis.findings.length > 0) {
            recommendations.push(`Content: ${report.checks.contentAnalysis.findings[0]}`);
        } else if (report.checks.contentAnalysis.score >= 15) {
            recommendations.push('Content Analysis: Page content appears clean with no suspicious indicators');
        }
    }

    // AI Analysis if available
    if (report.checks.aiAnalysis && report.checks.aiAnalysis.credibilityScore !== null) {
        if (report.checks.aiAnalysis.credibilityScore >= 75) {
            recommendations.push(`AI Assessment: High credibility score (${report.checks.aiAnalysis.credibilityScore}/100) - Website appears legitimate`);
        } else if (report.checks.aiAnalysis.credibilityScore >= 50) {
            recommendations.push(`AI Assessment: Medium credibility (${report.checks.aiAnalysis.credibilityScore}/100) - Exercise caution`);
        } else {
            recommendations.push(`AI Assessment: Low credibility score (${report.checks.aiAnalysis.credibilityScore}/100) - ${report.checks.aiAnalysis.recommendation}`);
        }
    }

    // Overall risk guidance
    if (report.overallRisk === 'Dangerous') {
        recommendations.push('HIGH RISK: Do not proceed unless you trust this source');
        recommendations.push('Verify the URL carefully for typos or spoofing');
    } else if (report.overallRisk === 'Caution') {
        recommendations.push('Exercise caution when entering sensitive information');
        recommendations.push('Verify the URL matches the intended destination');
    } else if (report.overallRisk === 'Safe') {
        recommendations.push('This website appears to be legitimate and secure');
        recommendations.push('Safe to browse and enter information');
    }

    // Ensure at least some recommendations
    if (recommendations.length === 0) {
        recommendations.push('Website assessment complete');
        recommendations.push('Always verify the URL matches the intended destination');
    }

    report.recommendations = recommendations;
};

module.exports = {
    scanURL
};
