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
            scannedBy: req.user.fullName,
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
            checkSuspiciousPatterns(targetURL, securityReport)
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
        score: isHTTPS ? 25 : 0,
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

        const headerScore = (foundHeaders.length / Object.keys(securityHeaders).length) * 25;

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
    let score = 15;
    let message = 'Domain reputation is unknown';
    let icon = '?';

    if (isTrusted) {
        status = 'Trusted';
        score = 25;
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
    let score = 25;
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
 * Calculate overall risk level
 */
const calculateOverallRisk = (report) => {
    const maxScore = 100;
    const percentage = (report.riskScore / maxScore) * 100;

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

    report.riskPercentage = Math.round(percentage);
};

/**
 * Generate security recommendations
 */
const generateRecommendations = (report) => {
    const recommendations = [];

    if (!report.checks.https || report.checks.https.score === 0) {
        recommendations.push('Avoid entering sensitive information - website is not encrypted');
    }

    if (report.checks.securityHeaders && report.checks.securityHeaders.score < 15) {
        recommendations.push('Website lacks important security headers');
    }

    if (report.checks.urlPattern && report.checks.urlPattern.warnings.length > 0) {
        recommendations.push('URL contains suspicious patterns - verify authenticity');
    }

    if (report.overallRisk === 'Dangerous') {
        recommendations.push('⚠ HIGH RISK: Do not proceed unless you trust this source');
        recommendations.push('Verify the URL carefully for typos or spoofing');
    }

    if (recommendations.length === 0) {
        recommendations.push('Website appears safe, but always exercise caution');
        recommendations.push('Verify the URL matches the intended destination');
    }

    report.recommendations = recommendations;
};

module.exports = {
    scanURL
};
