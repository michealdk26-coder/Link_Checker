/**
 * Dashboard JavaScript
 * Handles URL scanning, authentication checks, and results display
 */

// API Base URL
const API_URL = window.location.origin;

// Check authentication on page load
document.addEventListener('DOMContentLoaded', () => {
    checkAuthentication();

    // Handle scan form submission
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', handleScan);
    }

    // Handle logout
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }
});

/**
 * Check if user is authenticated
 * Redirect to login if not authenticated
 */
async function checkAuthentication() {
    try {
        const response = await fetch(`${API_URL}/api/auth/me`, {
            method: 'GET'
        });

        if (response.ok) {
            const data = await response.json();
            if (data.success && data.user) {
                // Update user name in navbar
                document.getElementById('userName').textContent = data.user.fullName;
            }
        } else {
            // Not authenticated
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Authentication check error:', error);
        window.location.href = '/login';
    }
}

/**
 * Handle URL scan
 */
async function handleScan(e) {
    e.preventDefault();

    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();

    if (!url) {
        showAlert('Please enter a URL to scan', 'warning');
        return;
    }

    // Get token
    // Show loading state
    showLoading();
    hideResults();

    const scanBtn = document.getElementById('scanBtn');
    scanBtn.disabled = true;

    try {
        const response = await fetch(`${API_URL}/api/scan/check`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            // Display results
            displayResults(data.report);
        } else {
            hideLoading();
            showAlert(data.message || 'Failed to scan URL. Please try again.', 'danger');
        }

        scanBtn.disabled = false;

    } catch (error) {
        console.error('Scan error:', error);
        hideLoading();
        showAlert('Network error. Please check your connection and try again.', 'danger');
        scanBtn.disabled = false;
    }
}

/**
 * Display scan results
 */
function displayResults(report) {
    hideLoading();

    const resultsSection = document.getElementById('resultsSection');
    resultsSection.style.display = 'block';

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Update overall risk badge
    updateOverallRisk(report);

    // Update individual checks
    updateCheck('httpsCheck', report.checks.https);
    updateCheck('securityHeadersCheck', report.checks.securityHeaders);
    updateCheck('domainReputationCheck', report.checks.domainReputation);
    updateCheck('urlPatternCheck', report.checks.urlPattern);

    // Update AI analysis (if available)
    if (report.checks.aiAnalysis) {
        updateAIAnalysis('aiAnalysisCheck', report.checks.aiAnalysis);
    }

    // Update recommendations
    updateRecommendations(report.recommendations);

    // Update scanned URL
    document.getElementById('scannedUrl').textContent = `Scanned: ${report.url}`;
}

/**
 * Update overall risk badge
 */
function updateOverallRisk(report) {
    const riskIcon = document.getElementById('riskIcon');
    const riskText = document.getElementById('riskText');
    const riskScore = document.getElementById('riskScore');
    const riskBadge = document.getElementById('overallRiskBadge');

    // Remove previous classes
    riskBadge.classList.remove('risk-safe', 'risk-warning', 'risk-danger');

    // Set risk level
    riskText.textContent = report.overallRisk;
    riskScore.textContent = `Security Score: ${report.riskPercentage}/100`;

    // Set icon and color
    if (report.riskLevel === 'low') {
        riskBadge.classList.add('risk-safe');
        riskIcon.innerHTML = '<i class="fas fa-shield-alt"></i>';
    } else if (report.riskLevel === 'medium') {
        riskBadge.classList.add('risk-warning');
        riskIcon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>';
    } else {
        riskBadge.classList.add('risk-danger');
        riskIcon.innerHTML = '<i class="fas fa-times-circle"></i>';
    }
}

/**
 * Update individual security check card
 */
function updateCheck(checkId, checkData) {
    const checkCard = document.getElementById(checkId);
    if (!checkCard || !checkData) return;

    const statusSpan = checkCard.querySelector('.check-status');
    const messageP = checkCard.querySelector('.check-message');
    const progressBar = checkCard.querySelector('.progress-bar');

    // Update status
    statusSpan.textContent = `${checkData.icon} ${checkData.status}`;

    // Update status color
    statusSpan.classList.remove('text-success', 'text-warning', 'text-danger');
    if (checkData.status === 'Secure' || checkData.status === 'Good' || checkData.status === 'Safe' || checkData.status === 'Trusted') {
        statusSpan.classList.add('text-success');
    } else if (checkData.status === 'Warning' || checkData.status === 'Caution' || checkData.status === 'Unknown') {
        statusSpan.classList.add('text-warning');
    } else {
        statusSpan.classList.add('text-danger');
    }

    // Update message
    messageP.textContent = checkData.message;

    // Update progress bar
    const percentage = (checkData.score / 25) * 100;
    progressBar.style.width = `${percentage}%`;

    // Update progress bar color
    progressBar.classList.remove('bg-success', 'bg-warning', 'bg-danger');
    if (percentage >= 75) {
        progressBar.classList.add('bg-success');
    } else if (percentage >= 40) {
        progressBar.classList.add('bg-warning');
    } else {
        progressBar.classList.add('bg-danger');
    }
}

/**
 * Update AI analysis card with detailed information
 */
function updateAIAnalysis(checkId, aiData) {
    const checkCard = document.getElementById(checkId);
    if (!checkCard || !aiData) return;

    const statusSpan = checkCard.querySelector('.check-status');
    const messageP = checkCard.querySelector('.check-message');
    const progressBar = checkCard.querySelector('.progress-bar');
    const detailsDiv = document.getElementById('aiAnalysisDetails');

    // Update status
    statusSpan.textContent = `${aiData.icon} ${aiData.status}`;

    // Update status color
    statusSpan.classList.remove('text-success', 'text-warning', 'text-danger', 'text-muted');
    if (aiData.status === 'Trusted' || aiData.trustLevel === 'safe') {
        statusSpan.classList.add('text-success');
    } else if (aiData.status === 'Caution' || aiData.trustLevel === 'caution') {
        statusSpan.classList.add('text-warning');
    } else if (aiData.status === 'Suspicious' || aiData.trustLevel === 'dangerous') {
        statusSpan.classList.add('text-danger');
    } else {
        statusSpan.classList.add('text-muted');
    }

    // Update message
    messageP.textContent = aiData.message;

    // Update progress bar
    const percentage = (aiData.score / 20) * 100;
    progressBar.style.width = `${percentage}%`;

    // Update progress bar color
    progressBar.classList.remove('bg-success', 'bg-warning', 'bg-danger', 'bg-info');
    if (percentage >= 75) {
        progressBar.classList.add('bg-success');
    } else if (percentage >= 50) {
        progressBar.classList.add('bg-warning');
    } else if (percentage > 0) {
        progressBar.classList.add('bg-danger');
    } else {
        progressBar.classList.add('bg-info');
    }

    // Show detailed AI analysis if available
    if (aiData.aiPowered && aiData.credibilityScore !== null) {
        detailsDiv.style.display = 'block';

        // Update credibility score in message
        messageP.innerHTML = `${aiData.message}<br><strong>AI Credibility Score: ${aiData.credibilityScore}/100</strong>`;

        // Update risk factors
        const riskFactorsList = document.getElementById('aiRiskFactors');
        riskFactorsList.innerHTML = '';
        if (aiData.riskFactors && aiData.riskFactors.length > 0) {
            aiData.riskFactors.forEach(factor => {
                const li = document.createElement('li');
                li.textContent = factor;
                li.className = 'text-danger';
                riskFactorsList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = 'No significant risk factors identified';
            li.className = 'text-muted';
            riskFactorsList.appendChild(li);
        }

        // Update legitimacy indicators
        const legitimacyList = document.getElementById('aiLegitimacyIndicators');
        legitimacyList.innerHTML = '';
        if (aiData.legitimacyIndicators && aiData.legitimacyIndicators.length > 0) {
            aiData.legitimacyIndicators.forEach(indicator => {
                const li = document.createElement('li');
                li.textContent = indicator;
                li.className = 'text-success';
                legitimacyList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = 'No strong legitimacy indicators found';
            li.className = 'text-muted';
            legitimacyList.appendChild(li);
        }

        // Update AI recommendation
        const recommendationSpan = document.getElementById('aiRecommendation');
        recommendationSpan.textContent = aiData.recommendation || 'Exercise caution when visiting this website.';
    } else {
        detailsDiv.style.display = 'none';
    }
}

/**
 * Update recommendations list
 */
function updateRecommendations(recommendations) {
    const recommendationsList = document.getElementById('recommendationsList');
    recommendationsList.innerHTML = '';

    recommendations.forEach(recommendation => {
        const li = document.createElement('li');
        li.textContent = recommendation;
        recommendationsList.appendChild(li);
    });
}

/**
 * Show loading state
 */
function showLoading() {
    document.getElementById('loadingState').style.display = 'block';
}

/**
 * Hide loading state
 */
function hideLoading() {
    document.getElementById('loadingState').style.display = 'none';
}

/**
 * Hide results section
 */
function hideResults() {
    document.getElementById('resultsSection').style.display = 'none';
}

/**
 * Handle logout
 */
async function handleLogout() {
    try {
        await fetch(`${API_URL}/api/auth/logout`, {
            method: 'POST'
        });
    } catch (error) {
        console.error('Logout error:', error);
    }

    window.location.href = '/login';
}

/**
 * Show alert message (used for errors)
 */
function showAlert(message, type) {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    alert.style.top = '80px';
    alert.style.right = '20px';
    alert.style.zIndex = '9999';
    alert.style.maxWidth = '400px';
    alert.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'warning' ? 'exclamation-triangle' : 'exclamation-circle'} me-2"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.body.appendChild(alert);

    // Auto dismiss after 5 seconds
    setTimeout(() => {
        alert.remove();
    }, 5000);
}
