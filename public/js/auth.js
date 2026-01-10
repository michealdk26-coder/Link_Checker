/**
 * Authentication JavaScript
 * Handles signup, login, and password visibility toggle
 */

// API Base URL
const API_URL = window.location.origin;

// Show/hide password toggle
document.addEventListener('DOMContentLoaded', () => {
    const togglePassword = document.getElementById('togglePassword');

    if (togglePassword) {
        togglePassword.addEventListener('click', function () {
            const passwordInput = document.getElementById('password');
            const icon = this.querySelector('i');

            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                passwordInput.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        });
    }

    // Handle Signup Form
    const signupForm = document.getElementById('signupForm');
    if (signupForm) {
        signupForm.addEventListener('submit', handleSignup);
    }

    // Handle Login Form
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
});

/**
 * Handle user signup
 */
async function handleSignup(e) {
    e.preventDefault();

    const fullName = document.getElementById('fullName').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const agreeTerms = document.getElementById('agreeTerms').checked;

    console.log('Signup attempt:', { fullName, email, passwordLength: password.length });

    if (password !== confirmPassword) {
        showAlert('Passwords do not match', 'danger');
        document.getElementById('confirmPassword').classList.add('is-invalid');
        return;
    }

    // Show loading state
    const signupBtn = document.getElementById('signupBtn');
    const originalText = signupBtn.innerHTML;
    signupBtn.disabled = true;
    signupBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Creating account...';

    try {
        const response = await fetch(`${API_URL}/api/auth/signup`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                fullName,
                email,
                password,
                confirmPassword
            })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            // Store token
            localStorage.setItem('token', data.token);

            // Show success message
            showAlert('Account created successfully! Redirecting to dashboard...', 'success');

            // Redirect to dashboard
            setTimeout(() => {
                window.location.href = '/dashboard';
            }, 1500);
        } else {
            // Show errors
            if (data.errors && Array.isArray(data.errors)) {
                data.errors.forEach(error => showAlert(error, 'danger'));
            } else {
                showAlert(data.message || 'Signup failed. Please try again.', 'danger');
            }

            signupBtn.disabled = false;
            signupBtn.innerHTML = originalText;
        }
    } catch (error) {
        console.error('Signup error:', error);
        showAlert('Network error. Please check your connection and try again.', 'danger');
        signupBtn.disabled = false;
        signupBtn.innerHTML = originalText;
    }
}

/**
 * Handle user login
 */
async function handleLogin(e) {
    e.preventDefault();

    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;

    // Clear previous errors
    clearValidationErrors();

    // Show loading state
    const loginBtn = document.getElementById('loginBtn');
    const originalText = loginBtn.innerHTML;
    loginBtn.disabled = true;
    loginBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Logging in...';

    try {
        const response = await fetch(`${API_URL}/api/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email,
                password
            })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            // Store token
            localStorage.setItem('token', data.token);

            // Show success message
            showAlert('Login successful! Redirecting to dashboard...', 'success');

            // Redirect to dashboard
            setTimeout(() => {
                window.location.href = '/dashboard';
            }, 1000);
        } else {
            // Show errors
            if (data.errors && Array.isArray(data.errors)) {
                data.errors.forEach(error => showAlert(error, 'danger'));
            } else {
                showAlert(data.message || 'Login failed. Please check your credentials.', 'danger');
            }

            loginBtn.disabled = false;
            loginBtn.innerHTML = originalText;
        }
    } catch (error) {
        console.error('Login error:', error);
        showAlert('Network error. Please check your connection and try again.', 'danger');
        loginBtn.disabled = false;
        loginBtn.innerHTML = originalText;
    }
}

/**
 * Show alert message
 */
function showAlert(message, type) {
    const alertContainer = document.getElementById('alertContainer');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.role = 'alert';
    alert.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'} me-2"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    alertContainer.appendChild(alert);

    // Auto dismiss after 5 seconds
    setTimeout(() => {
        alert.remove();
    }, 5000);
}

/**
 * Clear validation errors
 */
function clearValidationErrors() {
    const inputs = document.querySelectorAll('.form-control');
    inputs.forEach(input => {
        input.classList.remove('is-invalid');
    });

    const alertContainer = document.getElementById('alertContainer');
    if (alertContainer) {
        alertContainer.innerHTML = '';
    }
}
