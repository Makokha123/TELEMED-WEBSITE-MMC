// Enhanced password strength checker
function checkPasswordStrength(password) {
    let strength = 0;
    const requirements = {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        symbol: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
    };

    Object.values(requirements).forEach(requirement => {
        if (requirement) strength++;
    });

    return strength >= 4; // Require all criteria for strong password
}

function updatePasswordStrength(password) {
    const strengthBar = document.getElementById('passwordStrength');
    if (!strengthBar) return;

    const requirements = {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        symbol: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
    };

    let strength = 0;
    Object.values(requirements).forEach(requirement => {
        if (requirement) strength++;
    });

    strengthBar.className = 'password-strength';
    
    if (password.length === 0) {
        strengthBar.style.width = '0%';
        strengthBar.style.backgroundColor = 'transparent';
    } else if (strength <= 2) {
        strengthBar.className += ' strength-weak';
    } else if (strength === 3) {
        strengthBar.className += ' strength-fair';
    } else if (strength === 4) {
        strengthBar.className += ' strength-good';
    } else {
        strengthBar.className += ' strength-strong';
    }
}

// Password validation for reset forms
function validatePasswordOnSubmit() {
    const password = document.getElementById('new_password')?.value;
    const confirmPassword = document.getElementById('confirm_password')?.value;
    
    if (!password || !confirmPassword) {
        alert('Please fill in all password fields.');
        return false;
    }
    
    if (password !== confirmPassword) {
        alert('Passwords do not match!');
        return false;
    }
    
    if (!checkPasswordStrength(password)) {
        alert('Password does not meet security requirements. Please ensure it has at least 8 characters including uppercase, lowercase, numbers, and symbols.');
        return false;
    }
    
    return true;
}

// Event listener for password input
document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('new_password');
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            updatePasswordStrength(this.value);
        });
    }
    
    // Add form validation
    const resetForm = document.getElementById('resetPasswordForm');
    if (resetForm) {
        resetForm.addEventListener('submit', function(e) {
            if (!validatePasswordOnSubmit()) {
                e.preventDefault();
                return false;
            }
        });
    }

    // Toggle password visibility
    document.querySelectorAll('.toggle-password').forEach(button => {
        button.addEventListener('click', () => {
            const input = button.previousElementSibling;
            if (input && input.type === 'password') {
                input.type = 'text';
                button.innerHTML = '<i class="fas fa-eye-slash"></i>';
            } else if (input) {
                input.type = 'password';
                button.innerHTML = '<i class="fas fa-eye"></i>';
            }
        });
    });
});