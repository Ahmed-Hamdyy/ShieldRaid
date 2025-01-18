document.addEventListener('DOMContentLoaded', function() {
    // Animate auth container on load
    const authContainer = document.querySelector('.auth-container');
    if (authContainer) {
        authContainer.style.opacity = '0';
        authContainer.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            authContainer.style.transition = 'all 0.6s ease-out';
            authContainer.style.opacity = '1';
            authContainer.style.transform = 'translateY(0)';
        }, 100);
    }

    // Add floating effect to auth box
    const authBox = document.querySelector('.auth-box');
    if (authBox) {
        authBox.style.animation = 'float 6s ease-in-out infinite';
    }

    // Animate form inputs with staggered delay
    const formGroups = document.querySelectorAll('.form-group');
    formGroups.forEach((group, index) => {
        group.style.opacity = '0';
        group.style.transform = 'translateX(-20px)';
        
        setTimeout(() => {
            group.style.transition = 'all 0.5s ease-out';
            group.style.opacity = '1';
            group.style.transform = 'translateX(0)';
        }, 200 + (index * 100));

        // Add focus animations to inputs
        const input = group.querySelector('input');
        if (input) {
            input.addEventListener('focus', () => {
                group.style.transform = 'scale(1.02)';
                input.style.boxShadow = '0 0 15px rgba(var(--primary-color-rgb), 0.15)';
            });

            input.addEventListener('blur', () => {
                group.style.transform = 'scale(1)';
                input.style.boxShadow = 'none';
            });
        }
    });

    // Animate submit button
    const submitBtn = document.querySelector('button[type="submit"]');
    if (submitBtn) {
        submitBtn.style.opacity = '0';
        submitBtn.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            submitBtn.style.transition = 'all 0.5s ease-out';
            submitBtn.style.opacity = '1';
            submitBtn.style.transform = 'translateY(0)';
        }, 600);

        // Add hover animation
        submitBtn.addEventListener('mouseover', () => {
            submitBtn.style.transform = 'translateY(-2px)';
            submitBtn.style.boxShadow = '0 5px 15px rgba(var(--primary-color-rgb), 0.3)';
        });

        submitBtn.addEventListener('mouseout', () => {
            submitBtn.style.transform = 'translateY(0)';
            submitBtn.style.boxShadow = 'none';
        });
    }

    // Form validation and submission
    const registerForm = document.querySelector('form');
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = {
                username: document.getElementById('username').value.trim(),
                email: document.getElementById('email').value.trim(),
                password: document.getElementById('password').value,
                confirm_password: document.getElementById('confirm_password').value
            };
            
            const validationError = validateForm(formData);
            if (validationError) {
                showError(validationError);
                return;
            }
            
            // Add loading animation to button
            const submitBtn = this.querySelector('button[type="submit"]');
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Creating account...';
            submitBtn.disabled = true;
            
            // Submit the form
            setTimeout(() => registerForm.submit(), 500);
        });
    }
    
    function validateForm(data) {
        // Username validation
        if (!data.username) {
            return 'Username is required';
        }
        if (!/^[a-zA-Z0-9_-]{3,20}$/.test(data.username)) {
            return 'Username must be 3-20 characters and contain only letters, numbers, underscores, and hyphens';
        }
        
        // Email validation
        if (!data.email) {
            return 'Email is required';
        }
        if (!/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(data.email)) {
            return 'Please enter a valid email address';
        }
        
        // Password validation
        if (!data.password) {
            return 'Password is required';
        }
        if (data.password.length < 8) {
            return 'Password must be at least 8 characters long';
        }
        
        // Confirm password validation
        if (data.password !== data.confirm_password) {
            return 'Passwords do not match';
        }
        
        return null;
    }
    
    function showError(message) {
        const existingErrors = document.querySelectorAll('.alert-danger');
        existingErrors.forEach(error => error.remove());
        
        const errorDiv = document.createElement('div');
        errorDiv.className = 'alert alert-danger alert-dismissible fade show';
        errorDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Animate error message
        errorDiv.style.opacity = '0';
        errorDiv.style.transform = 'translateY(-20px)';
        
        const form = document.querySelector('form');
        if (form) {
            form.insertBefore(errorDiv, form.firstChild);
            
            // Trigger animation
            setTimeout(() => {
                errorDiv.style.transition = 'all 0.3s ease-out';
                errorDiv.style.opacity = '1';
                errorDiv.style.transform = 'translateY(0)';
            }, 10);
            
            // Auto-dismiss after 5 seconds
            setTimeout(() => {
                errorDiv.style.opacity = '0';
                errorDiv.style.transform = 'translateY(-20px)';
                setTimeout(() => errorDiv.remove(), 300);
            }, 5000);
        }
    }

    // Add password strength indicator
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        const strengthIndicator = document.createElement('div');
        strengthIndicator.className = 'password-strength mt-2';
        strengthIndicator.style.height = '4px';
        strengthIndicator.style.transition = 'all 0.3s ease';
        strengthIndicator.style.borderRadius = '2px';
        
        passwordInput.parentNode.appendChild(strengthIndicator);
        
        passwordInput.addEventListener('input', () => {
            const strength = getPasswordStrength(passwordInput.value);
            updateStrengthIndicator(strengthIndicator, strength);
        });
    }

    function getPasswordStrength(password) {
        let strength = 0;
        if (password.length >= 8) strength += 25;
        if (password.match(/[a-z]/)) strength += 25;
        if (password.match(/[A-Z]/)) strength += 25;
        if (password.match(/[0-9]/)) strength += 25;
        return strength;
    }

    function updateStrengthIndicator(indicator, strength) {
        let color;
        if (strength <= 25) color = '#ff4444';
        else if (strength <= 50) color = '#ffbb33';
        else if (strength <= 75) color = '#00C851';
        else color = '#007E33';

        indicator.style.width = strength + '%';
        indicator.style.backgroundColor = color;
    }

    // Add CSS keyframes for floating animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes float {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-10px); }
        }
    `;
    document.head.appendChild(style);
}); 