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

    // Add floating animation to auth box
    const authBox = document.querySelector('.auth-box');
    if (authBox) {
        authBox.style.animation = 'float 6s ease-in-out infinite';
    }

    // Animate form inputs
    const formInputs = document.querySelectorAll('.form-control');
    formInputs.forEach((input, index) => {
        input.style.opacity = '0';
        input.style.transform = 'translateX(-20px)';
        
        setTimeout(() => {
            input.style.transition = 'all 0.5s ease-out';
            input.style.opacity = '1';
            input.style.transform = 'translateX(0)';
        }, 200 + (index * 100));

        // Add focus animations
        input.addEventListener('focus', () => {
            input.style.transform = 'scale(1.02)';
            input.style.boxShadow = '0 0 15px rgba(var(--primary-color-rgb), 0.15)';
        });

        input.addEventListener('blur', () => {
            input.style.transform = 'scale(1)';
            input.style.boxShadow = 'none';
        });
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
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const loginInput = document.getElementById('login');
            const passwordInput = document.getElementById('password');
            
            if (!loginInput || !passwordInput) {
                showError('Form inputs not found');
                return;
            }
            
            const formData = {
                email: loginInput.value.trim(),
                password: passwordInput.value.trim()
            };
            
            const validationError = validateForm(formData);
            if (validationError) {
                showError(validationError);
                return;
            }
            
            // Add loading animation to button
            const submitBtn = this.querySelector('button[type="submit"]');
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Logging in...';
            submitBtn.disabled = true;
            
            // Submit the form
            loginForm.removeEventListener('submit', arguments.callee);
            setTimeout(() => loginForm.submit(), 500);
        });
    }
    
    function validateForm(data) {
        if (!data.email) {
            return 'Email is required';
        }
        if (!data.password) {
            return 'Password is required';
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
        
        const form = document.getElementById('loginForm');
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