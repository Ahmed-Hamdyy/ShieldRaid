document.addEventListener('DOMContentLoaded', () => {
    // Typing animation text
    const typingText = document.querySelector('.typing-text');
    const texts = [
        'Detect vulnerabilities in real-time',
        'Protect your applications',
        'Get detailed security insights',
        'Stay ahead of threats'
    ];
    let textIndex = 0;
    let charIndex = 0;
    let isDeleting = false;
    let typingDelay = 100;

    function typeText() {
        const currentText = texts[textIndex];
        
        if (isDeleting) {
            typingText.textContent = currentText.substring(0, charIndex - 1);
            charIndex--;
            typingDelay = 50;
        } else {
            typingText.textContent = currentText.substring(0, charIndex + 1);
            charIndex++;
            typingDelay = 100;
        }

        if (!isDeleting && charIndex === currentText.length) {
            isDeleting = true;
            typingDelay = 2000; // Pause at end
        } else if (isDeleting && charIndex === 0) {
            isDeleting = false;
            textIndex = (textIndex + 1) % texts.length;
            typingDelay = 500; // Pause before next word
        }

        setTimeout(typeText, typingDelay);
    }

    // Start typing animation
    setTimeout(typeText, 1000);

    // Animate stats numbers
    const stats = document.querySelectorAll('.stat-number');
    const animationDuration = 2000; // 2 seconds
    const frameDuration = 1000/60; // 60fps
    
    stats.forEach(stat => {
        const finalNumber = parseInt(stat.dataset.count);
        const totalFrames = Math.round(animationDuration/frameDuration);
        const countIncrement = finalNumber/totalFrames;
        let currentCount = 0;
        
        function updateCount() {
            currentCount += countIncrement;
            if(currentCount < finalNumber) {
                stat.textContent = Math.floor(currentCount);
                requestAnimationFrame(updateCount);
            } else {
                stat.textContent = finalNumber;
            }
        }
        
        // Start animation when element is in view
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if(entry.isIntersecting) {
                    requestAnimationFrame(updateCount);
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.5 });
        
        observer.observe(stat);
    });

    // Smooth scroll for navigation links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Parallax effect for security grid
    const grid = document.querySelector('.security-grid');
    let ticking = false;

    window.addEventListener('scroll', () => {
        if (!ticking) {
            window.requestAnimationFrame(() => {
                const scrolled = window.pageYOffset;
                if (grid) {
                    grid.style.transform = `perspective(500px) rotateX(60deg) translateY(${scrolled * 0.5}px)`;
                }
                ticking = false;
            });
            ticking = true;
        }
    });

    // Feature cards hover effect
    const cards = document.querySelectorAll('.feature-card');
    
    cards.forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            const centerX = rect.width / 2;
            const centerY = rect.height / 2;
            
            const angleX = (y - centerY) / 20;
            const angleY = (centerX - x) / 20;
            
            card.style.transform = `perspective(1000px) rotateX(${angleX}deg) rotateY(${angleY}deg) translateZ(10px)`;
        });
        
        card.addEventListener('mouseleave', () => {
            card.style.transform = 'perspective(1000px) rotateX(0) rotateY(0) translateZ(0)';
        });
    });

    // Add pulse animation to security badge icon
    const securityIcon = document.querySelector('.security-badge i');
    if (securityIcon) {
        setInterval(() => {
            securityIcon.style.animation = 'pulse 1s ease-in-out';
            setTimeout(() => {
                securityIcon.style.animation = '';
            }, 1000);
        }, 3000);
    }

    // Animate buttons on hover
    const buttons = document.querySelectorAll('.security-btn');
    
    buttons.forEach(button => {
        button.addEventListener('mousemove', (e) => {
            const rect = button.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            button.style.setProperty('--x', `${x}px`);
            button.style.setProperty('--y', `${y}px`);
        });
    });

    // Initialize AOS (Animate on Scroll) if available
    if (typeof AOS !== 'undefined') {
        AOS.init({
            duration: 1000,
            once: true,
            offset: 100
        });
    }
}); 