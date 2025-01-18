document.addEventListener('DOMContentLoaded', function() {
    // Add animation styles
    const style = document.createElement('style');
    style.textContent = `
        .container {
            opacity: 0;
            animation: fadeIn 0.6s ease-out forwards;
        }

        @keyframes fadeIn {
            to {
                opacity: 1;
            }
        }

        .card {
            opacity: 0;
            transform: translateY(20px);
            animation: slideUp 0.6s ease-out forwards;
        }

        @keyframes slideUp {
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .card-header {
            transition: all 0.3s ease;
        }

        .card-header:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .detail-item {
            opacity: 0;
            transform: translateX(-20px);
            animation: slideIn 0.5s ease-out forwards;
        }

        @keyframes slideIn {
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        .evidence-section {
            opacity: 0;
            transform: scale(0.95);
            animation: scaleIn 0.5s ease-out forwards;
        }

        @keyframes scaleIn {
            to {
                opacity: 1;
                transform: scale(1);
            }
        }

        .code-block {
            position: relative;
            overflow: hidden;
        }

        .code-block::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
            transform: translateX(-100%);
            animation: shimmer 2s infinite;
        }

        @keyframes shimmer {
            100% {
                transform: translateX(100%);
            }
        }

        .alert {
            animation: bounceIn 0.6s cubic-bezier(0.68, -0.55, 0.265, 1.55);
        }

        @keyframes bounceIn {
            0% {
                opacity: 0;
                transform: scale(0.3);
            }
            50% {
                opacity: 0.9;
                transform: scale(1.1);
            }
            80% {
                opacity: 1;
                transform: scale(0.89);
            }
            100% {
                opacity: 1;
                transform: scale(1);
            }
        }
    `;
    document.head.appendChild(style);

    // Add animation delays to cards
    const cards = document.querySelectorAll('.card');
    cards.forEach((card, index) => {
        card.style.animationDelay = `${index * 0.2}s`;
    });

    // Add animation delays to detail items
    const detailItems = document.querySelectorAll('.detail-item');
    detailItems.forEach((item, index) => {
        item.style.animationDelay = `${index * 0.1}s`;
    });

    // Add animation delays to evidence sections
    const evidenceSections = document.querySelectorAll('.evidence-section');
    evidenceSections.forEach((section, index) => {
        section.style.animationDelay = `${index * 0.3}s`;
    });

    // Handle card collapse animations
    document.querySelectorAll('.card-header').forEach(header => {
        header.addEventListener('click', function() {
            const icon = this.querySelector('.fa-chevron-down');
            const content = this.closest('.card').querySelector('.collapse');
            
            if (content.classList.contains('show')) {
                icon.style.transform = 'rotate(0deg)';
                content.style.animation = 'slideOutUp 0.3s ease-out forwards';
            } else {
                icon.style.transform = 'rotate(180deg)';
                content.style.animation = 'slideInDown 0.3s ease-out forwards';
            }
        });
    });

    // Add copy button to code blocks
    document.querySelectorAll('.code-block').forEach(block => {
        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn btn-sm btn-outline-light position-absolute top-0 end-0 m-2';
        copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
        copyBtn.addEventListener('click', function() {
            const code = block.querySelector('code').textContent;
            navigator.clipboard.writeText(code).then(() => {
                this.innerHTML = '<i class="fas fa-check"></i>';
                setTimeout(() => {
                    this.innerHTML = '<i class="fas fa-copy"></i>';
                }, 2000);
            });
        });
        block.style.position = 'relative';
        block.appendChild(copyBtn);
    });

    // Add expand/collapse all button
    const container = document.querySelector('.container');
    if (container && document.querySelectorAll('.card').length > 1) {
        const toggleBtn = document.createElement('button');
        toggleBtn.className = 'btn btn-outline-primary mb-3';
        toggleBtn.innerHTML = '<i class="fas fa-expand-alt"></i> Expand All';
        let expanded = false;

        toggleBtn.addEventListener('click', function() {
            const cards = document.querySelectorAll('.collapse');
            if (expanded) {
                cards.forEach(card => card.classList.remove('show'));
                this.innerHTML = '<i class="fas fa-expand-alt"></i> Expand All';
            } else {
                cards.forEach(card => card.classList.add('show'));
                this.innerHTML = '<i class="fas fa-compress-alt"></i> Collapse All';
            }
            expanded = !expanded;
        });

        container.insertBefore(toggleBtn, container.firstChild.nextSibling);
    }
}); 