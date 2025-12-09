// Theme toggle functionality
document.addEventListener('DOMContentLoaded', function() {
    const themeToggle = document.getElementById('toggleTheme');
    const toggleText = document.getElementById('toggleText');
    
    if (themeToggle && toggleText) {
        // Update toggle text based on current theme
        const updateText = () => {
            const isDark = document.documentElement.className === 'dark-mode';
            toggleText.textContent = isDark ? 'Toggle Light Mode' : 'Toggle Dark Mode';
        };
        
        // Initial text update
        updateText();
        
        // Handle theme toggle
        themeToggle.addEventListener('click', () => {
            const html = document.documentElement;
            const isDark = html.className === 'dark-mode';
            const nextTheme = isDark ? 'light' : 'dark';
            
            html.className = nextTheme + '-mode';
            localStorage.setItem('theme', nextTheme);
            updateText();
        });
    }
});

// Timer countdown for password display
document.addEventListener('DOMContentLoaded', () => {
    let timerEl = document.getElementById('timer');
    if (timerEl) {
        let seconds = parseInt(timerEl.textContent, 10);
        const interval = setInterval(() => {
            seconds--;
            timerEl.textContent = seconds;
            if (seconds <= 0) {
                clearInterval(interval);
                document.getElementById('password-display').innerHTML =
                    '<p class="text-muted">Password view expired. Please note it immediately next time.</p>';
            }
        }, 1000);

        // Fire confetti when password shows
        party.confetti(document.getElementById('new-password'), {
            count: party.variation.range(20, 40),
            speed: party.variation.range(200, 400)
        });
    }
});

// Form validation
function validateForm(form) {
    const requiredFields = form.querySelectorAll('[required]');
    let isValid = true;

    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            field.classList.add('is-invalid');
            isValid = false;
        } else {
            field.classList.remove('is-invalid');
        }
    });

    return isValid;
}

// AJAX form submission
function submitForm(form, successCallback, errorCallback) {
    if (!validateForm(form)) {
        return;
    }

    const submitButton = form.querySelector('button[type="submit"]');
    if (submitButton) {
        submitButton.disabled = true;
        submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
    }

    fetch(form.action, {
        method: form.method,
        body: new FormData(form)
    })
    .then(response => response.json())
    .then(data => {
        if (submitButton) {
            submitButton.disabled = false;
            submitButton.innerHTML = submitButton.dataset.originalText || 'Submit';
        }
        if (successCallback) successCallback(data);
    })
    .catch(error => {
        if (submitButton) {
            submitButton.disabled = false;
            submitButton.innerHTML = submitButton.dataset.originalText || 'Submit';
        }
        if (errorCallback) errorCallback(error);
    });
}

// Flash message handling
function showFlashMessage(message, type = 'info') {
    const flashContainer = document.getElementById('flash-messages');
    if (!flashContainer) return;

    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    flashContainer.appendChild(alert);

    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        alert.classList.remove('show');
        setTimeout(() => alert.remove(), 150);
    }, 5000);
}

// Initialize tooltips
document.addEventListener('DOMContentLoaded', function() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});
