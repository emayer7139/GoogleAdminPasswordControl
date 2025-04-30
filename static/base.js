// Handle flash message dismissal
document.addEventListener('DOMContentLoaded', function() {
    // Initialize all Bootstrap dismissible elements
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(alert => {
        const closeButton = alert.querySelector('.btn-close');
        if (closeButton) {
            closeButton.addEventListener('click', () => {
                alert.remove();
            });
        }
    });
}); 