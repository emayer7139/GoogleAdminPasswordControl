// Initialize theme before page load
document.addEventListener('DOMContentLoaded', function() {
    // Set initial theme
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.className = savedTheme + '-mode';

    // Theme toggle functionality
    const themeToggle = document.getElementById('toggleTheme');
    const toggleIcon = themeToggle.querySelector('i');
    const logoImage = document.querySelector('.logo-image');
    
    // Update icon and logo based on current theme
    const updateThemeElements = () => {
        const isDark = document.documentElement.className === 'dark-mode';
        toggleIcon.className = isDark ? 'bi bi-sun fs-4' : 'bi bi-moon-stars fs-4';
        
        // Update logo source based on theme
        if (logoImage) {
            const baseUrl = logoImage.src.split('/static/')[0];
            logoImage.src = `${baseUrl}/static/img/${isDark ? 'dark_mode_logo.png' : 'logo.png'}`;
        }
    };
    
    // Initial update
    updateThemeElements();
    
    // Handle theme toggle
    themeToggle.addEventListener('click', () => {
        const html = document.documentElement;
        const isDark = html.className === 'dark-mode';
        const nextTheme = isDark ? 'light' : 'dark';
        html.className = nextTheme + '-mode';
        localStorage.setItem('theme', nextTheme);
        updateThemeElements();
    });
}); 