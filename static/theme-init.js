// Initialize theme before page load to prevent flash
const savedTheme = localStorage.getItem('theme') || 'light';
document.documentElement.className = savedTheme + '-mode'; 