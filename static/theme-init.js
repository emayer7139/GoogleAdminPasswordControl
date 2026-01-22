// Initialize theme before page load to prevent flash
const serverTheme = window.__themePreference || '';
const savedTheme = serverTheme || localStorage.getItem('theme') || 'light';
document.documentElement.className = savedTheme + '-mode';
localStorage.setItem('theme', savedTheme);
