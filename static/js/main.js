document.addEventListener('DOMContentLoaded', () => {
    // Timer countdown for password display
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
  