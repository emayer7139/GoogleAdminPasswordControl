document.addEventListener('DOMContentLoaded', () => {
  // 1) TOOLTIP INIT (if you’re using any data-bs-toggle="tooltip")
  if (window.bootstrap) {
    const tipEls = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tipEls.forEach(el => new bootstrap.Tooltip(el));
  }

  // 2) MOTIVATIONAL QUOTE
 const fallback = [
  "Believe you can and you’re halfway there.",
  "Success is not final, failure is not fatal: it’s the courage to continue that counts.",
  "Hardships often prepare ordinary people for an extraordinary destiny."
];

fetch('https://api.quotable.io/random?tags=motivational|inspirational')
  .then(res => res.ok ? res.json() : Promise.reject())
  .then(data => {
    txt.textContent  = `"${data.content}"`;
    auth.textContent = data.author;
  })
  .catch(_ => {
    // on any error, pick a random fallback
    const q = fallback[Math.floor(Math.random() * fallback.length)];
    txt.textContent  = `"${q}"`;
    auth.textContent = "— Unknown";
  })
  .finally(() => {
    card.style.display = 'block';
    card.classList.add('animate__fadeIn');
  });


  // 3) PASSWORD DISPLAY TIMER & CONFETTI
  const timerEl = document.getElementById('timer');
  const pwDisplay = document.getElementById('password-display');
  const newPwEl   = document.getElementById('new-password');
  if (timerEl && pwDisplay && newPwEl && window.party) {
    let seconds = parseInt(timerEl.textContent, 10);
    const interval = setInterval(() => {
      if (--seconds <= 0) {
        clearInterval(interval);
        pwDisplay.innerHTML =
          '<p class="text-muted">Password view expired. Please note it immediately next time.</p>';
      } else {
        timerEl.textContent = seconds;
      }
    }, 1000);

    // small confetti burst
    party.confetti(newPwEl, {
      count: party.variation.range(20, 40),
      speed: party.variation.range(200, 400)
    });
  }

  // 4) HELP DRAWER TOGGLE
  const helpToggle = document.getElementById('helpToggle');
  const helpDrawer = document.getElementById('helpDrawer');
  const helpContent = document.getElementById('helpContent');
  if (helpToggle && helpDrawer && helpContent) {
    helpToggle.addEventListener('click', () => {
      // slide in/out
      if (helpDrawer.classList.contains('show')) {
        // bootstrap offcanvas will handle hide
      } else {
        // optionally load context‐specific help:
        const path = window.location.pathname;
        fetch(`/help${path}`)
          .then(r => r.text())
          .then(html => helpContent.innerHTML = html)
          .catch(() => {/* ignore failures */});
      }
    });
  }
});
