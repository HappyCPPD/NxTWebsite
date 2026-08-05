// Mobile nav toggle
const nav = document.getElementById('nav');
const navToggle = document.getElementById('navToggle');
const mobilePanel = document.getElementById('mobilePanel');

navToggle.addEventListener('click', () => {
  const isOpen = nav.classList.toggle('is-open');
  navToggle.setAttribute('aria-expanded', String(isOpen));
});

mobilePanel.querySelectorAll('a').forEach((link) => {
  link.addEventListener('click', () => {
    nav.classList.remove('is-open');
    navToggle.setAttribute('aria-expanded', 'false');
  });
});

// Scroll reveal
const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const revealEls = document.querySelectorAll('.reveal');

if (prefersReducedMotion || !('IntersectionObserver' in window)) {
  revealEls.forEach((el) => el.classList.add('is-visible'));
} else {
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.15 }
  );
  revealEls.forEach((el) => observer.observe(el));
}

// Join form (submits to Formspree)
const joinForm = document.getElementById('joinForm');
const formStatus = document.getElementById('formStatus');
const submitBtn = joinForm.querySelector('button[type="submit"]');

joinForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  // Honeypot check: if the hidden field got filled, silently drop it.
  const honeypot = joinForm.querySelector('#_gotcha');
  if (honeypot && honeypot.value) {
    joinForm.reset();
    return;
  }

  submitBtn.disabled = true;
  formStatus.textContent = 'Sending...';

  try {
    const response = await fetch(joinForm.action, {
      method: 'POST',
      body: new FormData(joinForm),
      headers: { Accept: 'application/json' },
    });

    if (response.ok) {
      formStatus.textContent = 'Thanks, we will be in touch soon.';
      joinForm.reset();
    } else {
      formStatus.textContent = 'Something went wrong. Please try again or reach out on Discord.';
    }
  } catch (err) {
    formStatus.textContent = 'Something went wrong. Please try again or reach out on Discord.';
  } finally {
    submitBtn.disabled = false;
  }
});
