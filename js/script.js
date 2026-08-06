const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

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

// Nav gets a border once the page has scrolled off the top
const onScroll = () => nav.classList.toggle('is-stuck', window.scrollY > 8);
window.addEventListener('scroll', onScroll, { passive: true });
onScroll();

// Highlight the nav link for whichever section is in view
const navLinks = Array.from(document.querySelectorAll('.nav-links a'));
const sections = navLinks
  .map((link) => document.querySelector(link.getAttribute('href')))
  .filter(Boolean);

if ('IntersectionObserver' in window && sections.length) {
  const spy = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        navLinks.forEach((link) => {
          link.classList.toggle('is-active', link.getAttribute('href') === `#${entry.target.id}`);
        });
      });
    },
    { rootMargin: '-45% 0px -50% 0px' }
  );
  sections.forEach((section) => spy.observe(section));
}

// Scroll reveal
const revealEls = document.querySelectorAll('.reveal');

const showAll = () => revealEls.forEach((el) => el.classList.add('is-visible'));

if (prefersReducedMotion || !('IntersectionObserver' in window)) {
  showAll();
} else {
  let observerReported = false;

  const observer = new IntersectionObserver(
    (entries) => {
      observerReported = true;
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.12 }
  );

  revealEls.forEach((el) => observer.observe(el));

  // A healthy observer reports on every target as soon as it starts watching.
  // If nothing has come back, its callbacks are not running (throttled or
  // unusual embedding) — show the content rather than leave the page blank.
  setTimeout(() => {
    if (!observerReported) showAll();
  }, 2000);
}

// Pointer-tracked highlight on the category cards
if (window.matchMedia('(hover: hover)').matches) {
  document.querySelectorAll('.focus-card').forEach((card) => {
    card.addEventListener('pointermove', (e) => {
      const rect = card.getBoundingClientRect();
      card.style.setProperty('--mx', `${e.clientX - rect.left}px`);
      card.style.setProperty('--my', `${e.clientY - rect.top}px`);
    });
  });
}

// Hero terminal: types the commands, fades in the output
const term = document.getElementById('term');

if (term) {
  const lines = Array.from(term.querySelectorAll('.term-line'));

  if (prefersReducedMotion) {
    lines.forEach((line) => line.classList.add('is-on'));
  } else {
    // Stash each command so the line can be typed back in a character at a time.
    const commands = new Map();
    lines.forEach((line) => {
      const cmd = line.querySelector('.cmd');
      if (cmd) {
        commands.set(line, cmd.textContent);
        cmd.textContent = '';
      }
    });

    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

    const boot = async () => {
      for (const line of lines) {
        line.classList.add('is-on');
        const cmd = line.querySelector('.cmd');

        if (cmd) {
          const text = commands.get(line);
          for (let i = 1; i <= text.length; i += 1) {
            cmd.textContent = text.slice(0, i);
            await wait(26);
          }
          await wait(240);
        } else {
          await wait(170);
        }
      }
    };

    boot();
  }
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

// The flag mentioned in the footer. It is base64 in data-x on #term.
console.log(
  '%cnxt_ctfs%c you found the console. the flag is one decode away — check data-x on #term.',
  'background:#e6293f;color:#fff;font-weight:700;padding:2px 6px;border-radius:3px',
  'color:#9d98a6'
);
