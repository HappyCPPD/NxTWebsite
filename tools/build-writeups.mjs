/* Build the on-site writeups from writeups/src/*.md + writeups.config.json.
 *
 *   node tools/build-writeups.mjs
 *
 * Produces writeups.html (index) and writeups/<slug>.html (one per challenge).
 * The only dependency is the vendored marked (tools/vendor/marked.esm.js),
 * used at build time only. The published pages ship as static HTML with no
 * third-party requests, matching the rest of the site.
 */
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { renderBody, esc } from './lib/renderer.mjs';
import { applyGlossary } from './lib/glossary.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cfg = JSON.parse(readFileSync(join(root, 'tools/writeups.config.json'), 'utf8'));
const glossary = JSON.parse(readFileSync(join(root, 'tools/glossary.json'), 'utf8'));

const CSS_V = 17;
const JS_V = 17;

/* Nest h3 entries under their preceding h2 in the sidebar TOC. `toc` text is
 * already HTML-entity-escaped once by the heading renderer - do not esc() it
 * again here, or quotes in headings double-escape to `&amp;quot;`. */
function renderToc(toc) {
  if (!toc.length) return '';
  let html = '';
  let open2 = false;
  let open3 = false;
  for (const t of toc) {
    if (t.level === 2) {
      if (open3) { html += '</ol>'; open3 = false; }
      if (open2) html += '</li>';
      html += `<li><a href="#${t.id}">${t.text}</a>`;
      open2 = true;
    } else {
      if (!open3) { html += '<ol class="wu-toc-sub">'; open3 = true; }
      html += `<li><a href="#${t.id}">${t.text}</a></li>`;
    }
  }
  if (open3) html += '</ol>';
  if (open2) html += '</li>';
  return `<nav class="wu-toc" aria-label="On this page">
        <button type="button" class="wu-toc-toggle" aria-expanded="false">On this page</button>
        <p class="wu-toc-h">On this page</p>
        <ol>${html}</ol>
      </nav>`;
}

function navHtml(prefix) {
  return `<nav class="nav" id="nav">
  <div class="container nav-inner">
    <div class="nav-id">
      <span class="nav-ws">[0]</span>
      <a href="${prefix}index.html#top" class="brand">
        <img src="${prefix}images/Logo-nobg.png" alt="NXT_CTFS logo" />
        <span class="brand-name">NXT_CTFS</span>
      </a>
    </div>
    <div class="nav-links">
      <a href="${prefix}index.html#about">about</a>
      <a href="${prefix}index.html#focus">categories</a>
      <a href="${prefix}index.html#results">results</a>
      <a href="${prefix}writeups.html" class="is-active">writeups</a>
      <a href="${prefix}index.html#team">team</a>
      <a href="${prefix}index.html#shell">challenge</a>
      <a href="${prefix}index.html#join">join</a>
    </div>
    <div class="nav-cta">
      <span class="nav-clock" id="navClock" aria-hidden="true">00:00:00</span>
      <a href="${prefix}index.html#join" class="btn btn-secondary">Join us</a>
      <button class="nav-toggle" id="navToggle" aria-label="Toggle menu" aria-expanded="false">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <line x1="4" y1="7" x2="20" y2="7"></line>
          <line x1="4" y1="12" x2="20" y2="12"></line>
          <line x1="4" y1="17" x2="20" y2="17"></line>
        </svg>
      </button>
    </div>
  </div>
  <div class="mobile-panel" id="mobilePanel">
    <a href="${prefix}index.html#about">about</a>
    <a href="${prefix}index.html#focus">categories</a>
    <a href="${prefix}index.html#results">results</a>
    <a href="${prefix}writeups.html">writeups</a>
    <a href="${prefix}index.html#team">team</a>
    <a href="${prefix}index.html#shell">challenge</a>
    <a href="${prefix}index.html#join">join</a>
  </div>
</nav>`;
}

function footerHtml(prefix) {
  return `<footer class="footer container">
  <div class="footer-grid">
    <div>
      <a href="${prefix}index.html#top" class="footer-brand">
        <img src="${prefix}images/Logo-nobg.png" alt="NXT_CTFS logo" />
        <span>NXT_CTFS</span>
      </a>
      <p class="footer-tag">A team built around curiosity, persistence, and the occasional 3am breakthrough.</p>
    </div>
    <div class="footer-col">
      <h4>Navigate</h4>
      <a href="${prefix}index.html#about">About</a>
      <a href="${prefix}index.html#focus">Categories</a>
      <a href="${prefix}index.html#results">Results</a>
      <a href="${prefix}writeups.html">Writeups</a>
      <a href="${prefix}index.html#join">Join</a>
    </div>
    <div class="footer-col">
      <h4>Connect</h4>
      <a href="https://discord.gg/AnmfSNMvS" target="_blank" rel="noopener noreferrer">Discord</a>
      <a href="https://github.com/HappyCPPD/NxT-s-Team-Library" target="_blank" rel="noopener noreferrer">GitHub</a>
      <a href="https://ctftime.org/team/442864" target="_blank" rel="noopener noreferrer">CTFtime</a>
    </div>
  </div>
  <div class="footer-bottom">
    <span>&copy; 2026 NXT_CTFS. All rights reserved.</span>
    <span class="footer-hint">Two flags on this page. One is in the sandbox.</span>
  </div>
</footer>`;
}

function page({ prefix, title, desc, body }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>${esc(title)}</title>
<meta name="description" content="${esc(desc)}" />
<link rel="icon" href="${prefix}images/Logo-nobg.png" type="image/png" />
<link rel="stylesheet" href="${prefix}css/fonts.css?v=2" />
<link rel="stylesheet" href="${prefix}css/styles.css?v=${CSS_V}" />
<script>document.documentElement.classList.add('js');</script>
</head>
<body>

<div class="backdrop" aria-hidden="true"></div>
<div class="gutters" aria-hidden="true"></div>

${navHtml(prefix)}

${body}

${footerHtml(prefix)}

<script src="${prefix}js/script.js?v=${JS_V}"></script>
</body>
</html>
`;
}

const catLabel = {
  ai: 'AI', pwn: 'pwn', rev: 'rev', crypto: 'crypto', misc: 'misc', web: 'web', forensics: 'forensics', osint: 'osint',
};

/* ---------- index ---------- */
function buildIndex() {
  const r = cfg.result;
  const cards = cfg.challenges
    .map((c) => `      <li class="wu-card">
        <a class="wu-card-link" href="writeups/${c.slug}.html">
          <div class="wu-card-top">
            <span class="wu-cat wu-cat-${c.category}">${catLabel[c.category] || c.category}</span>
            <span class="wu-pts">${c.points} pts</span>
          </div>
          <h3 class="wu-card-name">${esc(c.name)}<span class="wu-card-sub">${esc(c.subtitle)}</span></h3>
          <p class="wu-card-blurb">${esc(c.blurb)}</p>
          <div class="wu-card-foot">
            <code class="wu-flag">${esc(c.flag)}</code>
            <span class="wu-go">read <svg class="icon" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M200,64V168a8,8,0,0,1-16,0V83.31L69.66,197.66a8,8,0,0,1-11.32-11.32L172.69,72H88a8,8,0,0,1,0-16H192A8,8,0,0,1,200,64Z"/></svg></span>
          </div>
        </a>
      </li>`)
    .join('\n');

  const body = `<main id="top">
  <section class="wu-hero container">
    <p class="eyebrow"><span class="dot"></span>${esc(cfg.event)}</p>
    <h1>Writeups</h1>
    <p class="wu-hero-lede">How the team solved each challenge at ${esc(cfg.event)}. Root cause first, then the exploit. ${r.solves} solves, ${r.points} points, ${esc(r.placement)} in the ${esc(r.league)}.</p>
    <div class="wu-scoreline">
      <span><b>${esc(r.placement)}</b> ${esc(r.league)}</span>
      <span><b>${r.points}</b> points</span>
      <span><b>${r.solves}</b> solves</span>
      <span><b>${esc(cfg.team)}</b> · ${esc(cfg.org)}</span>
    </div>
  </section>

  <section class="section container" style="border-top:none;padding-top:0">
    <ul class="wu-grid">
${cards}
    </ul>
    <p class="wu-note">Solve scripts and challenge archives aren't published here. Ask in <a href="https://discord.gg/AnmfSNMvS" target="_blank" rel="noopener noreferrer">Discord</a>. Flags are per-event; some sandbox challenges issued a per-instance flag.</p>
  </section>
</main>`;

  writeFileSync(
    join(root, 'writeups.html'),
    page({
      prefix: '',
      title: `Writeups · ${cfg.event} · NXT_CTFS`,
      desc: `NXT_CTFS writeups for ${cfg.event}: ${cfg.challenges.map((c) => c.name).join(', ')}.`,
      body,
    })
  );
  console.log('wrote writeups.html');
}

/* ---------- detail pages ---------- */
function buildDetail(c, i) {
  const md = readFileSync(join(root, 'writeups/src', `${c.slug}.md`), 'utf8');
  const { html: rendered, toc } = renderBody(md);
  const html = applyGlossary(rendered, glossary);
  const prev = cfg.challenges[i - 1];
  const next = cfg.challenges[i + 1];

  const tocHtml = renderToc(toc);

  const prevCard = prev
    ? `<a class="wu-pager-link wu-pager-prev" href="${prev.slug}.html"><span class="wu-pager-dir">&larr; Previous</span><span class="wu-pager-name">${esc(prev.name)}</span></a>`
    : `<a class="wu-pager-link wu-pager-prev wu-pager-index" href="../writeups.html"><span class="wu-pager-dir">Index</span><span class="wu-pager-name">All writeups</span></a>`;
  const nextCard = next
    ? `<a class="wu-pager-link wu-pager-next" href="${next.slug}.html"><span class="wu-pager-dir">Next &rarr;</span><span class="wu-pager-name">${esc(next.name)}</span></a>`
    : `<a class="wu-pager-link wu-pager-next wu-pager-index" href="../writeups.html"><span class="wu-pager-dir">Index</span><span class="wu-pager-name">All writeups</span></a>`;
  const pager = `<nav class="wu-pager" aria-label="More writeups">
    ${prevCard}
    ${nextCard}
  </nav>`;

  const body = `<div class="wu-progress" aria-hidden="true"><div class="wu-progress-bar" id="wuProgress"></div></div>
  <main class="wu-main container" id="top">
  <div class="wu-crumbs"><a href="../index.html#top">nxt_ctfs</a> <span>/</span> <a href="../writeups.html">writeups</a> <span>/</span> <span>${esc(c.slug)}</span></div>

  <header class="wu-head">
    <div class="wu-head-tags">
      <span class="wu-cat wu-cat-${c.category}">${catLabel[c.category] || c.category}</span>
      <span class="wu-pts">${c.points} pts</span>
      <span class="wu-when">solved ${esc(c.solved)}</span>
    </div>
    <h1>${esc(c.name)} <span>${esc(c.subtitle)}</span></h1>
    <div class="wu-flagrow">
      <span class="wu-flagrow-k">flag</span>
      <code id="wuFlag">${esc(c.flag)}</code>
      <button type="button" class="wu-copy" data-copy="#wuFlag" aria-label="Copy flag">copy</button>
    </div>
  </header>

  <div class="wu-layout">
    <article class="wu-article">
${html}
    </article>
    ${tocHtml}
  </div>

  ${pager}
</main>`;

  writeFileSync(
    join(root, 'writeups', `${c.slug}.html`),
    page({
      prefix: '../',
      title: `${c.name} · ${cfg.event} writeup · NXT_CTFS`,
      desc: c.blurb,
      body,
    })
  );
  console.log(`wrote writeups/${c.slug}.html`);
}

buildIndex();
cfg.challenges.forEach(buildDetail);

/* sanity: warn on stray src files not in config */
const known = new Set(cfg.challenges.map((c) => `${c.slug}.md`));
for (const f of readdirSync(join(root, 'writeups/src'))) {
  if (f.endsWith('.md') && !known.has(f)) console.warn(`! ${f} in writeups/src has no config entry`);
}
