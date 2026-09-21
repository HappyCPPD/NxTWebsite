/* Build the on-site writeups from writeups/src/*.md + writeups.config.json.
 *
 *   node tools/build-writeups.mjs
 *
 * Produces writeups.html (multi-event index), writeups/<slug>.html (one per
 * challenge, flat across events) and members/<slug>.html (one per team member).
 * The only dependency is the vendored marked (tools/vendor/marked.esm.js),
 * used at build time only. The published pages ship as static HTML with no
 * third-party requests, matching the rest of the site.
 */
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { renderBody, esc } from './lib/renderer.mjs';
import { applyGlossary } from './lib/glossary.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cfg = JSON.parse(readFileSync(join(root, 'tools/writeups.config.json'), 'utf8'));
const glossary = JSON.parse(readFileSync(join(root, 'tools/glossary.json'), 'utf8'));

const CSS_V = 18;
const JS_V = 18;

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

function navHtml(prefix, active = 'writeups') {
  const cls = (name) => (name === active ? ' class="is-active"' : '');
  return `<nav class="nav" id="nav">
  <div class="container nav-inner">
    <div class="nav-id">
      <span class="nav-ws">[0]</span>
      <a href="${prefix}index.html#top" class="brand">
        <img src="${prefix}images/brand/logo.png" alt="NXT_CTFS logo" />
        <span class="brand-name">NXT_CTFS</span>
      </a>
    </div>
    <div class="nav-links">
      <a href="${prefix}index.html#about">about</a>
      <a href="${prefix}index.html#focus">categories</a>
      <a href="${prefix}index.html#results">results</a>
      <a href="${prefix}writeups.html"${cls('writeups')}>writeups</a>
      <a href="${prefix}index.html#team"${cls('team')}>team</a>
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
        <img src="${prefix}images/brand/logo.png" alt="NXT_CTFS logo" />
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

function page({ prefix, title, desc, body, navActive = 'writeups' }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>${esc(title)}</title>
<meta name="description" content="${esc(desc)}" />
<link rel="icon" href="${prefix}images/brand/logo.png" type="image/png" />
<link rel="stylesheet" href="${prefix}css/fonts.css?v=2" />
<link rel="stylesheet" href="${prefix}css/styles.css?v=${CSS_V}" />
<script>document.documentElement.classList.add('js');</script>
</head>
<body>

<div class="backdrop" aria-hidden="true"></div>
<div class="gutters" aria-hidden="true"></div>

${navHtml(prefix, navActive)}

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

/* Inner <span>s for a result scoreline. `placeClass` adds the .is-place hook
 * used by the homepage / member-page styling; the writeups index leaves it off
 * to match the pre-existing markup. */
function scorelineSpans(ev, placeClass) {
  const r = ev.result;
  const s = [];
  s.push(`<span${placeClass ? ' class="is-place"' : ''}><b>${esc(r.placement)}</b> ${esc(r.league || r.field || '')}</span>`);
  if (r.weight != null) s.push(`<span><b>${r.weight}</b> CTFtime weight</span>`);
  if (r.points != null) s.push(`<span><b>${r.points}</b> points</span>`);
  s.push(`<span><b>${r.solves}</b> solves</span>`);
  const suffix = ev.attribution || ev.org;
  s.push(`<span><b>${esc(ev.team)}</b>${suffix ? ` &middot; ${esc(suffix)}` : ''}</span>`);
  return s.join('\n      ');
}

/* ---------- writeups index ---------- */
function buildIndex() {
  const eventNames = cfg.events.map((e) => e.event).join(' and ');

  const groups = cfg.events
    .map((ev) => {
      const cards = ev.challenges
        .map((c) => `        <li class="wu-card">
          <a class="wu-card-link" href="writeups/${c.slug}.html">
            <div class="wu-card-top">
              <span class="wu-cat wu-cat-${c.category}">${catLabel[c.category] || c.category}</span>
              ${c.points != null ? `<span class="wu-pts">${c.points} pts</span>` : ''}
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

      return `    <div class="wu-eventgroup">
      <div class="wu-eventgroup-head">
        <h2>${esc(ev.event)}</h2>
        <div class="wu-scoreline">
      ${scorelineSpans(ev)}
        </div>
      </div>
      <ul class="wu-grid">
${cards}
      </ul>
    </div>`;
    })
    .join('\n\n');

  const body = `<main id="top">
  <section class="wu-hero container">
    <p class="eyebrow"><span class="dot"></span>NXT_CTFS</p>
    <h1>Writeups</h1>
    <p class="wu-hero-lede">How each challenge was solved, root cause first and then the exploit. Grouped by event.</p>
  </section>

  <section class="section container" style="border-top:none;padding-top:0">
${groups}
    <p class="wu-note">Solve scripts and challenge archives aren't published here. Ask in <a href="https://discord.gg/AnmfSNMvS" target="_blank" rel="noopener noreferrer">Discord</a>. Flags are per-event; some sandbox challenges issued a per-instance flag.</p>
  </section>
</main>`;

  writeFileSync(
    join(root, 'writeups.html'),
    page({
      prefix: '',
      title: 'Writeups · NXT_CTFS',
      desc: `NXT_CTFS challenge writeups for ${eventNames}.`,
      body,
    })
  );
  console.log('wrote writeups.html');
}

/* ---------- detail pages ---------- */
function buildDetail(ev, c, i) {
  const md = readFileSync(join(root, 'writeups/src', `${c.slug}.md`), 'utf8');
  const { html: rendered, toc } = renderBody(md);
  const html = applyGlossary(rendered, glossary);
  const prev = ev.challenges[i - 1];
  const next = ev.challenges[i + 1];

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

  const headTags = [
    `<span class="wu-cat wu-cat-${c.category}">${catLabel[c.category] || c.category}</span>`,
    c.points != null ? `<span class="wu-pts">${c.points} pts</span>` : '',
    c.solved ? `<span class="wu-when">solved ${esc(c.solved)}</span>` : '',
  ].filter(Boolean).join('\n      ');

  const body = `<div class="wu-progress" aria-hidden="true"><div class="wu-progress-bar" id="wuProgress"></div></div>
  <main class="wu-main container" id="top">
  <div class="wu-crumbs"><a href="../index.html#top">nxt_ctfs</a> <span>/</span> <a href="../writeups.html">writeups</a> <span>/</span> <span>${esc(c.slug)}</span></div>

  <header class="wu-head">
    <div class="wu-head-tags">
      ${headTags}
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
      title: `${c.name} · ${ev.event} writeup · NXT_CTFS`,
      desc: c.blurb,
      body,
    })
  );
  console.log(`wrote writeups/${c.slug}.html`);
}

/* ---------- member pages ---------- */
function memberEventBlock(ev) {
  const hasWhen = ev.challenges.some((c) => c.solved);
  const rows = ev.challenges
    .map((c) => `          <tr>
            <th scope="row" class="solve-chal"><a href="../writeups/${c.slug}.html">${esc(c.name)}</a></th>
            <td class="solve-cat"><span class="wu-cat wu-cat-${c.category}">${catLabel[c.category] || c.category}</span></td>
            <td class="solve-pts">${c.points != null ? c.points : ''}</td>
            ${hasWhen ? `<td class="solve-when">${c.solved ? esc(c.solved) : ''}</td>` : ''}
          </tr>`)
    .join('\n');

  const certDims = ev.certW && ev.certH ? ` width="${ev.certW}" height="${ev.certH}"` : '';
  const cert = ev.cert
    ? `      <figure class="cert">
        <img src="../${esc(ev.cert)}"${certDims} alt="${esc(ev.certAlt || ev.event + ' certificate')}" loading="lazy" />
        <figcaption>${esc(ev.event)} &middot; certificate of participation</figcaption>
      </figure>`
    : '';

  return `    <article class="mp-event">
      <div class="mp-event-head">
        <h2>${esc(ev.event)}</h2>
        ${ev.result.date ? `<p class="mp-event-date">${esc(ev.result.date)}</p>` : ''}
      </div>
      <div class="results-scoreline">
      ${scorelineSpans(ev, true)}
      </div>
${cert}
      <div class="table-scroll">
        <table class="solve-table">
          <caption class="sr-only">Challenges solved at ${esc(ev.event)}</caption>
          <thead>
            <tr>
              <th scope="col">Challenge</th>
              <th scope="col">Category</th>
              <th scope="col" style="text-align:right">Points</th>
              ${hasWhen ? '<th scope="col">Solved</th>' : ''}
            </tr>
          </thead>
          <tbody>
${rows}
          </tbody>
        </table>
      </div>
    </article>`;
}

function buildMembers() {
  mkdirSync(join(root, 'members'), { recursive: true });
  const byId = new Map(cfg.events.map((e) => [e.id, e]));

  for (const m of cfg.members) {
    const events = (m.events || []).map((id) => byId.get(id)).filter(Boolean);
    const focus = (m.focus || []).map((f) => `<span class="tag">${esc(f)}</span>`).join('\n        ');
    const linkedin = m.linkedin
      ? `<p class="mp-links"><a href="${esc(m.linkedin)}" target="_blank" rel="noopener noreferrer">LinkedIn <svg class="icon" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M200,64V168a8,8,0,0,1-16,0V83.31L69.66,197.66a8,8,0,0,1-11.32-11.32L172.69,72H88a8,8,0,0,1,0-16H192A8,8,0,0,1,200,64Z"/></svg></a></p>`
      : '';
    const eventsHtml = events.length
      ? events.map(memberEventBlock).join('\n\n')
      : '    <p class="mp-empty">No solo events logged yet.</p>';

    const body = `<main class="mp-main container" id="top">
  <div class="wu-crumbs"><a href="../index.html#top">nxt_ctfs</a> <span>/</span> <a href="../index.html#team">team</a> <span>/</span> <span>${esc(m.slug)}</span></div>

  <header class="mp-head">
    <img class="mp-avatar" src="../${esc(m.avatar)}" alt="${esc(m.handle)}" />
    <div class="mp-id">
      <h1>${esc(m.handle)}${m.tag ? ` <span class="mp-tag">${esc(m.tag)}</span>` : ''}</h1>
      <div class="mp-focus">
        ${focus}
      </div>
      ${[m.bio ? `<p class="mp-bio">${esc(m.bio)}</p>` : '', linkedin].filter(Boolean).join('\n      ')}
    </div>
  </header>

  <section class="mp-events">
${eventsHtml}
  </section>
</main>`;

    writeFileSync(
      join(root, 'members', `${m.slug}.html`),
      page({
        prefix: '../',
        title: `${m.handle} · NXT_CTFS`,
        desc: `${m.handle}, NXT_CTFS. ${m.bio || ''}`.trim(),
        body,
        navActive: 'team',
      })
    );
    console.log(`wrote members/${m.slug}.html`);
  }
}

/* ---------- run ---------- */
buildIndex();
cfg.events.forEach((ev) => ev.challenges.forEach((c, i) => buildDetail(ev, c, i)));
buildMembers();

/* sanity: warn on stray src files not in any event */
const known = new Set(cfg.events.flatMap((ev) => ev.challenges.map((c) => `${c.slug}.md`)));
for (const f of readdirSync(join(root, 'writeups/src'))) {
  if (f.endsWith('.md') && !known.has(f)) console.warn(`! ${f} in writeups/src has no config entry`);
}
