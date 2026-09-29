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
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { renderBody, esc } from './lib/renderer.mjs';
import { applyGlossary } from './lib/glossary.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cfg = JSON.parse(readFileSync(join(root, 'tools/writeups.config.json'), 'utf8'));
const glossary = JSON.parse(readFileSync(join(root, 'tools/glossary.json'), 'utf8'));

/* Cache-busting: every CSS/JS file gets a short content hash in its ?v= query,
 * so a browser refetches exactly when the file changes. */
const CSS_FILES = ['css/fonts.css', 'css/base.css', 'css/components.css', 'css/pages.css'];
const JS_FILES = ['js/script.js'];
const hashOf = (rel) => createHash('sha1').update(readFileSync(join(root, rel))).digest('hex').slice(0, 8);
const cssLinks = (prefix) =>
  CSS_FILES.map((f) => `<link rel="stylesheet" href="${prefix}${f}?v=${hashOf(f)}" />`).join('\n');
const jsTags = (prefix) =>
  JS_FILES.map((f) => `<script src="${prefix}${f}?v=${hashOf(f)}"></script>`).join('\n');

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
      <a href="${prefix}index.html#top" class="brand">
        <img src="${prefix}images/brand/logo.png" alt="NXT_CTFS logo" />
        <span class="brand-name">NXT_CTFS</span>
      </a>
    </div>
    <div class="nav-links">
      <a href="${prefix}writeups.html"${cls('writeups')}>writeups</a>
      <a href="${prefix}index.html#team"${cls('team')}>team</a>
      <a href="${prefix}index.html#shell">try a box</a>
      <a href="${prefix}index.html#join">join</a>
    </div>
    <div class="nav-cta">
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
    <a href="${prefix}writeups.html">writeups</a>
    <a href="${prefix}index.html#team">team</a>
    <a href="${prefix}index.html#shell">try a box</a>
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

/* One header for every subpage: breadcrumb, title, meta line, optional
 * description and extras, all on the same left edge. `lead` is an optional
 * image (member avatar) that sits beside the title block. */
function crumbsHtml(items) {
  const parts = items.map((it, i) =>
    it.href && i < items.length - 1 ? `<a href="${it.href}">${it.label}</a>` : `<span>${it.label}</span>`);
  return `<nav class="crumbs" aria-label="Breadcrumb">${parts.join(' <span aria-hidden="true">/</span> ')}</nav>`;
}

function pageHeader({ crumbs, title, meta = '', desc = '', extra = '', lead = '' }) {
  return `${crumbsHtml(crumbs)}

  <header class="page-head${lead ? ' has-lead' : ''}">
    ${lead}
    <div class="page-head-body">
      <h1>${title}</h1>
      ${meta ? `<div class="page-meta">${meta}</div>` : ''}
      ${desc ? `<p class="page-desc">${desc}</p>` : ''}
      ${extra}
    </div>
  </header>`;
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
${cssLinks(prefix)}
<script>document.documentElement.classList.add('js');</script>
</head>
<body>

${navHtml(prefix, navActive)}

${body}

${footerHtml(prefix)}

${jsTags(prefix)}
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

/* ---------- home page: sections generated between marker comments ---------- */
const ARROW = '<svg class="icon" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M200,64V168a8,8,0,0,1-16,0V83.31L69.66,197.66a8,8,0,0,1-11.32-11.32L172.69,72H88a8,8,0,0,1,0-16H192A8,8,0,0,1,200,64Z"/></svg>';

function eventCards() {
  const recent = [...cfg.events]
    .sort((a, b) => Date.parse(b.result.date) - Date.parse(a.result.date))
    .slice(0, 3);
  const cards = recent
    .map((ev) => {
      const r = ev.result;
      const rest = r.league || r.field || '';
      const solvers = cfg.members.filter((m) => (m.events || []).includes(ev.id)).map((m) => m.handle);
      const who = ev.attribution === 'solo'
        ? `Solo &middot; ${esc((solvers.length ? solvers : [ev.team]).join(', '))}`
        : `Team &middot; ${esc(ev.team)}${ev.org ? `, ${esc(ev.org)}` : ''}`;
      const meta = [`${r.solves} ${r.solves === 1 ? 'solve' : 'solves'}`];
      if (r.points != null) meta.push(`${r.points} points`);
      meta.push(who);
      return `      <li class="event-card">
        <a class="card-link" href="writeups.html#${esc(ev.id)}">
          <p class="event-date">${esc(r.date)}</p>
          <h3 class="event-name">${esc(ev.event)}</h3>
          <p class="event-place"><b>${esc(r.placement)}</b>${rest ? ` ${esc(rest)}` : ''}</p>
          <p class="event-meta">${meta.join(' &middot; ')}</p>
          <span class="card-go">Read writeups ${ARROW}</span>
        </a>
      </li>`;
    })
    .join('\n');
  return `<ul class="event-grid">
${cards}
    </ul>
    <p class="section-more"><a href="writeups.html">All writeups ${ARROW}</a></p>`;
}

function teamCards() {
  const cards = [...cfg.members]
    .sort((a, b) => (a.order ?? 99) - (b.order ?? 99))
    .map((m) => {
      const tags = [
        m.role ? `<span class="tag tag-ghost">${esc(m.role)}</span>` : '',
        ...(m.focus || []).map((f) => `<span class="tag">${esc(f)}</span>`),
      ].filter(Boolean).join('\n            ');
      const status = m.status === 'active' ? '<span class="member-status"><span class="status-dot is-on"></span>Active</span>' : '';
      return `      <li class="member-card">
        <a class="card-link" href="members/${esc(m.slug)}.html">
          <div class="member-top">
            <img class="member-avatar" src="${esc(m.avatar)}" alt="" width="56" height="56" loading="lazy" />
            <div>
              <h3 class="member-name">${esc(m.handle)}</h3>
              ${status}
            </div>
          </div>
          <div class="member-tags">
            ${tags}
          </div>
          <span class="card-go">View page ${ARROW}</span>
        </a>
      </li>`;
    })
    .join('\n');
  return `<ul class="member-grid">
${cards}
    </ul>`;
}

function injectMarkers(file, blocks, indent = '    ') {
  const path = join(root, file);
  let html = readFileSync(path, 'utf8');
  for (const [name, inner] of Object.entries(blocks)) {
    const re = new RegExp(String.raw`<!-- build:${name} -->[\s\S]*?<!-- /build:${name} -->`);
    if (!re.test(html)) throw new Error(`${file} is missing <!-- build:${name} --> markers`);
    html = html.replace(re, () => `<!-- build:${name} -->
${indent}${inner}
${indent}<!-- /build:${name} -->`);
  }
  writeFileSync(path, html);
  console.log(`updated ${file}`);
}

function buildHome() {
  injectMarkers('index.html', { events: eventCards(), team: teamCards(), footer: footerHtml('') });
  injectMarkers('index.html', { css: cssLinks(''), js: jsTags('') }, '');
}

const CAT_ORDER = ['web', 'pwn', 'rev', 'crypto', 'forensics', 'osint', 'ai', 'misc'];

/* ---------- writeups index ---------- */
function buildIndex() {
  const eventNames = cfg.events.map((e) => e.event).join(' and ');
  const total = cfg.events.reduce((n, e) => n + e.challenges.length, 0);
  const cats = CAT_ORDER.filter((k) => cfg.events.some((e) => e.challenges.some((c) => c.category === k)));

  const groups = cfg.events
    .map((ev) => {
      const rows = ev.challenges
        .map((c) => `        <li class="wu-row" data-cat="${c.category}">
          <a class="wu-row-link" href="writeups/${c.slug}.html">
            <span class="wu-row-title"><span class="wu-row-name">${esc(c.name)}</span><span class="wu-row-sub">${esc(c.subtitle)}</span></span>
            <span class="wu-cat wu-cat-${c.category}">${catLabel[c.category] || c.category}</span>
            <span class="wu-row-pts">${c.points != null ? `${c.points} pts` : ''}</span>
            <span class="wu-row-blurb">${esc(c.blurb)}</span>
          </a>
        </li>`)
        .join('\n');

      return `    <div class="wu-eventgroup" id="${ev.id}" data-event="${ev.id}">
      <div class="wu-eventgroup-head">
        <h2>${esc(ev.event)}</h2>
        <div class="wu-scoreline">
      ${scorelineSpans(ev)}
        </div>
        <p class="wu-eventgroup-count" data-count>${ev.challenges.length} ${ev.challenges.length === 1 ? 'writeup' : 'writeups'}</p>
      </div>
      <ul class="wu-list-rows">
${rows}
      </ul>
    </div>`;
    })
    .join('\n\n');

  const chip = (attr, value, label, extraClass = '', pressed = false) =>
    `<button type="button" class="chip${extraClass}" ${attr}="${value}" aria-pressed="${pressed}">${label}</button>`;

  const filters = `<div class="wu-filters" role="group" aria-label="Filter writeups">
      <div class="wu-filter-row">
        <span class="wu-filter-label" id="fCatLabel">Category</span>
        <div class="wu-filter-chips" role="group" aria-labelledby="fCatLabel">
          ${[chip('data-cat', 'all', 'All', '', true), ...cats.map((k) => chip('data-cat', k, catLabel[k] || k, ` chip-dot wu-cat-${k}`))].join('\n          ')}
        </div>
      </div>
      <div class="wu-filter-row">
        <span class="wu-filter-label" id="fEventLabel">Event</span>
        <div class="wu-filter-chips" role="group" aria-labelledby="fEventLabel">
          ${[chip('data-event', 'all', 'All', '', true), ...cfg.events.map((e) => chip('data-event', e.id, esc(e.event)))].join('\n          ')}
        </div>
      </div>
      <p class="wu-count" id="wuCount" aria-live="polite">${total} writeups</p>
    </div>`;

  const header = pageHeader({
    crumbs: [{ href: 'index.html#top', label: 'nxt_ctfs' }, { label: 'writeups' }],
    title: 'Writeups',
    meta: `${total} writeups across ${cfg.events.length} events`,
    desc: 'How each challenge was solved, root cause first and then the exploit. Grouped by event.',
  });

  const body = `<main class="page-main container" id="top">
  ${header}

  ${filters}

  <div class="wu-groups" id="wuGroups">
${groups}
  </div>
  <p class="wu-empty" id="wuEmpty" hidden>No writeups match these filters.</p>
  <p class="wu-note">Solve scripts and challenge archives aren't published here. Ask in <a href="https://discord.gg/AnmfSNMvS" target="_blank" rel="noopener noreferrer">Discord</a>.</p>
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

  const headMeta = [
    `<span class="wu-cat wu-cat-${c.category}">${catLabel[c.category] || c.category}</span>`,
    c.points != null ? `<span>${c.points} pts</span>` : '',
    c.solved ? `<span>solved ${esc(c.solved)}</span>` : '',
  ].filter(Boolean).join('\n      ');

  const header = pageHeader({
    crumbs: [{ href: '../index.html#top', label: 'nxt_ctfs' }, { href: '../writeups.html', label: 'writeups' }, { label: esc(c.slug) }],
    title: `${esc(c.name)} <span class="page-sub">${esc(c.subtitle)}</span>`,
    meta: headMeta,
    extra: `<div class="wu-flagrow">
        <span class="wu-flagrow-k">flag</span>
        <code id="wuFlag">${esc(c.flag)}</code>
        <button type="button" class="wu-copy" data-copy="#wuFlag" aria-label="Copy flag">copy</button>
      </div>`,
  });

  const body = `<div class="wu-progress" aria-hidden="true"><div class="wu-progress-bar" id="wuProgress"></div></div>
  <main class="page-main container" id="top">
  ${header}

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
    ? `<figure class="cert-thumb">
          <a href="../${esc(ev.cert)}" data-lightbox aria-label="View certificate full size">
            <img src="../${esc(ev.cert)}"${certDims} alt="${esc(ev.certAlt || ev.event + ' certificate')}" loading="lazy" />
          </a>
          <figcaption>Certificate of participation</figcaption>
        </figure>`
    : '';

  return `    <article class="mp-event">
      <div class="mp-event-head">
        <h2>${esc(ev.event)}</h2>
        ${ev.result.date ? `<p class="mp-event-date">${esc(ev.result.date)}</p>` : ''}
      </div>
      <div class="mp-event-summary">
        <div class="results-scoreline">
      ${scorelineSpans(ev, true)}
        </div>
        ${cert}
      </div>
      <div class="table-scroll">
        <table class="data-table solve-table">
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
    const focus = (m.focus || []).map((f) => `<span class="tag">${esc(f)}</span>`).join('\n      ');
    const linkedin = m.linkedin
      ? `<p class="mp-links"><a href="${esc(m.linkedin)}" target="_blank" rel="noopener noreferrer">LinkedIn <svg class="icon" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M200,64V168a8,8,0,0,1-16,0V83.31L69.66,197.66a8,8,0,0,1-11.32-11.32L172.69,72H88a8,8,0,0,1,0-16H192A8,8,0,0,1,200,64Z"/></svg></a></p>`
      : '';
    const eventsHtml = events.length
      ? events.map(memberEventBlock).join('\n\n')
      : '    <p class="mp-empty">No solo events logged yet.</p>';

    const header = pageHeader({
      crumbs: [{ href: '../index.html#top', label: 'nxt_ctfs' }, { href: '../index.html#team', label: 'team' }, { label: esc(m.slug) }],
      title: `${esc(m.handle)}${m.tag ? ` <span class="mp-tag">${esc(m.tag)}</span>` : ''}`,
      meta: focus,
      desc: m.bio ? esc(m.bio) : '',
      extra: linkedin,
      lead: `<img class="mp-avatar" src="../${esc(m.avatar)}" alt="${esc(m.handle)}" />`,
    });

    const lightbox = `<dialog class="lightbox" id="lightbox" aria-label="Certificate">
  <button type="button" class="lightbox-close" aria-label="Close">&times;</button>
  <img class="lightbox-img" alt="" />
</dialog>`;

    const body = `<main class="page-main container" id="top">
  ${header}

  <section class="mp-events">
${eventsHtml}
  </section>
  ${lightbox}
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
buildHome();
buildIndex();
cfg.events.forEach((ev) => ev.challenges.forEach((c, i) => buildDetail(ev, c, i)));
buildMembers();

/* sanity: warn on stray src files not in any event */
const known = new Set(cfg.events.flatMap((ev) => ev.challenges.map((c) => `${c.slug}.md`)));
for (const f of readdirSync(join(root, 'writeups/src'))) {
  if (f.endsWith('.md') && !known.has(f)) console.warn(`! ${f} in writeups/src has no config entry`);
}
