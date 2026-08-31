/* Markdown -> writeup-article-HTML pipeline: marked renderer overrides
 * (syntax-highlighted code, heading anchors/TOC), the ::: directive
 * renderers (admonitions, spoilers, annotated code, steps, tabs), and the
 * ```session fence. Build-time only; ships as static pre-rendered HTML. */
import { marked } from '../vendor/marked.esm.js';
import hljs from '../vendor/highlight-core.js';
import hljsBash from '../vendor/hljs-lang/bash.js';
import hljsPython from '../vendor/hljs-lang/python.js';
import hljsC from '../vendor/hljs-lang/c.js';
import hljsJavascript from '../vendor/hljs-lang/javascript.js';
import hljsJson from '../vendor/hljs-lang/json.js';
import hljsX86asm from '../vendor/hljs-lang/x86asm.js';
import { parseDirectives, renderTree, splitTopLevel } from './directives.mjs';

hljs.registerLanguage('bash', hljsBash);
hljs.registerLanguage('sh', hljsBash);
hljs.registerLanguage('shell', hljsBash);
hljs.registerLanguage('python', hljsPython);
hljs.registerLanguage('py', hljsPython);
hljs.registerLanguage('c', hljsC);
hljs.registerLanguage('javascript', hljsJavascript);
hljs.registerLanguage('js', hljsJavascript);
hljs.registerLanguage('json', hljsJson);
hljs.registerLanguage('x86asm', hljsX86asm);
hljs.registerLanguage('asm', hljsX86asm);

const LANG_LABEL = {
  bash: 'bash', sh: 'bash', shell: 'bash',
  python: 'python', py: 'python',
  c: 'c',
  javascript: 'js', js: 'js',
  json: 'json',
  x86asm: 'asm', asm: 'asm',
};

export const esc = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const escAttr = (s) => esc(s).replace(/\n/g, ' ');

const slugifyBase = (s) =>
  s.toLowerCase().trim().replace(/&[a-z]+;/g, '').replace(/[^\w\s-]/g, '').replace(/[\s_]+/g, '-').replace(/-+/g, '-');

/* ---------- per-page state (reset before each renderBody call) ---------- */
let codeBlockId = 0;
let usedSlugs = null;
let toc = null;

function resetPage() {
  codeBlockId = 0;
  usedSlugs = new Set();
  toc = [];
}

function slugify(text) {
  let id = slugifyBase(text) || 'section';
  if (usedSlugs.has(id)) {
    let n = 2;
    while (usedSlugs.has(`${id}-${n}`)) n++;
    id = `${id}-${n}`;
  }
  usedSlugs.add(id);
  return id;
}

/* ---------- line-aware syntax highlighting ---------- */

/* Re-wrap highlighted (or plain) HTML per source line, keeping <span> nesting
 * balanced across line breaks, so every line can carry its own data-line and
 * a gutter number without breaking multi-line hljs spans (block comments,
 * triple-quoted strings, ...). */
function wrapLines(html) {
  const rawLines = html.split('\n');
  const stack = [];
  const tagRe = /<span class="([^"]*)">|<\/span>/g;
  return rawLines.map((raw) => {
    let line = stack.map((t) => t).join('');
    let idx = 0;
    let m;
    tagRe.lastIndex = 0;
    while ((m = tagRe.exec(raw))) {
      line += raw.slice(idx, m.index);
      if (m[0] === '</span>') {
        stack.pop();
        line += '</span>';
      } else {
        stack.push(m[0]);
        line += m[0];
      }
      idx = tagRe.lastIndex;
    }
    line += raw.slice(idx);
    for (let i = 0; i < stack.length; i++) line += '</span>';
    return line;
  });
}

function parseInfo(infostring) {
  const info = (infostring || '').trim();
  const m = info.match(/^([\w+-]*)\s*(?:title="([^"]*)")?/);
  return { lang: (m && m[1]) || '', title: (m && m[2]) || '' };
}

/* Renders one fenced code block as a `.wu-code` figure: language label,
 * optional title, a copy button (reuses the generic .wu-copy[data-copy]
 * handler in js/script.js), and, for a recognized language, highlighted
 * + line-numbered markup. opts.forceLineWrap/opts.noCollapse are for the
 * ::: annotate directive, which needs per-line targeting even on an
 * unrecognized language and must never collapse an annotated block. */
export function renderCodeFigure(code, infostring, opts = {}) {
  const { lang, title } = parseInfo(infostring);
  const known = lang && hljs.getLanguage(lang);
  codeBlockId += 1;
  const id = `code-${codeBlockId}`;
  const body = code.replace(/\n$/, '');
  const rawLines = body.split('\n');
  const lineCount = rawLines.length;

  let bodyHtml;
  const shouldLineWrap = known || opts.forceLineWrap;
  if (known) {
    const { value } = hljs.highlight(body, { language: lang, ignoreIllegals: true });
    const lines = wrapLines(value);
    bodyHtml = lines
      .map((l, i) => `<span class="wu-line" data-line="${i + 1}"><span class="wu-ln">${i + 1}</span><span class="wu-lc">${l}</span></span>`)
      .join('\n');
  } else if (opts.forceLineWrap) {
    bodyHtml = rawLines
      .map((l, i) => `<span class="wu-line" data-line="${i + 1}"><span class="wu-ln">${i + 1}</span><span class="wu-lc">${esc(l)}</span></span>`)
      .join('\n');
  } else {
    bodyHtml = esc(body);
  }

  const collapsible = !opts.noCollapse && lineCount > 25;
  const langLabel = known ? (LANG_LABEL[lang] || esc(lang)) : lang ? esc(lang) : 'output';
  const titleHtml = title ? `<span class="wu-code-title">${esc(title)}</span>` : '';
  const classes = ['wu-code'];
  if (!known) classes.push('wu-code-output');
  if (collapsible) classes.push('is-collapsible');

  return `<figure class="${classes.join(' ')}" data-lines="${lineCount}">
      <figcaption>
        ${titleHtml}
        <span class="wu-code-lang">${langLabel}</span>
        <button type="button" class="wu-copy" data-copy="#${id}" aria-label="Copy code">copy</button>
      </figcaption>
      <pre id="${id}"><code class="language-${esc(lang || 'text')}">${bodyHtml}</code></pre>
      ${collapsible ? `<button type="button" class="wu-code-more" aria-expanded="false" data-more="+${lineCount - 12} lines" data-less="show less">+${lineCount - 12} lines</button>` : ''}
    </figure>`;
}

/* ---------- ```session fence: a static, replayable terminal transcript --- */
function renderSession(body) {
  const lines = body.replace(/\n$/, '').split('\n');
  const rows = lines.map((raw) => {
    if (raw.startsWith('$ ')) {
      return `<span class="wu-term-line" data-kind="cmd"><span class="wu-term-prompt">$</span><span class="wu-term-cmd">${esc(raw.slice(2))}</span></span>`;
    }
    return `<span class="wu-term-line" data-kind="out">${esc(raw) || '&nbsp;'}</span>`;
  });
  return `<div class="wu-session">
      <div class="wu-session-bar">
        <span class="wu-session-label">session</span>
        <button type="button" class="wu-session-replay">replay</button>
      </div>
      <pre class="wu-session-body">${rows.join('\n')}</pre>
    </div>`;
}

/* ---------- directive renderers ---------- */

const ADMON_LABEL = { insight: 'Insight', pitfall: 'Pitfall', note: 'Note' };

function renderAdmonition(node, ctx) {
  const label = ADMON_LABEL[node.name] || node.name;
  return `<div class="wu-admon wu-admon-${node.name}">
      <p class="wu-admon-h">${esc(node.arg) || label}</p>
      ${ctx.renderChildren(node.children)}
    </div>`;
}

function renderSpoiler(node, ctx) {
  const summary = node.arg ? esc(node.arg) : 'Reveal';
  return `<details class="wu-spoiler">
      <summary>${summary}</summary>
      <div class="wu-spoiler-body">${ctx.renderChildren(node.children)}</div>
    </details>`;
}

const FENCE_RE = /^(`{3,}|~{3,})([^\n]*)\n([\s\S]*?)\n\1[ \t]*$/m;
const NOTE_RE = /^[ \t]*(\d+)\.\s+(.+)$/gm;

function renderAnnotate(node) {
  const raw = node.raw || '';
  const fm = raw.match(FENCE_RE);
  if (!fm) {
    return `<div class="wu-admon wu-admon-note"><p class="wu-admon-h">Note</p><p>Malformed ::: annotate block: no fenced code found.</p></div>`;
  }
  const [, , infostring, code] = fm;
  const codeHtml = renderCodeFigure(code, infostring, { forceLineWrap: true, noCollapse: true });
  const notesSrc = raw.slice(fm.index + fm[0].length);
  const notes = [];
  let m;
  NOTE_RE.lastIndex = 0;
  while ((m = NOTE_RE.exec(notesSrc))) {
    notes.push({ line: m[1], text: marked.parseInline(m[2]) });
  }
  const markedLines = new Set(notes.map((n) => n.line));
  const markedCode = codeHtml.replace(
    /<span class="wu-line" data-line="(\d+)">/g,
    (full, n) => (markedLines.has(n) ? `<span class="wu-line wu-line-marked" data-line="${n}">` : full)
  );
  const notesHtml = notes
    .map((n) => `<li class="wu-annotate-note" data-line="${n.line}"><span class="wu-annotate-ln">${n.line}</span><span class="wu-annotate-text">${n.text}</span></li>`)
    .join('');
  return `<div class="wu-annotate">
      ${markedCode}
      <ol class="wu-annotate-notes">${notesHtml}</ol>
    </div>`;
}

function renderSteps(node, ctx) {
  const { intro, segments } = splitTopLevel(node.raw || '', /^###\s+(.*)$/);
  if (!segments.length) return ctx.renderMarkdown(node.raw || '');
  const n = segments.length;
  const introHtml = intro ? ctx.renderMarkdown(intro) : '';
  const dots = segments
    .map((s, i) => `<button type="button" class="wu-step-dot" role="tab" aria-selected="${i === 0}" data-step="${i}">${i + 1}</button>`)
    .join('');
  const panels = segments
    .map((s, i) => {
      const inner = renderTree(parseDirectives(s.raw), ctx.renderMarkdown, dispatchDirective);
      return `<section class="wu-step${i === 0 ? ' is-current' : ''}" data-step="${i}">
          <h4 class="wu-step-title"><span class="wu-step-num">${i + 1}/${n}</span>${esc(s.heading)}</h4>
          ${inner}
        </section>`;
    })
    .join('');
  return `<div class="wu-steps">
      ${introHtml}
      <div class="wu-steps-nav" role="tablist" aria-label="Steps">${dots}</div>
      <div class="wu-steps-body">${panels}</div>
      <div class="wu-steps-controls">
        <button type="button" class="wu-step-prev">&larr; prev</button>
        <button type="button" class="wu-step-showall">show all</button>
        <button type="button" class="wu-step-next">next &rarr;</button>
      </div>
    </div>`;
}

let tabsId = 0;
function renderTabs(node, ctx) {
  const { intro, segments } = splitTopLevel(node.raw || '', /^###\s+(.*)$/);
  if (!segments.length) return ctx.renderMarkdown(node.raw || '');
  tabsId += 1;
  const gid = `wu-tabs-${tabsId}`;
  const introHtml = intro ? ctx.renderMarkdown(intro) : '';
  const tabs = segments
    .map((s, i) => `<button type="button" class="wu-tab${i === 0 ? ' is-current' : ''}" role="tab" aria-selected="${i === 0}" id="${gid}-tab-${i}" aria-controls="${gid}-panel-${i}" data-tab="${i}">${esc(s.heading)}</button>`)
    .join('');
  const panels = segments
    .map((s, i) => {
      const inner = renderTree(parseDirectives(s.raw), ctx.renderMarkdown, dispatchDirective);
      return `<div class="wu-tabpanel${i === 0 ? ' is-current' : ''}" role="tabpanel" id="${gid}-panel-${i}" aria-labelledby="${gid}-tab-${i}" data-tab="${i}">${inner}</div>`;
    })
    .join('');
  return `<div class="wu-tabs" id="${gid}">
      ${introHtml}
      <div class="wu-tabs-nav" role="tablist">${tabs}</div>
      <div class="wu-tabs-body">${panels}</div>
    </div>`;
}

function dispatchDirective(node, ctx) {
  switch (node.name) {
    case 'insight':
    case 'pitfall':
    case 'note':
      return renderAdmonition(node, ctx);
    case 'spoiler':
      return renderSpoiler(node, ctx);
    case 'annotate':
      return renderAnnotate(node);
    case 'steps':
      return renderSteps(node, ctx);
    case 'tabs':
      return renderTabs(node, ctx);
    default:
      return `<div class="wu-admon wu-admon-note"><p class="wu-admon-h">Unknown directive: ${esc(node.name)}</p></div>`;
  }
}

/* ---------- marked wiring ---------- */

marked.setOptions({ gfm: true, breaks: false });
marked.use({
  renderer: {
    code(code, infostring) {
      const { lang } = parseInfo(infostring);
      if (lang === 'session') return renderSession(code);
      return renderCodeFigure(code, infostring);
    },
    heading(text, level, raw) {
      if (level !== 2 && level !== 3) return `<h${level}>${text}</h${level}>\n`;
      const bare = text.replace(/<[^>]+>/g, '');
      const id = slugify(bare.replace(/&[a-z]+;/g, ' '));
      toc.push({ id, text: bare, level });
      return `<h${level} id="${id}"><a class="wu-anchor" href="#${id}" aria-hidden="true">#</a>${text}</h${level}>\n`;
    },
  },
});

function renderMarkdown(md) {
  return marked.parse(md);
}

/* ---------- public entry points ---------- */

/* Angle-bracket placeholders like <hex>, <R>, <instance-id> are common in
 * these writeups' prose. Outside code they'd be dropped as unknown HTML
 * tags, so shield them, but only alnum-led tokens, to leave blockquote
 * markers and `a < b` alone. */
export function shieldPlaceholders(md) {
  return md
    .split(/(```[\s\S]*?```|`[^`]*`)/)
    .map((part, i) => (i % 2 ? part : part.replace(/<([A-Za-z0-9_][^<>\n]*?)>/g, '&lt;$1&gt;')))
    .join('');
}

/* Split the meta block (everything before the first horizontal rule) from
 * the body. */
export function splitFrontMatter(md) {
  const lines = md.split(/\r?\n/);
  const idx = lines.findIndex((l, i) => i > 0 && l.trim() === '---');
  if (idx === -1) return md;
  return lines.slice(idx + 1).join('\n').trim();
}

export function renderBody(md) {
  resetPage();
  const shielded = shieldPlaceholders(splitFrontMatter(md));
  const nodes = parseDirectives(shielded);
  const html = renderTree(nodes, renderMarkdown, dispatchDirective);
  return { html, toc };
}
