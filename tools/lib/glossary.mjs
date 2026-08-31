/* Wraps the first occurrence of each glossary term (per page) in a
 * <button class="wu-gloss"> with a definition, skipping anything inside
 * <code>, <pre>, <a>, headings and figcaptions. Runs on already-rendered
 * article HTML (post-markdown, post-directives), same tag/text splitting
 * technique as shieldPlaceholders in build-writeups.mjs. */

const SKIP_OPEN = /^<(code|pre|a|h1|h2|h3|h4|figcaption|button)\b/i;
const SKIP_CLOSE = /^<\/(code|pre|a|h1|h2|h3|h4|figcaption|button)>/i;
const TAG_RE = /(<[^>]+>)/;

const escAttr = (s) =>
  s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function applySegment(text, entries, used) {
  let result = '';
  let cursor = 0;
  while (cursor < text.length) {
    let best = null;
    for (const { term, def } of entries) {
      if (used.has(term)) continue;
      const re = new RegExp(`\\b${escapeRegExp(term)}\\b`, 'i');
      const m = re.exec(text.slice(cursor));
      if (m) {
        const idx = cursor + m.index;
        if (!best || idx < best.index) best = { index: idx, len: m[0].length, term, def, matchText: m[0] };
      }
    }
    if (!best) {
      result += text.slice(cursor);
      break;
    }
    result += text.slice(cursor, best.index);
    result += `<button type="button" class="wu-gloss" data-def="${escAttr(best.def)}">${best.matchText}</button>`;
    used.add(best.term);
    cursor = best.index + best.len;
  }
  return result;
}

/* glossary: array of { term, def }, longest term first (so "TreeEnsembleClassifier"
 * is tried before a shorter substring term would ever get a chance to collide). */
export function applyGlossary(html, glossary) {
  if (!glossary.length) return html;
  const entries = [...glossary].sort((a, b) => b.term.length - a.term.length);
  const used = new Set();
  const parts = html.split(TAG_RE);
  let skipDepth = 0;
  return parts
    .map((part) => {
      if (TAG_RE.test(part)) {
        if (SKIP_OPEN.test(part) && !part.endsWith('/>')) skipDepth++;
        else if (SKIP_CLOSE.test(part)) skipDepth = Math.max(0, skipDepth - 1);
        return part;
      }
      if (skipDepth > 0 || !part) return part;
      return applySegment(part, entries, used);
    })
    .join('');
}
