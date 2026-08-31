/* Container-directive pre-processor for writeup markdown.
 *
 * Syntax:
 *   ::: <type> [inline argument]
 *   markdown content
 *   :::
 *
 * Fence-aware (a ::: line inside a ``` or ~~~ fence is inert) and supports
 * nesting. Two parse modes per directive name:
 *
 *   - "tree"  (default) - children are recursively parsed into text/directive
 *     nodes, so plain markdown and further nested directives both work.
 *   - "raw"   (RAW_CAPTURE_NAMES) - children are kept as one raw markdown
 *     string, for directives (steps, tabs, annotate) that need to slice their
 *     body themselves (e.g. by top-level ### headings) before recursing.
 *
 * Unprocessed (e.g. if this module is skipped), the ::: delimiters are just
 * plain text lines, so source files stay readable as plain markdown.
 */

const FENCE_LINE_RE = /^\s*(`{3,}|~{3,})/;
const OPEN_RE = /^:::\s*([\w-]+)(?:\s+(.*?))?\s*$/;
const CLOSE_RE = /^:::\s*$/;

export const RAW_CAPTURE_NAMES = new Set(['steps', 'tabs', 'annotate']);

/* Walk lines from `pos`, tracking fence state, until an unmatched closing
 * `:::` (or end of input). Returns the joined raw text and the new pos,
 * with the closing line consumed. */
function captureRaw(lines, start) {
  let pos = start;
  let depth = 0;
  let fence = null;
  const buf = [];
  while (pos < lines.length) {
    const line = lines[pos];
    if (fence) {
      buf.push(line);
      if (line.trim() === fence) fence = null;
      pos++;
      continue;
    }
    const fm = line.match(FENCE_LINE_RE);
    if (fm) {
      fence = fm[1];
      buf.push(line);
      pos++;
      continue;
    }
    if (CLOSE_RE.test(line)) {
      if (depth === 0) {
        pos++;
        return { body: buf.join('\n'), pos };
      }
      depth--;
      buf.push(line);
      pos++;
      continue;
    }
    if (OPEN_RE.test(line)) depth++;
    buf.push(line);
    pos++;
  }
  return { body: buf.join('\n'), pos };
}

/* Parse a run of lines (from `start`) into a node tree. `stopAtClose`
 * governs whether an unmatched `:::` line ends this block (true while
 * inside a directive) or is left as plain text (top level). */
function parseBlock(lines, start, stopAtClose) {
  let pos = start;
  const nodes = [];
  let textBuf = [];
  let fence = null;

  const flushText = () => {
    if (textBuf.length) {
      nodes.push({ type: 'text', raw: textBuf.join('\n') });
      textBuf = [];
    }
  };

  while (pos < lines.length) {
    const line = lines[pos];

    if (fence) {
      textBuf.push(line);
      if (line.trim() === fence) fence = null;
      pos++;
      continue;
    }
    const fm = line.match(FENCE_LINE_RE);
    if (fm) {
      fence = fm[1];
      textBuf.push(line);
      pos++;
      continue;
    }
    if (stopAtClose && CLOSE_RE.test(line)) {
      pos++;
      flushText();
      return { nodes, pos };
    }
    const om = line.match(OPEN_RE);
    if (om) {
      flushText();
      const name = om[1];
      const arg = om[2] || '';
      pos++;
      if (RAW_CAPTURE_NAMES.has(name)) {
        const { body, pos: nextPos } = captureRaw(lines, pos);
        nodes.push({ type: 'directive', name, arg, raw: body });
        pos = nextPos;
      } else {
        const { nodes: children, pos: nextPos } = parseBlock(lines, pos, true);
        nodes.push({ type: 'directive', name, arg, children });
        pos = nextPos;
      }
      continue;
    }
    textBuf.push(line);
    pos++;
  }
  flushText();
  return { nodes, pos };
}

export function parseDirectives(md) {
  const lines = md.split(/\r?\n/);
  return parseBlock(lines, 0, false).nodes;
}

/* Render a node tree to HTML. `renderMarkdown(text)` renders a plain
 * markdown string (used for text nodes and, recursively, for raw directive
 * bodies split by the directive renderer). `renderDirective(node, ctx)`
 * renders one directive node to HTML; ctx exposes renderChildren/renderRaw
 * so directive renderers can recurse without importing this module. */
export function renderTree(nodes, renderMarkdown, renderDirective) {
  const ctx = {
    renderChildren: (children) => renderTree(children, renderMarkdown, renderDirective),
    renderMarkdown,
    parseDirectives,
  };
  return nodes
    .map((n) => (n.type === 'text' ? renderMarkdown(n.raw) : renderDirective(n, ctx)))
    .join('\n');
}

/* Fence-and-directive-aware scan for top-level lines matching `re` inside a
 * raw directive body (used to split ::: steps / ::: tabs bodies by ### headings
 * without tripping on a ### inside a nested directive or a fenced code block). */
export function splitTopLevel(raw, re) {
  const lines = raw.split(/\r?\n/);
  const marks = [];
  let fence = null;
  let depth = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (fence) {
      if (line.trim() === fence) fence = null;
      continue;
    }
    const fm = line.match(FENCE_LINE_RE);
    if (fm) {
      fence = fm[1];
      continue;
    }
    if (CLOSE_RE.test(line)) {
      if (depth > 0) depth--;
      continue;
    }
    if (OPEN_RE.test(line)) {
      depth++;
      continue;
    }
    if (depth === 0) {
      const m = line.match(re);
      if (m) marks.push({ line: i, match: m });
    }
  }

  const segments = [];
  if (marks.length === 0) return { intro: raw.trim() ? raw : '', segments };

  const introLines = lines.slice(0, marks[0].line);
  const intro = introLines.join('\n').trim();

  for (let i = 0; i < marks.length; i++) {
    const from = marks[i].line + 1;
    const to = i + 1 < marks.length ? marks[i + 1].line : lines.length;
    segments.push({
      heading: marks[i].match[1] ? marks[i].match[1].trim() : '',
      raw: lines.slice(from, to).join('\n'),
    });
  }
  return { intro, segments };
}
