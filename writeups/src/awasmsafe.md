# awasmsafe

**Event:** Kaspersky CTF 2026
**Category:** reverse engineering
**Points:** 74 (88 at time of writing, 186 solves)
**Flag:** `kaspersky{w4sm_3lectrif1ed_7d19ae15}`

---

> "We're ordered a new secret-keeping machine! The whole safe-machine, believe
> it! A massive terminal just to keep confidential info secure. They say it
> has highest-grade protection made just for us! Amazing!"

The challenge ships two files: `awasmsafe_<hash>.exe` and
`awasmsafe_<hash>.AppImage`. Both are just platform builds of the same
Electron app - a fake CRT-terminal "safe" that asks for a password before
letting you `read`/`store` a secret.

## 1. Getting the source out

Electron apps package their JS/HTML/assets into an `app.asar` archive next
to the native binary. Extracting the Linux build:

```bash
./awasmsafe_*.AppImage --appimage-extract
npx asar extract squashfs-root/resources/app.asar app_extracted
```

That yields three files: `package.json`, `index.js` (the Electron main
process - just boilerplate that creates a `BrowserWindow` with
`nodeIntegration:false, contextIsolation:true, sandbox:true` and loads
`safe.html`), and `safe.html`, the entire app.

`safe.html` is a single page: a CSS-heavy fake CRT terminal, and two
`<script>` blocks.

- **Script 1** sets `window.codeBuffer = new Uint8Array([...])`, a large
  byte array.
- **Script 2** is the terminal emulator: handles typing/printing, and an
  `init()` that gzip-decompresses `codeBuffer`, `WebAssembly.instantiate`s
  it, and exposes the result as `window.checkFlag`:

```js
window.checkFlag = (flag) =>
  instance.exports.check_flag(window.return((new TextEncoder()).encode(flag)));
```

So the actual password check is not in JavaScript at all - it's compiled to
WebAssembly. The only import the module needs is a single generic callback:

```js
const { instance } = await WebAssembly.instantiate(await decompress(codeBuffer), {
  env: { e: (c => eval(wgs(c))), memory }
});
```

`env.e` reads a null-terminated string out of WASM linear memory and
`eval()`s it in the page. That's the module's entire escape hatch back into
JS - and it turns out to matter a lot.

## 2. Pulling the WASM apart

```python
import re, gzip
m = re.search(r'window\.codeBuffer = new Uint8Array\(\[([\d,]+)\]\)', html)
wasm = gzip.decompress(bytes(int(x) for x in m.group(1).split(',')))
```

12,995 bytes, exporting only `check_flag`, `malloc`, `free`. Disassembling
with `wabt` (`wasm2wat`) gives ~5,200 lines of `.wat`, clearly compiled C,
not hand-written, complete with an optimized SWAR `strlen`, a `memcmp`, and
a from-scratch RC4 and a small LCG PRNG. `check_flag` itself is a thin
wrapper: `local.get 0; call 9; call 23`, all the real work is in `func 9`.

Reading `func 9` end to end:

1. Requires the input to be **exactly 36 bytes** (`strlen(input) == 36`,
   otherwise bail out immediately).
2. `env.e(67504)` evaluates a string that turns out to be
   `"(typeof global).length"`, and stores the numeric result as the seed
   of the LCG at address `67580`.
3. Copies a static 36-byte ciphertext blob (address `67536`) into a scratch
   buffer, then XORs it byte-by-byte against the LCG's output stream. Call
   this `decrypted_target`.
4. `env.e(<dynamic buffer>)` evaluates a *second*, much longer string
   (187 bytes, itself decrypted in-place by a helper cipher before use).
   The numeric result of this eval is stored as a 32-byte "key" pointer,
   `r`.
5. Calls a function matching the exact signature `(data, datalen, key,
   keylen, out)` with `(input, 36, r, 32, scratch)` - this is `func 2`,
   which on inspection is textbook **RC4**: standard KSA over 256 bytes
   using `r` as the key, then PRGA XOR-ing `input` into `scratch`.
6. `memcmp(scratch, decrypted_target, 36) == 0` → return true.

So: `RC4(key = r, data = password) == decrypted_target`. Two unknowns: the
seed for step 2, and the string evaluated in step 4.

## 3. What actually gets `eval`'d

Dumping WASM linear memory at address `67504` after instantiation shows the
plaintext string directly:

```
(typeof global).length
```

This is a deliberate anti-Node-analysis trick. In a real browser or
Electron *renderer* (which is what actually runs this page -
`nodeIntegration:false` means there is no Node `global`), `typeof global`
evaluates to `"undefined"` (`typeof` never throws on an unresolved
identifier) - length **9**. Under Node.js, where `global` genuinely exists
as an object, it's `"object"`, length **6**. Whoever dumps this WASM and
just runs it in `node` gets silently fed the wrong PRNG seed and will never
recover the right value, with no error to tip them off.

There's a second, more direct anti-Node measure elsewhere in the module's
startup code (traced separately): one of the `eval`'d strings is literally

```js
try { process.exit(1) } catch (e) {  }
```

In Node, `process` exists, so this instantly kills the analysis process. In
a real browser, `process` doesn't exist, the `ReferenceError` is caught,
and it's a no-op. (Direct `eval` inherits the caller's lexical scope, so
this can be defeated by locally shadowing `process`, but it's a strong
signal the challenge wants you in a real renderer, not Node.)

The big 187-byte string (step 4 above), once decrypted by the WASM's own
helper cipher, turns out to be:

```js
window.return(h(
  document.querySelectorAll('script')[1].textContent,
  document.querySelectorAll('*')[5].content?.split(' ')[1]?.slice(8,-1)
  || 'Gn8FyC3e2b2zK/pAXa0HXHOZaEa7Z1h2DbAzZO25YXk='
))
```

with `window.h` defined back in `safe.html` as:

```js
window.h = (d, s) => {
  var r = Uint8Array.fromBase64(s);
  for (var i = 0; i < d.length; i++) r[i % r.length] += d.charCodeAt(i);
  return r;
};
```

This is a **self-referential key**: it's derived from the app's own shipped
source text, at runtime, from inside the running page.

- `document.querySelectorAll('script')[1].textContent` is the literal
  source of Script 2 - the terminal-emulator code itself.
- `document.querySelectorAll('*')[5]` is the 6th element in the document in
  document order. Counting `<html> <head> <meta charset> <title> <meta
  viewport> <meta CSP>`, index 5 is the page's own
  `<meta http-equiv="Content-Security-Policy" content="script-src
  'sha256-XXXX...' 'sha256-YYYY...' 'unsafe-eval';">` tag.
  `.content.split(' ')[1].slice(8,-1)` strips `'sha256-` and the trailing
  `'`, yielding the first base64 SHA-256 hash verbatim.
- `h(d, s)`: base64-decode the CSP hash into 32 bytes, then add (mod 256,
  via `Uint8Array` wraparound) every character code of the entire second
  `<script>` block's source into it, cyclically. `window.return(...)`
  mallocs a WASM buffer, copies those 32 bytes in, and returns the pointer,
  which is exactly the `r` that `func 9` uses as the RC4 key.

Neat: the "key" is baked directly into the page's own markup and its own
JS source, but *deriving* it correctly requires actually being a browser
DOM evaluating that page, not a static blob sitting on disk.

## 4. The part that actually breaks naive reversing

There's a third piece, easy to miss if you only trace `check_flag`
directly: earlier in the module's startup (`func 5`, run automatically as
the WASM `start` function, before `check_flag` is ever called), there's a
loop that evaluates **~55 more strings**, one per iteration, all of the
form:

```
window.toString().replaceAll(/\n| /g,'').length
document.toString().replaceAll(/\n| /g,'').length
navigator.toString().replaceAll(/\n| /g,'').length
HTMLElement.toString().replaceAll(/\n| /g,'').length
WebGLRenderingContext.toString().replaceAll(/\n| /g,'').length
RTCPeerConnection.toString().replaceAll(/\n| /g,'').length
... (localStorage, MediaRecorder, ServiceWorker, Notification, Clipboard, ...)
```

This is a battery of "does this look like a real Electron/Chromium
renderer" checks, stripped of whitespace so exact formatting doesn't
matter. Each numeric result gets folded, one at a time, into a small
rolling 8-byte buffer via addition and XOR. That buffer is then XORed
directly over the **36-byte ciphertext** the rest of `check_flag` reads
from (address `67536`) - permanently, once, at startup.

::: insight
In other words: the ciphertext that `decrypted_target` is derived from is
*itself* scrambled by real-environment fingerprint data before `check_flag`
ever runs. Running the WASM under Node with these globals simply undefined
doesn't crash anything (the challenge doesn't want a crash - it wants a
silent wrong answer) - it just folds in the wrong numbers, and no password,
however cleverly derived, will ever satisfy the final `memcmp`. Every path
through this challenge that isn't "be a real Chromium renderer" produces
plausible-looking garbage with no indication anything went wrong.
:::

## 5. Getting a real renderer to answer honestly

Given all that, the only reliable way to recover the true values is to let
an actual Electron/Chromium instance run the actual page. The sandbox this
was solved in had no browser and no root:

- `npx playwright install chromium`, blocked by the sandbox's network
  allowlist.
- Running the bundled AppImage directly - failed with `libgtk-3.so.0` and
  `libXdamage.so.1` missing, and no `apt`/root to install them.

Fix: apt can be pointed entirely at user-writable directories
(`-o Dir::State::Lists=... -o Dir::Cache=...`), which lets it update package
lists and `--download-only` fetch `.deb`s without root. `dpkg-deb -x` then
extracts a `.deb`'s contents anywhere, no privileges needed:

```bash
apt-get -o Dir::State::Lists=~/apt/lists -o Dir::Cache=~/apt/cache \
  -o Dir::Etc::SourceList=/etc/apt/sources.list update
apt-get -o ... install --download-only -y libgtk-3-0 libxdamage1
for deb in ~/apt/cache/archives/*.deb; do dpkg-deb -x "$deb" ~/localroot; done
LD_LIBRARY_PATH=~/localroot/usr/lib/x86_64-linux-gnu ./awasmsafe ...
```

That's enough to get the real, packaged app running headless under `Xvfb`.

Two more traps on the way to a clean answer:

- **Don't touch the DOM structure.** An instrumented test page needs its
  own extra `<script>` to drive the analysis, but adding one *before* the
  original scripts shifts every `querySelectorAll` index the self-referential
  key derivation depends on. Fix: keep the original two `<script>` tags and
  the original `<head>` byte-for-byte (the second script re-inserted as
  inert `type="text/plain"` so it doesn't also try to wire up a terminal UI
  that isn't there), and append the analysis code as a third script after.
  The page's CSP (`script-src 'sha256-...'`) will then block that third,
  unlisted script from running at all - so `http-equiv="Content-Security-Policy"`
  gets renamed to a non-enforcing attribute name, *without touching its
  `content` value*, since that value is exactly the string the key
  derivation reads.
- **Don't use `webContents.executeJavaScript` to pull results out.**
  Electron implements it over the Chrome DevTools Protocol's
  `Runtime.evaluate`, and simply having a CDP session active is enough to
  make the challenge's own `debugger;` anti-debug statements (evaluated
  thousands of times during startup) actually pause execution - with
  nothing ever attached to resume them, the app hangs forever. Swapping to
  a `preload.js` + `contextBridge` + `ipcRenderer.send(...)` /
  `ipcMain.on(...)` channel avoids CDP entirely and returns results to the
  Node main process (and hence to stdout) cleanly.

With that in place, the real renderer reports, honestly:

```
seed  = 9                                    (typeof global).length, real renderer
r     = d850442ebf57f96a47fe4cda47e4eb735ec96f3c2578d1736be77eb15247a1af
cipher36 (post-fingerprint-XOR) = 089ffbf7c29848177a6b81747622bac0979404b534d9d38af396675fc1b30f80536dc1fb
target = LCG-decrypt(seed, cipher36)
       = e91a30db53d5df5996dafceb8cfc3e35a4fc9f119122e7378c5c31c7e223f8de973802fb
keystream = RC4-PRGA(r, 36 bytes)
       = 827b43ab36a7ac32efa18bdfff916106c899fc65e34b8106e9386ef08612c1bff2093786
```

## 6. Solving instead of guessing

RC4 encryption is `out = data XOR keystream(key)`, and the keystream itself
never depends on the data - only the key and requested length. So instead
of brute-forcing a 36-byte password, just invert the XOR:

```
password = target XOR keystream(r)
```

```python
password = bytes(a ^ b for a, b in zip(target, keystream))
# b'kaspersky{w4sm_3lectrif1ed_7d19ae15}'
```

36 bytes, clean ASCII, right format for the CTF. Feeding it back into the
live `window.checkFlag()` in the same real-renderer run confirms it:
`check_flag(password) == 1`.

## Flag

```
kaspersky{w4sm_3lectrif1ed_7d19ae15}
```

## Files

- `SOLUTION.md`, condensed version of this writeup.
- `solve_harness.html`, an earlier, Node.js-oriented exploration attempt,
  kept for reference; it's what first surfaced the `process.exit`/`typeof
  global` killswitch and the missing-DOM-globals problem that motivated the
  Electron-based approach above.
