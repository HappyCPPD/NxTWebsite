# Zero Report

**Event:** SolarCTF
**Category:** crypto
**Flag:** `SOLARCTF{y0u_h4sh3d_th3_wr0ng_th1ng}`

---

**Category:** Cryptography
**Flag:** `SOLARCTF{y0u_h4sh3d_th3_wr0ng_th1ng}`

## TL;DR
The auditor's "invariant" is the **linear congruence**

```
(1 - h)·a + h·b ≡ 0  (mod P)      P = 2^127 - 1,   h = H(source) = sha256(source) mod P
```

`h` is not random at verification time - it is a *known, computable* function of the
submitted bytes, and the sandboxed DSL lets `generate()` reference `H(SOURCE)` directly.
So the whole thing collapses: any `(a, b)` on that line works. Take

```
a = h
b = h - 1
```

Then `(1-h)·h + h·(h-1) = h - h² + h² - h = 0`. Report `(h, h-1)` is **nonzero** and
**accepted** → flag. The author "hashed the wrong thing": the acceptance test is
satisfiable trivially because the value it depends on is attacker-controlled.

## The challenge
`service.py` reads one base64 program, parses `generate()` with a *restricted AST
evaluator* (no execution of arbitrary code), and computes a 2-integer "report".

Acceptance (`audit`):

```python
accepted = (0 <= a < P and 0 <= b < P
            and (a != 0 or b != 0)
            and ((1 - source_hash) * a + source_hash * b) % P == 0)
```

`source_hash = sha256(source) % P`, and `source` is the *canonical packed program*
(`pack.py`) - one fixed string once the body is fixed.

The DSL (`report_from_source`) allows only:
- integer literals with `bit_length() <= 256`,
- the name `P` (= 2^127-1),
- previously-assigned local names,
- the single call `H(SOURCE)` → `source_hash`,
- `+ - * %` (and unary ±), intermediates `<= 512` bits.

Constraint: ≤ 32 statements, ≤ 256 AST nodes, depth ≤ 32, body ≤ 2048 bytes,
source must equal `pack.pack(extract_body(source))` byte-for-byte (canonical).

## The bug (two coupled mistakes)
1. **Self-referential input.** `H(SOURCE)` is a first-class DSL value. The hash the
   acceptance test uses is `H` of the very program being submitted, so it is not an
   unknown to solve for - it is an input the solver *reads*.
2. **A linear equation is not a predicate.** `(1-h)·a + h·b ≡ 0 (mod P)` defines a
   1-dimensional affine line of solutions, not the single point `(0,0)`. For `h ≠ 0`
   these are `b ≡ (h-1)·h⁻¹·a`, a huge family. Requiring `(a,b) ≠ (0,0)` therefore
   *guarantees* accept of a nonzero report, the exact opposite of the intent.

The author's tests presumably only checked `(0,0)`-returning programs, so the
"invariant" passed while being vacuous.

## Solution body (`solve/body.txt`)
```python
a = H(SOURCE)
b = H(SOURCE) - 1
return [a, b]
```

Packed (must go through `pack.py` to stay canonical):
```bash
python3 pack.py solve/body.txt solve/prog.py
```

## Verify
```bash
cd ~/Downloads/ctfs/Solarctf/Zero-Report
python3 solve.py            # build + local audit -> ACCEPT with nonzero report
python3 solve.py --remote   # submit to solarctf.ru:30102
```
Observed:
```
Report: [16249036334193251681511280897471541906, 16249036334193251681511280897471541905]
ACCEPT
remote: SOLARCTF{y0u_h4sh3d_th3_wr0ng_th1ng}
```

## Why it works (algebra)
With `a = h`, `b = h - 1`:
`(1-h)·h + h·(h-1) = h - h² + h² - h = 0`, and modulo `P` that is `0`.
`(a,b) ≠ (0,0)` whenever `h ≠ 0` (probability of the degenerate `h = 0` is `~P⁻¹`).
Both `0 <= h, h-1 < P`. Nothing else is required.

## Alternative fixes (if one were hardening this)
- Make acceptance a *predicate on the report being zero*: require `a ≡ 0 and b ≡ 0`,
  not a linear combination.
- Never expose a self-referential hash (or any value derived from the submitted
  bytes) as an input the program can read; hash a server-fixed secret/challenge
  instead, and sign it.
- Bind the check to a value the program cannot compute (e.g. server nonce inside the
  hash but unknown to the program, with the honest program forced to `(0,0)`).
