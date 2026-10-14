# The-Recurrence

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{p0hlig_h3llman_sm00th}`

---

**Binary:** `chall` - ELF 64-bit x86-64, stripped, dynamically linked
(`sha256 3206437d20a2a6a741753fabbc675a5e7b153c7352f9623f3893df99cb252090`)

## 0. Recon

```
$ printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAA' | ./chall
nope.
```

`strings` reveals the whole game:

```
need exactly %d bytes of input
CORRECT -- the flag is the input you just gave me.
nope.
```

So there is no embedded flag: **the flag IS the 28-byte input**. We must find
the unique 28-byte string the program accepts. The binary reads exactly
`0x1c = 28` bytes from stdin (`fread(buf, 1, 28, stdin)`) and bails if it gets
fewer.

## 1. How the input is consumed

At `0x4003eb` - `0x400461` the 28 bytes on the stack are packed into a 256-bit
little-endian integer at `[rsp+0x20]` (four 64-bit limbs):

```
limb[i>>3] |= input[i] << ((i & 7) * 8)      for i = 1..27
limb[0]      = input[0]
```

i.e. **k = int.from_bytes(input, 'little')** - a 224-bit scalar (bits 224..255
are zero).

Then a loop runs `ebx` from `255` down to `0`, testing bit `ebx` of k
(`bt rax, rbx; jae ...`) and taking one of two update paths.

## 2. The two helper routines

Hand-decompiling the small functions:

- **`0x4007c0` - modular addition mod M.** 256-bit add of two 4-limb numbers,
  then `if result >= M: result -= M`, where `M` is the constant at `0x401320`.
- **`0x4008f0` - modular subtraction mod M.** `a - b`, or `a - b + M` when
  `a < b` (the `0x40094d` branch computes `M - b` then adds `a` via `0x4007c0`).
- **`0x400860` - modular multiplication mod M.** Classic left-to-right
  double-and-add over 256 bits: `acc = acc + acc` (doubling) then
  `acc = acc + rbp` when the current mask bit is set, all in the `Z_M`
  additive group of `0x4007c0`. Net effect: `out = a * mask mod M`.

## 3. The recurrence

The main loop keeps two 4-limb values:
`A` at `[rsp+0x60]` and `B` at `[rsp+0x80]`, initialised to

```
A = 2                       (the constant at 0x401340)
B = P  = value at 0x401300  = 0x2e4407f92792ed6df3991d8de01c294c9f66992d15d54b5f7de0b31a8525a8
```

For each bit of k (MSB→LSB) it applies one of:

```
bit CLEAR (0x4004d0):
    A' = A*A - 2          (0x400860 then 0x4008f0 with b = 2)
    B' = A*B - P          (0x400860 then 0x4008f0 with b = P)

bit SET   (0x40058e):
    A' = A*B - P
    B' = B*B - 2
```

This is exactly the **double-and-add ladder of a Lucas sequence**
V_n(P, Q=1):

```
V_0 = 2,  V_1 = P
V_2n   = V_n^2 - 2
V_2n+1 = V_n * V_n+1 - P
V_2n+2 = V_n+1^2 - 2
```

With `(A,B) = (V_n, V_{n+1})`:
- bit clear → `n := 2n`   gives `(V_2n, V_2n+1)`
- bit set   → `n := 2n+1` gives `(V_2n+1, V_2n+2)`

So after consuming k the state is `(V_k, V_{k+1})`.

## 4. The check

Only `A` is verified (`0x40060b`, `0x400648`): the program XORs the four limbs
of `A` against the constant at `0x4012e0` and prints "nope." on any mismatch.
Therefore we need

```
V_k(P, 1) ≡ T (mod M)
T = 0x49e8add02e2a5b87f2de8e6703998b93fbd3872fadce56bb759965f1103100
```

## 5. Inverting it: Lucas → discrete log → Pohlig - Hellman

Since Q = 1, the characteristic roots `α, β = α^{-1}` of `x² - Px + 1`
give the closed form

```
V_n = α^n + α^{-n}
```

(The root exists in F_M because `D = P² - 4` is a QR mod M.) The condition
`V_k = T` becomes

```
α^k + α^{-k} = T
(α^k)² - T·α^k + 1 = 0
α^k = (T ± sqrt(T² - 4)) / 2
```

`T² - 4` is also a QR, so both roots live in F_M. Recovering k is now a
**discrete log of `α^k` base α** in F_M*.

Now the crux - is it tractable? Factor the group order:

```
M - 1 = 2 · 997 · 1399 · 1931 · 2297 · 4003 · 5701 · 7103 · 10211 · 12799 ·
        14551 · 48271 · 46229 · 47279 · 51263 · 52937 · 53923 · 58771 · 59051
```

Squarefree and **fully smooth** (largest factor 59051). α turns out to be a
**primitive root** (order = M-1). So Pohlig - Hellman splits the 247-bit dlog
into one dlog per ~16-bit prime and CRTs them together - milliseconds.

Two candidate roots → two candidate k values (they are k and −k mod M-1,
matching `V_k = V_{-k}`). Exactly one lies in `[0, 2^224)` and yields
printable ASCII in little-endian - that is the flag.

```
k = 13207006284361456903106593959418730498679199957338452512214440375145
k.to_bytes(28, 'little') = b'isfcr{p0hlig_h3llman_sm00th}'
```

## 6. Verification

```
$ printf '%s' 'isfcr{p0hlig_h3llman_sm00th}' | ./chall
CORRECT -- the flag is the input you just gave me.
$ echo $?
0
```

`solve.py --verify` recomputes everything from the constants and pipes the
result into `./chall` to confirm.

## 7. Takeaway

The "recurrence" is a Lucas V-sequence; the `-2` / `-P` constants and the
`(V_2n, V_2n+1, V_2n+2)` ladder are its fingerprint. Because Q=1 the sequence
collapses to `α^n + α^{-n}`, turning the puzzle into a discrete log, and the
author conveniently chose a prime M with a fully smooth M-1 (the flag name
`p0hlig_h3llman_sm00th` gives it away). The rest is plumbing: Tonelli - Shanks
for the two square roots, Pohlig - Hellman + CRT for the log, and a little-endian
byte reinterpretation to read off the ASCII flag.

