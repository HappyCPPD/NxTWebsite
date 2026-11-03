# Cold Circuit

**Event:** HICyberCon CTF 2026
**Category:** rev
**Flag:** `hiCTF{6e305f6a7461675f6e65656465642121}`

---

Flag: `hiCTF{6e305f6a7461675f6e65656465642121}`
(hex-decoded payload: `n0_jtag_needed!!`)

## Artificial
Single stripped PIE ELF `check`, 14 KB, no args needed (`./check <flag>` or
flag on stdin).

## Triage
```
file check    -> ELF 64-bit PIE, dynamically linked, stripped
strings check -> "hiCTF{", "no input", "Bad format.", "unreachable",
                 "Access granted.", "Incorrect."
```
`.rodata` held four blob tables: a 256-byte S-box @0x2020, a 16-byte
permutation @0x2120, a 320-byte (20x16) round-key table @0x2140, and a
16-byte target @0x2280.

## Input parser (0x12d6)
- strips trailing `\n`/`\r`
- requires total length **39** (`0x27`)
- `memcmp(s, "hiCTF{", 6) == 0`
- `s[38] == '}'`
- parses `s[6..38)` as **32 hex chars -> 16 raw bytes** into `buf[16]`
  (`hexval`: `0-9`, `a-f`, `A-F`; returns -1 on anything else).

## Cipher (main @0x1431)
20 rounds, each round `r` with key block `K = table[16r : 16r+16]`:
```
for i in 0..15:                  # ARX-ish byte add
    b[i] = (b[i] + K[i]) & 0xff
for i in 0..15:                  # substitution
    b[i] = SBOX[b[i]]
for i in 0..15:                  # permutation
    o[PERM[i]] = b[i]
b = o
```
Then `bad = OR_i (b[i] ^ TARGET[i])`; `bad == 0` -> "Access granted."

## Decoys (both are mathematically unfailable)
Two gates run on `n = argc + buf[0]` before the cipher:
- `0x125c`: if `(n*n + 1) % 4 == 0` -> print "unreachable", return 99.
- `0x1229`: if `(n*n) % 3 == 2`      -> return 98.
Since `n^2 mod 4 in {0,1}` and `n^2 mod 3 in {0,1}`, **neither condition can
ever hold** - dead anti-tamper checks.
A `ptrace(PTRACE_TRACEME)` probe sets a flag that XORs `buf[0] ^= 1` when the
process is being traced; running the binary normally leaves it untouched.
(Sanity: for the real `buf[0]=0x6e`, `argc=1` -> n=111, `argc=2` -> n=112;
both gates false either way.)

## Inverting
Every round is invertible:
```
o = b (after perm)  ->  b_pre_perm[i] = o[PERM[i]]
b_pre_sbox[i] = SBOX_INV[b_pre_perm[i]]
b_prev[i]     = (b_pre_sbox[i] - K[i]) & 0xff
```
Walking TARGET backwards through rounds 19..0 yields the 16 input bytes.

`6e305f6a7461675f6e65656465642121` -> ASCII `n0_jtag_needed!!`

## Verification
```
$ echo 'hiCTF{6e305f6a7461675f6e65656465642121}' | ./check
Access granted.        (exit 0)
$ ./check 'hiCTF{6e305f6a7461675f6e65656465642121}'
Access granted.        (exit 0)
# negative control (last nibble 1->0):
$ echo 'hiCTF{6e305f6a7461675f6e65656465642120}' | ./check
Incorrect.             (exit 1)
```
Re-encrypting the recovered bytes reproduces TARGET exactly.

Solver: `work/solve.py`.
