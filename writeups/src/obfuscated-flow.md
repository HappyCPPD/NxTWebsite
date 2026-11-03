# Obfuscated Flow

**Event:** HICyberCon CTF 2026
**Category:** rev
**Flag:** `hiCTF{m4th_c0ntr0l_fl0w_3ll1pt1c_dlog_4f7b2c9e}`

---

**Category:** rev (control-flow flattened state machine) · **Artifact:** `extracted/challenge`
(stripped x86-64, GCC 16.2, 18 KB)

## Flag
```
hiCTF{m4th_c0ntr0l_fl0w_3ll1pt1c_dlog_4f7b2c9e}
```
Verified with the untouched binary: `printf 'hiCTF{m4th_c0ntr0l_fl0w_3ll1pt1c_dlog_4f7b2c9e}\n' | ./challenge`
→ `[+] ACCESS GRANTED! Passkey verified.` + the flag. Negative control: changing the last character
(…2c9f) → `[-] Access Denied.`; swapping the final word order (`…dlog_2c9e4f7b`) is also denied.

## Shape of the binary
* Banner `[ hiCTF Sentinel Gateway ]`, prompt `Passkey: `.
* Input: `fgets(0x100)` into `rsp+0x170`; trailing `\n`/`\r` stripped; `strlen-1 == 0x2e` → **47 chars**;
  `strncmp(input,"hiCTF{",6) == 0`; `input[0x2e] == '}'`. So the passkey is flag-shaped by construction.
* A flattened **state machine**: the state value in `eax` is dispatched against constants
  (`0x3d087b16`, `0x2f71a8d4`, `0x38a5f41c`, `0x19c45d80`, `0x51e29f3a`, `0x6b3e91f2`, `0x43b7e025`, …)
  and each state block computes the next state from *words of the input*.
* Rotating PRNG state lives in `[rsp+0xe0]`, seeded from rodata `0x403210`/`0x403220`
  (MD5-IV-like words `efcdab89 67452301 10325476 98badcfe`); helper `0x401f80` is its
  add/rol/xor update step. Intermediate blocks XOR the PRNG state with input-derived values, so the
  final keystream - and therefore the printed string - is a function of the whole 47-char passkey.

## The flag body, word by word (4-byte LE words of input[6:46])
| word | value | gate |
|------|-------|------|
| w0 | `m4th` | quadratic system mod 2³¹−1 |
| w1 | `_c0n` | same system |
| w2 | `tr0l` | elliptic-curve equation (found by brute force, 2³² candidates per word) |
| w3 | `_fl0` | same |
| w4 | `w_3l` | discrete log, base 7, mod 2³¹−1 |
| w5 | `l1pt` | discrete log, base 11, mod 2³¹−1 |
| w6 | `1c_d` | 2×2 linear system mod 2³²−5 |
| w7 | `log_` | same |
| w8 | `4f7b` | sum/product mod 2³¹−1 - two candidates (`2c9e`,`4f7b`); only one order passes |
| w9 | `2c9e` | ditto |

Reads as “math control flow, elliptic dlog”. The state value `0x38a5f41c` routes to the final block at
`0x401a9a`, which expands the PRNG into 98 bytes, XORs the rodata table at `0x4031a0`, and requires the
djb2 recurrence `h = h*31 + b` over those 98 bytes to equal `0xb4f079c8`; only then does it call
`printf("%s", buf)` (0x401b8f). Patching the deny branches to jump straight to `0x401a9a` reaches that
block but prints garbage, because the PRNG state must first be advanced correctly by the state machine
proof that the passkey words are genuinely required.

## Method that got there
1. Ghidra headless decompiled the obfuscated function cleanly (`FUN_004010c0`), which made the modular
   arithmetic readable: each gate is a pure 2-word modular check plus a PRNG mix. Helpers:
   `0x402010` (primality), `0x402220` (Montgomery multiply without full reduction), `0x401f80` (PRNG).
2. Five of the words fell to direct algebra: quadratic system mod 2³¹−1, discrete logs base 7/11 mod
   2³¹−1, and a 2×2 linear system mod 2³²−5.
3. The `0x19c45d80` gate is an **elliptic-curve** relation over q = 10⁹+7 (disasm `0x401439–0x4014d2`):
   it forms `w2³`, adds `0x20a6e·w2`, adds `0x30730db7`, and requires the result to equal `w3² mod q`:
   `w3² ≡ w2³ + 0x20a6e·w2 + 0x30730db7  (mod 10⁹+7)`
   (the constants `0x20a6e`/`0x89705f3112a28fe5` are the same curve constants used by the point
   add/double routine `FUN_00402220`). The other terms in that block are constants seeded from
   `0x403230` and the 11-iteration loop is `const^0x539`, so w2/w3 appear in exactly this one
   relation. Brute-forcing the equation over printable w2 with Tonelli - Shanks (`ecbrute2.c`) leaves
   ~771k printable candidates, which the leet context collapses to `w2='tr0l'`, `w3='_fl0'`
   → "math_control_flow_elliptic_dlog".
4. Resolved the w8/w9 order (two candidate words with known sum/product) by trying both against
   `./challenge`: `4f7b` then `2c9e` is correct (the reverse → Access Denied).
