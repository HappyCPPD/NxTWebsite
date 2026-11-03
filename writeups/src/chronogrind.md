# ChronoGrind

**Event:** HICyberCon CTF 2026
**Category:** crypto
**Flag:** `hiCTF{n1c3_w0rk_n0w_t4k3_s0m3_r3$t}`

---

**Category:** crypto / patience · **Artifacts:** `extracted/chronogrind/state.dat` (1358 B), `flag.enc` (68 B)

## Flag
```
hiCTF{n1c3_w0rk_n0w_t4k3_s0m3_r3$t}
```
Recovered after the full 9e9-step squaring chain (~158 min at ~950k squarings/s; the key came out as
`96156b5d6965bf3ba35616cd280de13b2f7ae6e3734772083b7faf686cdf6148`). The ChaCha20-Poly1305 **tag
verifies**, which is cryptographic proof the key is the intended one - a wrong state fails the tag.
Reproduce with `python3 decrypt.py` (reads `grind_state.json`, writes `FLAG.txt`).

## state.dat format (reversed)
* magic `CGD1`, whole body **XOR 0x4C**; then a 2-byte header and a sequence of `[tag u8][len u32 LE]`
  TLV fields (tags `01 11 22 33 44 55 66 77 88`).
* Readable fields: `team=testrun`, and a note spelling out the scheme:
  ```
  anchor = rec[11] (base241), seed = rec[22] (base241), cycles = rec[33] (decimal)
  chk    = rec[44] = sha256('anchor:seed:cycles' as colon-separated decimals)[:8]
  derivation: v = seed; repeat `cycles` times: v = v*v mod anchor
  k = sha256(v as 256-byte big-endian)
  msg container CGFX: magic 'CGFX'(4) ver(1) nonce(12) tag(16) ct(rest)
  aead = chacha20-poly1305, key = k, nonce = nonce field
  ```
* `anchor`/`seed` are 259-byte little-endian **base-241** digit strings (2048 / 2045 bits); `cycles =
  9000000000`. The gate `sha256("anchor:seed:cycles")[:8] == rec[44]` reproduces exactly
  (`3afdd49ebe78a45a`), confirming the parse.

## Why it's a grind
`v = seed^(2^9e9) mod anchor`, and `anchor` is a 2048-bit **composite with no small factors**, so the
exponent cannot be reduced modulo λ(anchor) - the squaring chain has to be run literally, and it is
inherently sequential (no CRT/parallel shortcut). Measured ~0.95-1.0 µs per modular squaring with
gmpy2, i.e. ~2.6 h on one core - exactly the "bring a charger" line in the challenge.

## Runner
`grind.py`: chunked `gmpy2.powmod(v, 1 << 1e8, anchor)` with a checkpoint to `grind_state.json`
(so it resumes if interrupted) and progress to `grind.log`. On completion it stores the hex key; then
```
k  = bytes.fromhex(key)
# flag.enc: 'CGFX' | ver(1) | nonce(12) | tag(16) | ct(35)
pt = ChaCha20Poly1305(k).decrypt(nonce, ct + tag, None)
```
