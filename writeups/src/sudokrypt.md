# Sudokrypt

**Event:** Kaspersky CTF 2026
**Category:** crypto
**Points:** 50 (64 at time of writing)
**Server:** `tcp.sasc.tf 31415`
**Flag:** `kaspersky{D4mn_1m_s0_c00l!!_1_c4n_d0_sud0ku_n0w_st4cy_t0t4lly_g01ng_t0_pr0m_w1th_m3}`

---

## Overview

The challenge is a custom 128-bit block cipher ("SudoKrypt") built on top of a
16×16 Hexadoku (sudoku) grid, plus a homebrew "spectral" keystream generator.
The server exposes a menu:

```
1) encrypt one block
2) peek at Stacy's homework (once)
3) how many queries are left
4) get me out
```

Option 1 is a chosen-plaintext encryption oracle (default 96 queries per
connection). Option 2 encrypts the flag exactly once and immediately closes
the oracle. The cipher looks intimidating - Feistel wrapping, bit diffusion,
a sudoku board, a 56-term modular exponential keystream - but almost none of
it is actually load-bearing. Two design leaks let you fully break it well
within the 96-query budget.

---

## Cipher structure (`sudokrypt_core.py`)

Per 16-byte block:

1. Each plaintext byte `i` is combined with a keystream value
   `values[i]` (12 bits, from the spectral generator) via `inner_word()`,
   producing a 16-bit "word". This mixes in two session-secret 16-entry
   permutations, `q_perm` and `symbol_perm`.
2. The 16 words are cyclically **rotated** by an amount derived from the
   keystream (`block_rotation`).
3. Each rotated word is passed through `public_wrapper()` (a 4-round
   Feistel network), then through `diffuse_words()`, a fixed bit-rotation
   mixing step.

Critically, **step 3 uses no secret key material at all.** The Feistel
round keys are `0x53 + rank*0x29 + rnd*0x47`, pure public constants
indexed only by position. `diffuse_words` is likewise a fixed, keyless
bit-mixing permutation. Both are exactly invertible by anyone
(`public_wrapper_inv`, `undiffuse_words`), for free, with no oracle queries
at all. So the entire outer two layers contribute zero security; the real
secrets are just:

- `q_perm` and `symbol_perm` - two 16-entry permutations, fixed per session
- the **spectral generator**: `values(lane, t) = Σ c[lane][j] · nodes[j]^t (mod 4093)` for 56 secret field elements `nodes[j]` and 16×56 secret coefficients - this drives both the keystream and the block rotation

---

## Leak #1 - `q_perm` in a single query

Inside `inner_word()`, the top nibble of the output word is exactly
`q_perm[q]`, where `q` is the top nibble of the plaintext byte - no
keystream or other secret mixed in at all. Send a plaintext whose 16
`q`-nibbles are `[0, 0, 1, 2, ..., 14]` (deliberately repeating `0` once).
After publicly un-wrapping the ciphertext, the resulting 16 top-nibbles are
just this sequence *cyclically rotated* by the block's secret rotation
amount. Since `q_perm` is a bijection, exactly one adjacent pair in that
16-cycle is equal (the deliberate duplicate) and every other value is
unique - so that pair's position pins the rotation exactly, and the
duplicate/elimination trick then hands you all 16 entries of `q_perm` in
one query. As a bonus, once `q_perm` is known, every future block's
rotation is also free: brute-force the 16 possible rotations and check
which one makes the top nibbles equal `q_perm[q_i]` position-for-position.

## Leak #2 - `symbol_perm` via a free checksum

`symbol_perm` is entangled with per-position keystream nibbles
(`row_code`, `mask`) in a way that looks perfectly masked: for any
candidate value of `symbol_inv[k]`, the two observable fields
(`row_field`, `col_field`) always have a unique, self-consistent solution
for `row_code`/`mask`, a single query leaks nothing.

The escape hatch is `block_rotation`:

```
rotation = (sum(values) + 3*values[0] + block_number) & 15
```

Since `256 mod 16 == 0`, this checksum only depends on the **low byte** of
each lane's keystream value - exactly the byte that falls out of the
`row_code`/`mask` formula once you guess `symbol_inv[k]`. So: fix a
candidate symbol at all 16 byte lanes in one query (rotation already known
for free from leak #1), brute-force the 16 possible values of
`symbol_inv[k]`, and keep only the guess whose implied checksum matches the
real rotation. On average a handful of wrong guesses survive one query;
2-3 repeats per symbol collapse the candidate set to exactly one. Doing
this for `k = 0..15` fully recovers `symbol_perm` in roughly 30-40 queries.

Each calibration query is also a bonus: once `symbol_inv[k]` is confirmed,
the last unknown nibble (the "check" field, an XOR with an S-box of
otherwise-known inputs) is now fully determined too - so every calibration
query hands over the **exact 12-bit keystream value for all 16 lanes**,
for free.

---

## Leak #3 - the spectral keystream generator

`values(lane, t) = Σ_{j=0}^{55} c[lane][j] · nodes[j]^t (mod 4093)` is, by
construction, a degree-56 linear recurring sequence shared across all 16
lanes (same 56 `nodes`, different coefficients per lane). With ~90
consecutive exact samples per lane (collected as a side effect of leak #2,
since every encrypt query - regardless of symbol - advances the same
block counter by exactly 1), this is heavily overdetermined:

1. Stack `value(t) = Σ rec[j]·value(t-1-j)` equations across all 16 lanes
   and solve the resulting linear system (mod 4093) for the 56 recurrence
   coefficients.
2. Factor the corresponding degree-56 characteristic polynomial over
   `GF(4093)`, its 56 roots are exactly the secret `nodes[j]`.
3. With `nodes` known, solve a 56×56 Vandermonde system per lane (using
   the first 56 samples) to recover each lane's 56 coefficients exactly.

The one-time "fold" applied to the generator's state right before the flag
is encrypted (`fold_for_flag`) is a fixed public formula in terms of these
same `(nodes, coefficients)`, so it can be replayed exactly offline, even
though the real oracle is closed by the time you need it. That gives the
exact keystream for however many blocks the (padded) flag occupies.

---

## Putting it together

With `q_perm`, `symbol_perm`, and the full keystream generator recovered:

1. Request the encrypted flag (closes the oracle, triggers the fold).
2. Replay the fold offline to predict the keystream for each flag block.
3. Compute each block's rotation from the predicted keystream.
4. Publicly un-wrap the ciphertext, undo the rotation, and invert
   `inner_word` (now trivial with `q_perm`/`symbol_perm` known) to recover
   each plaintext byte.
5. Strip PKCS7 padding.

No brute force is needed at the decryption step - everything is solved
in closed form once the three leaks are exploited.

---

## Implementation

`solve.py`, a self-contained script (only needs `sympy` for polynomial
factoring over `GF(4093)`):

- `RemoteOracle`, speaks the real `server.py` line protocol over a raw
  socket
- `Solver.bootstrap_qperm()`, leak #1
- `Solver.resolve_symbol()` / `recover_symbol_perm()`, leak #2
- `Solver.recover_lfsr()`, leak #3 (linear system → poly factoring →
  Vandermonde)
- `Solver.decrypt_flag()`, replays the fold and decodes the flag

Total query budget used: ~95 of the 96 available (1 for `q_perm`, ~30-45
calibrating `symbol_perm`, the rest padding out to enough consecutive
keystream samples for the linear-algebra step).

Validated end-to-end against a local copy of the challenge's own
`server.py` before running against the real server (5/5 successful runs).

---

## Flag

```
kaspersky{D4mn_1m_s0_c00l!!_1_c4n_d0_sud0ku_n0w_st4cy_t0t4lly_g01ng_t0_pr0m_w1th_m3}
```

---

## Notes

- The "Hexadoku" board itself (the actual sudoku grid, `row_for_shift`,
  `col_for_base`) is a red herring for the attacker - it's only used
  server-side as a self-consistency check during encryption and is never
  needed to decrypt.
::: insight
The core design mistake is reusing one global block counter (and thus
one continuous keystream) across both the attacker-controlled oracle and
the flag encryption, combined with a rotation checksum that leaks
keystream information mod 16 for free. Either one alone would likely
have been fine; together they fully break the scheme.
:::
