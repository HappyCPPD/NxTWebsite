# leaky-eval

**Event:** CryoVault CTF 2026
**Category:** crypto
**Flag:** `isfcr{n3g4cycl1c_n01s3_l34k}`

---

**Files:** `chall.py`, `output.json`

## Summary

A bottled "approximate-homomorphic" service samples Ring-LWE pairs in
`R_Q = Z_Q[X]/(X^N+1)` with `N = 64`, `Q = 2^61-1` (Mersenne prime). The
secret `s` has ternary coefficients in `{-1, 0, 1}`. Each of the 72 published
samples has message `m = 0`, so a ciphertext is `(a, b)` with

```
b = a*s + e            (mod Q),   |e_i| <= 2^20
```

For every sample the service additionally publishes `leak = e[idx] % Q` - a
*single* coefficient of the approximate decryption `Dec(a,b) = b - a*s = e`.

The trap: because `|e[idx]| < 2^20` is far smaller than `Q`, the reduction mod
`Q` is exact and the leak pins *one full linear equation on `s`*:

```
(a*s)[idx] == b[idx] - leak   (mod Q)
```

The noise is never "small enough to average away" - it's handed over as an
exact value at one coordinate, converting an LWE-style search problem into a
plain linear algebra problem over `Z_Q`.

## Solve

1. Build, for each of the 72 samples, the row of coefficients of `s` in the
   single revealed coordinate `idx` of `(a*s)`:
   for `k = idx`,
   `c[j] = a[(k-j) mod N]` if `j <= k`, else `-a[(k+N-j) mod N]` (mod `Q`).
   The sign flip is the negacyclic wrap `X^N = -1`.
2. Right-hand side `rhs = b[idx] - leak (mod Q)`.
3. Gaussian elimination mod `Q` (Mersenne prime ⇒ invertible via Fermat:
   `inv(x) = x^(Q-2) mod Q`).
4. 72 equations ≥ 64 unknowns; the system is full rank **64/64**, so `s` is
   recovered uniquely. Every recovered entry lifts cleanly to `{-1, 0, 1}`.
5. `key = sha256(",".join(map(str, s)).encode())`, then
   `AES-GCM` with nonce `b"leaky-eval--"` decrypts `flag_ct`/`flag_tag`.

```
$ python3 solve.py
rank: 64 of 64
s = [-1, 1, -1, -1, -1, -1, 0, 1, 0, 1, 1, -1, -1, -1, 1, 1, -1, 1, -1, -1,
      1, 0, 0, -1, -1, -1, -1, -1, 1, -1, 0, 0, 1, 0, 0, 1, -1, 1, 0, 0,
      1, -1, 0, 0, -1, 0, 0, -1, 1, 1, 0, 0, -1, -1, 0, -1, -1, 1, -1, 1,
      1, 0, 0, 1]
FLAG: isfcr{n3g4cycl1c_n01s3_l34k}
```

## Why one coefficient per sample is enough

With `72 > 64` samples, each giving one exact linear equation, the system is
overdetermined and lands exactly on full rank. The ternary constraint was never
even needed to solve - it only served as a sanity check that the recovered
`Z_Q` solution is the genuine (small) secret rather than an unrelated vector.
Had the leak been rounded/truncated (MSB leak), the equations would have been
approximate and the problem would not have collapsed this way; the leak is
*exact*, which is the whole weakness.

## Note on the author's own bug (my first attempt)

My first script recovered the correct `s` (verified against all 72 samples) but
the AES-GCM MAC check failed. Cause: the key is derived from the *ternary ints*
`str(s)` producing `-1,0,1`, but I passed `str(x % Q)` producing the huge
canonical reps. Fixing the string form to `-1/0/1` decrypted immediately. The
crypto was never the issue - only the serialization used for the KDF.

## Artifacts

- `solve.py` - full solve (Gaussian elimination + decrypt).
- `output.json` - challenge data.
- `chall.py` - challenge source.

