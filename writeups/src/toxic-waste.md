# toxic-waste

**Event:** CryoVault CTF 2026
**Category:** crypto
**Flag:** `isfcr{ch30n_8f_th3_c0mpr3ss3d_srs}`

---

> Trusted setup done, secret burned. We kept the two ends and binned the middle to save on disk.

`chall.py` runs a KZG-style trusted setup: picks `d = 2^44`, a prime `m`, `q = d*m + 1` prime, a 1024-bit prime `P` with `q | P-1`, generator `g` of the order-`q` subgroup, and secret `tau` uniform in `[2, q-2]`. The full SRS would be `g, g^tau, ..., g^(tau^d)`; only the two ends are kept: `A = g^tau` (head), `B = g^(tau^d)` (tail). The flag key is `sha256(str(tau))`. The claimed security is `sqrt(q)` ≈ 2^43.5; both claims are wrong - this is exactly the setup for **Cheon's attack**.

**Why the two ends are fatal:** Cheon's attack (J. H. Cheon, 2010) solves, given `g, g^alpha, g^(alpha^d)` with `d | q-1`, for `alpha` in `O(sqrt(q/d) + sqrt(d))`. Decompose `tau = h^(k0 + k1*m) mod q` for a generator `h` of `Z_q^*`. Since `h^(q-1) = 1`, `tau^d = h^(d*k0) (mod q)`, so `B` leaks `k0` and `A` then leaks `k1` via two BSGS phases.

**Phase 1 (recover k0, ~3.35M steps/side):** `k0 = i*N + j`. Build baby table `{ g^(h^(d*j)) : 0 <= j < N }`; walk giant side `B^(h^(-d*i*N))` until it lands in the table.

**Phase 2 (recover k1, ~4.19M steps/side):** with `eta = h^m`, `A^(h^-k0) = g^(eta^k1)`. Same BSGS structure recovers `k1`.

Environment quirk: `2` is not a primitive root mod `q`; the smallest generator found was `h = 3`. Complexity ≈ `2^22` group operations per phase.

```
[cheon] generator h = 3
[cheon] part1: N = 3349947        # baby built in 138s, giant match at i=1.41M
[cheon] k0 = 4734199638712
[cheon] part2: N2 = 4194305       # baby built in 186s, giant match at i=2.21M
[cheon] k1 = 9264960971644
[cheon] RECOVERED tau = 53372121991905014611291611
FLAG: isfcr{ch30n_8f_th3_c0mpr3ss3d_srs}
```

Sanity checks `g^(h^(d*k0)) == B` and `g^tau == A` both pass. A two-ended SRS (`g^tau`, `g^(tau^d)`) is not "just ends"; it is a full Cheon auxiliary-input instance whenever `d | q-1`. The real security is `O(sqrt(q/d) + sqrt(d))`, not `sqrt(q)`; factoring `q-1` and noticing the big power-of-two divisor is the audit step that was skipped.
