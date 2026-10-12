# sparse-change

**Event:** CryoVault CTF 2026
**Category:** crypto
**Flag:** `isfcr{pr0ny_kn3w_1t_1n_1795}`

---

A black box evaluated a secret sparse polynomial `F(X) = sum_{i=1..T} c_i * X^(e_i) (mod p)` over `GF(p)`, `p` 61-bit prime, `T = 24` sparse terms with distinct exponents. Only 48 samples given: `log[j] = F(g^j)` for `j = 0..47`, `g` a generator of `GF(p)*`. The flag key is `sha256(";".join(f"{e}:{c}"))` over the true term list sorted by exponent. The challenge rules out interpolating a degree-`p-2` polynomial (needs `p-1` points) and guessing exponents (`C(p-1,24) ~ 10^421`).

**Key insight:** substituting `a_i = g^(e_i) mod p` gives `log[j] = sum_i c_i * a_i^j` - a sum of `T` exponentials in `j` (Prony's problem, 1795). Any such sequence satisfies a linear recurrence of order `T` whose characteristic polynomial `C(X) = prod_i (X - a_i)` has `sum_k u_k * log[j+k] = 0`. With exactly `2T = 48` samples (the Berlekamp-Massey/Prony minimum), set up the `T x T` Hankel system and solve by one Gaussian elimination mod `p`.

**Recovering the exponents:** the roots of `C` over `GF(p)` are exactly the `a_i = g^{e_i}`. Split `C` into linear factors with Cantor-Zassenhaus (degree 24, instant). Each exponent is then a discrete log base `g`; `p - 1 = 2 · 281833 · 784577 · 2614081` (all < 2^22), so Pohlig-Hellman reduces each dlog to a subgroup of order < 2^22, solved by BSGS, then CRT.

**Recovering the coefficients:** with `a_i` known, `log[j] = sum_i c_i a_i^j` is a 24×24 Vandermonde system solved mod `p`. Pitfall: the mapping `a_i -> e_i` is not order preserving, so the Vandermonde solution must be matched to roots in the *same order they came out*, not sorted independently - sorting roots and exponents separately silently mismatches pairs and fails the tag check. Verification: the recovered term list reproduces all 48 published evaluations exactly.

```
key = sha256(";".join(f"{e}:{c}" for (e,c) in terms_sorted_by_e))
isfcr{pr0ny_kn3w_1t_1n_1795}
cd sparse-change
/usr/bin/python3 solve.py
# -> FLAG: b'isfcr{pr0ny_kn3w_1t_1n_1795}'
```

Runtime < 1 second. The flag is a nod to Gaspard de Prony, who solved exactly this problem in 1795.
