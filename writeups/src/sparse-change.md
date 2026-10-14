# sparse-change

**Event:** CryoVault CTF 2026
**Category:** crypto
**Flag:** `isfcr{pr0ny_kn3w_1t_1n_1795}`

---

## The challenge

We are given `chall.py` and `output.json`. A black box evaluated a secret
polynomial

```
F(X) = sum_{i=1..T} c_i * X^(e_i)   (mod p)
```

over `GF(p)` with `p` a 61-bit prime, `T = 24` **sparse** terms, distinct
exponents `e_i` in `[1, p-2]`, nonzero coefficients. We only got 48 samples:

```
log[j] = F(g^j)   for j = 0 .. 2T-1 = 47
```

where `g` is a generator of `GF(p)*`. The flag is AES-GCM encrypted under
`sha256(";".join(f"{e}:{c}"))` over the true term list (sorted by exponent),
with the ciphertext/tag/nonce published.

The challenge text explicitly rules out the two obvious dead ends:
interpolating a degree-`p-2` polynomial needs `p-1` points (we have 48), and
guessing which 24 of the `p-1` exponents are live is `C(p-1,24) ~ 10^421`.

## The key insight: it is a sum of exponentials → a linear recurrence

Substitute `a_i = g^(e_i) mod p`. Then

```
log[j] = F(g^j) = sum_i c_i * (g^{e_i})^j = sum_i c_i * a_i^j
```

This is a **sum of `T` exponentials in `j`** (Prony's problem, 1795). Any such
sequence satisfies a linear recurrence of order `T` whose characteristic
polynomial is

```
C(X) = prod_i (X - a_i) = X^T + u_{T-1} X^{T-1} + ... + u_1 X + u_0
```

i.e. `sum_{k=0}^{T} u_k * log[j+k] = 0` with `u_T = 1`.

We have exactly `2T = 48` samples, which is the minimum needed (Berlekamp - Massey
/ Prony). Setting up the `T x T` Hankel system for `j = 0..T-1`:

```
[ log[0]   log[1]   ... log[T-1]   ] [u_0]     [ -log[T]   ]
[ log[1]   log[2]   ... log[T]     ] [u_1]  =  [ -log[T+1] ]
[ ...                              ] [ ... ]    [ ...       ]
[ log[T-1] log[T]   ... log[2T-2]  ] [u_{T-1}] [ -log[2T-1] ]
```

One Gaussian elimination mod `p` gives `C`.

## Recovering the exponents: root finding + Pohlig - Hellman

The roots of `C` over `GF(p)` are exactly the `a_i = g^{e_i}` (they are all in
the base field, so `gcd(C, X^p - X) = C`). We split `C` into linear factors with
Cantor - Zassenhaus (random `r`, `gcd(C, (X+r)^((p-1)/2) - 1)`), isolating each
`a_i`. Degree is only 24, so this is instant.

Then, since `a_i = g^{e_i}`, each exponent is a **discrete log** base `g`. The
challenge deliberately built `p-1` from small primes so this is easy:

```
p - 1 = 2 · 281833 · 784577 · 2614081        (all < 2^22)
```

Pohlig - Hellman reduces each discrete log to a subgroup of order < 2^22, solved
by baby-step giant-step (~2048 steps each), then CRT. All 24 exponents recovered.

## Recovering the coefficients

With the `a_i` known, `log[j] = sum_i c_i a_i^j` is again a linear system - a
24×24 Vandermonde matrix `V[j][i] = a_i^j` - solved mod `p`.

Important pitfall: the mapping `a_i -> e_i = dlog(a_i)` is **not order
preserving**, so you must solve the Vandermonde for coefficients in the *same
order* the roots came out, then attach each coefficient to its own exponent via
`dlog`, and only then sort by exponent. Sorting the root values and the
exponents independently (a natural-looking shortcut) silently mismatches the
pairs and fails the AES-GCM tag check.

Verification: the recovered term list reproduces *all 48* published evaluations
exactly (`verify recurrence: True`).

## Unsealing the flag

```
key = sha256(";".join(f"{e}:{c}" for (e,c) in terms_sorted_by_e))
```

AES-GCM decrypt with the published nonce/tag yields:

```
isfcr{pr0ny_kn3w_1t_1n_1795}
```

The flag is a nod to Gaspard de Prony, who solved exactly this problem
(sum of exponentials from sparse samples) in 1795.

## Reproduce

```
cd sparse-change
/usr/bin/python3 solve.py
# -> FLAG: b'isfcr{pr0ny_kn3w_1t_1n_1795}'
```

Runtime: < 1 second (sympy for `factorint`, pycryptodome for AES-GCM; the
polynomial / dlog code is pure Python since sizes are tiny).

