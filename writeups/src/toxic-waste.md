# toxic-waste

**Event:** CryoVault CTF 2026
**Category:** crypto
**Flag:** `isfcr{ch30n_8f_th3_c0mpr3ss3d_srs}`

---

> Trusted setup done, secret burned. We kept the two ends and binned the middle
> to save on disk.

## 1. The scenario

`chall.py` runs a KZG-style trusted setup in the multiplicative group of a
prime field. It picks:

- `d = 2^44`, a prime `m`, and `q = d*m + 1` prime (so `d | q-1`, `m` prime);
- a 1024-bit prime `P` with `q | P-1`, and `g` a generator of the order-`q`
  subgroup `G ⊆ GF(P)*`;
- a secret `tau` uniformly in `[2, q-2]`.

The full structured reference string would be `g, g^tau, g^(tau^2), …,
g^(tau^d)`. To "save disk" the deployment keeps only the **two ends**:

```
A = g^tau          # head
B = g^(tau^d)      # tail   (exponent tau^d reduced mod q)
```

The flag is encrypted with `AES-GCM`, key `sha256(str(tau))`, nonce
`b"toxic-waste-"`. The tin claims security is `sqrt(q)`: recovering `tau`
"means solving a discrete log in G". With `q` 88 bits, `sqrt(q) ≈ 2^43.5`,
which sounds safe.

Both claims are wrong. The tail `B = g^(tau^d)` is not decoration - supplied
together with `A = g^tau`, and with `d | q-1`, it is precisely the auxiliary
input that breaks the DLP efficiently via **Cheon's attack**.

## 2. Why the two ends are fatal: Cheon's attack

Cheon's attack ("Discrete Logarithm Problems with Auxiliary Inputs",
J. H. Cheon, *J. Cryptology* 23(3), 2010) solves, in a group of order `q`,

> given `g`, `g^alpha`, and `g^(alpha^d)` with `d | q-1`,

for `alpha` in time `O(sqrt(q/d) + sqrt(d))` rather than `sqrt(q)`. The same
structure appears in real KZG trusted-setup audits (Kobi Gurkan,
*Cheon's attack and its effect on the security of big trusted setups*;
ZK Hack III "Power Corrupts" is essentially this puzzle).

The crux is that `alpha` lives in `Z_q^*`, a group of order `q-1 = d*m`.
Decompose the *exponent* `alpha` using a generator `h` of `Z_q^*`:

```
tau = h^(k0 + k1*m) mod q,     0 <= k0 < m,   0 <= k1 < d.
```

Because `h^(q-1) = 1`, raising to the `d`-th power kills the `k1*m` part:

```
tau^d = h^(d*k0 + k1*(q-1)) = h^(d*k0)   (mod q).
```

So `B = g^(tau^d) = g^(h^(d*k0))` leaks `k0`, and `A = g^tau` then leaks `k1`.
Two baby-step/giant-step phases recover them:

**Phase 1 (recover k0, ~3.35M steps/side).** We want `k0 = i*N + j`. Then
`h^(d*k0) = h^(d*i*N) * h^(d*j)`, hence

```
B = g^(h^(d*i*N) * h^(d*j)).
```

Build a baby table `{ g^(h^(d*j)) : 0 <= j < N }` (each next entry is the
previous one raised to `h^d`). Walk the giant side `B^(h^(-d*i*N))`: when it
lands in the table we have `k0 = i*N + j`.

**Phase 2 (recover k1, ~4.19M steps/side).** With `eta = h^m` (an element of
order exactly `d`),

```
tau = h^k0 * eta^k1,   hence   A^(h^-k0) = g^(eta^k1).
```

Same BSGS with baby sequence `g^(eta^j)` recovers `k1 = i*N2 + j`.

Finally `tau = h^(k0 + k1*m) mod q`.

## 3. Execution

Environment quirk: `2` is **not** a primitive root mod `q` here, so we search
for the smallest generator (`h = 3`). Complexity is `sqrt(m) + sqrt(d)`, i.e.
about `2^22` group operations per phase - utterly feasible.

The run (`solve.py`, gmpy2, builtin `pow` would be ~5x slower):

```
[cheon] generator h = 3
[cheon] part1: N = 3349947        # baby built in 138s, giant match at i=1.41M
[cheon] k0 = 4734199638712
[cheon] part2: N2 = 4194305       # baby built in 186s, giant match at i=2.21M
[cheon] k1 = 9264960971644
[cheon] RECOVERED tau = 53372121991905014611291611
FLAG: isfcr{ch30n_8f_th3_c0mpr3ss3d_srs}
```

Sanity checks embedded in the solver: `g^(h^(d*k0)) == B` and `g^tau == A`
both pass, so `tau` is exact and the key is right.

## 4. Takeaways

- Two-ended SRS (`g^tau`, `g^(tau^d)`) is *not* "just ends"; it is a full
  Cheon auxiliary-input instance whenever `d | q-1`. The real security is
  `O(sqrt(q/d) + sqrt(d))`, not `sqrt(q)`. Here `d = 2^44` splits the exponent
  group into two ~44-bit halves, collapsing `2^43.5` work to `2^22`.
- A "one-way" discrete log is only as hard as the *extra structure in the
  exponent group* allows; factoring `q-1` (and noticing a big power-of-two
  divisor) is the audit step that was skipped.
- The 1024-bit modulus `P` buys nothing: the attack never touches `P`'s
  structure beyond arithmetic in `G`.

**Flag:** `isfcr{ch30n_8f_th3_c0mpr3ss3d_srs}`

