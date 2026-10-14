# implicit-twins

**Event:** CryoVault CTF 2026
**Category:** crypto
**Flag:** `isfcr{1mpl1c1t_f4ct0r1ng_0f_tw1ns}`

---

## Challenge

```
Two 1280-bit RSA keys, separated at birth. Neither of them will talk alone.
```

`chall.py` builds two moduli:

- `N1 = p1*q1`, `N2 = p2*q2`
- `p1`, `p2` are 1024-bit primes drawn from one broken generator: they share a run
  of low bits. `q1`, `q2` are independent 256-bit primes (from `nextprime`).
- `p1 ≡ p2 (mod 2^T)`, with `T = 530` (secret in the flavour text, but the
  distributed generator source pins it; the recovered instance was even a touch
  luckier at `T = 531`).
- Flag is textbook RSA (`e = 65537`) under `N1`.

No common factor, no small primes, no close `q`. The only weakness is the shared
low-bit block of `p1` and `p2`.

This is the **Implicit Factorization Problem** (May - Ritzenhofen / Sarkar - Maitra).
The twist here is that the two primes of each modulus are wildly unbalanced
(`p` 1024-bit vs `q` 256-bit), which makes an *elementary two-dimensional
lattice* attack enough - no Coppersmith/LLL over a big lattice required.

## The trick

```
N1 = p1*q1,   N2 = p2*q2,   p1 - p2 = 2^T * k
```

Substitute and cross-multiply:

```
q1*N2 - q2*N1 = q1*q2*(p1 - p2) = 2^T * k * q1 * q2
```

so

```
q1*N2 ≡ q2*N1   (mod 2^T)
```

Both `q1, q2 < 2^256`, i.e. tiny compared to the modulus `2^T ≈ 2^530`.
Consider the 2-D lattice

```
L = { (a, b) in Z^2 : a*N2 - b*N1 ≡ 0  (mod 2^T) }
```

`det(L) = 2^T`, so its shortest vector is `≈ 2^(T/2) ≈ 2^265` by Minkowski.
The target vector `(q1, q2)` has length `≈ 2^256.5` - **shorter** than the
generic shortest vector, so it *is* the shortest vector (given `T` is large
enough, `T ≳ 513`). A plain **2-D Gauss reduction** finds it.

A basis is `{ (2^T, 0), (N1 * N2^-1 mod 2^T, 1) }` (valid since `N2` is odd and
invertible mod `2^T`). Reduce, take the short vector `(±q1, ±q2)`, then
`p1 = N1/q1`, `phi = (p1-1)(q1-1)`, standard RSA decrypt.

`solve.py` simply sweeps `T` downward from 700 and stops on the first short
vector that actually divides `N1` and `N2` - so it does not need `T` to be
leaked. It fires at `T = 531`.

## Solve

```
$ python3 solve.py
[+] hit at T=531:  q1=64786...93731
                   q2=101170...328241
[+] shared low bits confirmed (>=200)
[+] flag: b'isfcr{1mpl1c1t_f4ct0r1ng_0f_tw1ns}'
```

Full flag file: `flag.txt`. Reproducible from the two distributed files alone.

## Why the unbalanced primes matter

Because `bits(q) << bits(p)`, the shared-bit run `T` exceeds `bits(q)`. That
turns a hard bivariate Coppersmith problem into "find the small kernel vector of
a linear congruence mod `2^T`" - a textbook 2-D lattice reduction. With balanced
primes you would need the full May - Ritzenhofen lattice and many more samples.

