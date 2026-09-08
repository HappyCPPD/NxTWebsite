# MATH OR METH?

**Event:** TFC CTF 26
**Category:** crypto
**Points:** 298
**Flag:** `TFCCTF{this_is_a_very_very_long_flag_for_a_short_ctf_chall_ggs}`

---

## Overview

The challenge encodes the flag body as a vector of little-endian base-33 digits
and plants it as one row of a small random matrix `A` (57 rows, 88 columns). It
publishes only the product

```text
h = a * A  (mod p)
```

for a secret row vector `a` and a 1084-bit prime `p`, and withholds both `a` and
`A`. The goal is to recover the planted row.

## The digit vector

```python
base = B + 1  # 33
while x:
    row.append(x % base)
    x //= base
```

So the planted row `f` satisfies `x = sum(f[j] * 33**j)` with every coordinate in
`[0, 32]`. Recovering `f` and reading it as base-33 gives the flag body.

## Vulnerability

Work in the lattice of integer vectors that are consistent with the single
published modular relation:

```text
L = { v in Z^88 : <h, v> = 0 (mod p) }
```

Every integer null-vector of `A` lies in `L`, because `A v = 0` implies
`<h, v> = a A v = 0`. With 57 rows and 88 columns, `A` has expected nullity
`88 - 57 = 31`, and those 31 null-vectors are short since every entry
of `A` is small. Any vector that only satisfies the modular relation is huge by
comparison, on the order of `p`. LLL on `L` therefore recovers exactly the 31
short null-relations.

::: insight
Two rounds of LLL. The first recovers the null-space of the hidden matrix as
short vectors. Stack them into `Y`. Every original row of `A` is orthogonal to
`Y`, so the integer right kernel of `Y` contains the row lattice of `A`. A
second LLL on that kernel produces short vectors in the hidden row lattice. One
of them, up to sign and small combinations, has all 88 coordinates in `[0, 32]`
and decodes to printable text.
:::

## Solver

```python
# SageMath, run from the challenge directory
inv = inverse_mod(h[0], p)
rows = [[p] + [0] * (m - 1)]
for j in range(1, m):
    v = [0] * m
    v[0] = ZZ((-h[j] * inv) % p)
    if v[0] > p // 2:
        v[0] -= p
    v[j] = 1
    rows.append(v)

K = Matrix(ZZ, rows).LLL(delta=0.999)
short = [v for v in K.rows() if v.norm() < 10000]      # ~31 of these

Y = Matrix(ZZ, short).row_space().basis_matrix()
R = Y.right_kernel_matrix().LLL(delta=0.999)           # hidden row lattice

def decode(v):
    if min(v) < 0 or max(v) > B:
        return None
    x = sum(ZZ(v[i]) * ZZ(B + 1) ** i for i in range(m))
    return int(x).to_bytes((int(x).bit_length() + 7) // 8, 'big')

# search the short basis, its signs, and modest pairwise combinations
candidates = list(R.rows())
for i in range(R.nrows()):
    for j in range(i):
        candidates += [R[i] + R[j], R[i] - R[j], -R[i] + R[j], -R[i] - R[j]]
for v in candidates:
    for w in (v, -v):
        msg = decode(w)
        if msg and (b'TFCCTF' in msg or all(32 <= c < 127 for c in msg)):
            print('CANDIDATE', msg)
```

```session
$ sage solve_math_or_meth.sage
short modular relations: 31
relation rank: 31
row lattice: 57 88
CANDIDATE b'this_is_a_very_very_long_flag_for_a_short_ctf_chall_ggs'
```

The challenge source wraps the recovered body in `TFCCTF{}`.

## Flag

```text
TFCCTF{this_is_a_very_very_long_flag_for_a_short_ctf_chall_ggs}
```
