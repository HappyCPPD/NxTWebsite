# hidden-weights

**Event:** CryoVault CTF 2026
**Category:** crypto
**Flag:** `isfcr{0rth0g0n4l_l4tt1c3_1s_th3_tr1ck}`

---

## 1. The problem

`chall.py` picks `n = 10` secret weights `a_1..a_n` uniformly in `Z_M`
with `M = nextprime(2^200)`, plus a secret `m = 50` column 0/1 matrix
`X`, and publishes only the 50 sums

```
h_j = sum_i a_i * x_{i,j}   (mod M),      x_{i,j} in {0,1}
```

Both the weights **and** the selection subsets are hidden. The flag is
AES-GCM encrypted with

```
key = SHA256(",".join(sorted(weights)))
```

so we must recover the weights *exactly* as integers in `[0, M)`.

The challenge text warns that "the usual lattice does not apply" - in
ordinary subset-sum the weights are public and you search for the
subset; here both are secret, so the classic `(I | h)` embedding is
useless. The intended trick is the **orthogonal (relation) lattice**.

## 2. Key observation

Let `X` be the `n x m` matrix whose column `j` is the indicator of the
`j`-th hidden subset, so the published data is

```
h  ==  X^T a   (mod M).
```

For any integer vector `c in Z^m`,

```
c . h  ==  a . (X c)   (mod M).
```

If `c` lands in the integer kernel of `X` (`X c == 0`), the relation
holds **exactly**, i.e. `c . h == 0 (mod M)`. Because `X` is 0/1,
`ker(X)` is a rank-`(m - n) = 40` lattice **packed with very short
vectors**:

* `h_19 == h_20` in the data, so `e_19 - e_20` is a relation of norm
  `sqrt(2)` (the two columns of `X` are identical);
* two columns whose integer sum coincides (e.g. `x_a + x_b = x_c + x_d`)
  give relations like `e_a + e_b - e_c - e_d` of norm `2`.

A "generic" element of the relation lattice is long (~26 here), so
lattice reduction cleanly separates `ker(X)` from everything else.

## 3. The lattice

The full relation lattice

```
R = { c in Z^m : c . h == 0 (mod M) }
```

has rank `m = 50` and covolume `M`. Since `h_0` is invertible mod `M`
(this is exactly why `chall.py` retries until `gcd(h_0, M) == 1`), a
basis is immediate:

```
b_0        = M * e_0
b_j        = e_j + ((-h_j * h_0^{-1}) mod M) * e_0      (j = 1..m-1)
```

`b_j . h = -h_j + h_j = 0 (mod M)`.

LLL-reducing the resulting `50 x 50` basis yields a clean split:

```
norm^2 of reduced basis:  [2, 4, 4, ..., 9,  <then 10 vectors ~6e10>]
                              \_____ 40 short ____/   \__ n long __/
```

Exactly `m - n = 40` short vectors (norm² ≤ 9) - these span `ker(X)` -
and `n = 10` huge ones. The **orthogonal complement of the short
vectors is the row space `W` of `X`**, of dimension `n = 10`.

## 4. Recovering the secret 0/1 rows

`W` contains exactly the 10 rows of `X` as its only 0/1 vectors (the
rows are dense random binary, so accidental 0/1 combinations are
essentially impossible). Find them by solving the homogeneous 0/1
system

```
S v == 0,   v in {0,1}^50,    S = the 40 short kernel vectors.
```

`S` has rank 40, so the solution space is 10-dimensional: take its RREF,
pick the 10 free columns, and brute-force all `2^10 = 1024` 0/1
assignments to the free coordinates, back-substituting the 40 pivot
coordinates and keeping the integral 0/1 results. Output: the zero
vector plus exactly **10 non-zero 0/1 vectors - the secret rows of `X`**.

## 5. Solve for the weights and decrypt

With `X` known the system is linear:

```
(X X^T) a  ==  X h   (mod M)     =>     a == (X X^T)^{-1} X h  (mod M).
```

`det(X X^T)` is invertible mod `M` (checked). The recovered weights
reproduce all 50 published sums exactly (`X^T a == h mod M`), which is a
complete independent verification. Then

```
key = SHA256(",".join(sorted(a)))
pt  = AES-GCM-decrypt(flag_ct, key, nonce="hidden-wts--", tag=flag_tag)
```

```
isfcr{0rth0g0n4l_l4tt1c3_1s_th3_tr1ck}
```

The flag name - *orthogonal lattice is the trick* - confirms the method.

## 6. Reproduce

```
pip install fpylll sympy pycryptodome
python3 solve.py
# -> [+] FLAG: isfcr{0rth0g0n4l_l4tt1c3_1s_th3_tr1ck}
```

Runtime: a few seconds (one LLL of a 50-dim lattice, then `2^10`
back-substitutions).

## 7. Why it works (intuition)

With `m = 50 > n = 10` the data is massively overdetermined, and the
0/1 constraint makes `ker(X)` a low-covolume lattice full of tiny
vectors. LLL pulls those out first; their orthogonal complement pins
down the row space of the hidden selection matrix, and the 0/1 points of
that space *are* the secret matrix. Everything else (weights, key,
plaintext) follows by linear algebra. No subset-search, no brute force
over the 2^500 selection space.

