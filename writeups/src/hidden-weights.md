# hidden-weights

**Event:** CryoVault CTF 2026
**Category:** crypto
**Flag:** `isfcr{0rth0g0n4l_l4tt1c3_1s_th3_tr1ck}`

---

`chall.py` picks `n = 10` secret weights `a_1..a_n` uniformly in `Z_M` with `M = nextprime(2^200)`, plus a secret `m = 50` column 0/1 matrix `X`, and publishes only the 50 sums

```
h_j = sum_i a_i * x_{i,j}   (mod M),      x_{i,j} in {0,1}
```

Both the weights **and** the selection subsets are hidden. The flag is AES-GCM encrypted with `key = SHA256(",".join(sorted(weights)))`, so the weights must be recovered exactly as integers in `[0, M)`.

The challenge text warns that "the usual lattice does not apply" - in ordinary subset-sum the weights are public and you search for the subset; here both are secret, so the classic `(I | h)` embedding is useless. The intended trick is the **orthogonal (relation) lattice**.

**Key observation:** Let `X` be the `n x m` matrix whose column `j` is the indicator of the `j`-th hidden subset, so the published data is `h == X^T a (mod M)`. For any integer vector `c in Z^m`, `c . h == a . (X c) (mod M)`. If `c` lands in the integer kernel of `X` (`X c == 0`), the relation holds **exactly**. Because `X` is 0/1, `ker(X)` is a rank-`(m - n) = 40` lattice **packed with very short vectors** (e.g. `h_19 == h_20` in the data means two columns are identical, giving a relation of norm `sqrt(2)`).

**The lattice:** the full relation lattice `R = { c in Z^m : c . h == 0 (mod M) }` has rank `m = 50` and covolume `M`. A basis is immediate since `h_0` is invertible mod `M`:

```
b_0        = M * e_0
b_j        = e_j + ((-h_j * h_0^{-1}) mod M) * e_0      (j = 1..m-1)
```

LLL-reducing the resulting `50 x 50` basis yields a clean split: 40 short vectors (norm² ≤ 9) spanning `ker(X)`, and 10 huge ones. The orthogonal complement of the short vectors is the row space `W` of `X`, dimension 10.

**Recovering the secret 0/1 rows:** `W` contains exactly the 10 rows of `X` as its only 0/1 vectors. Solve the homogeneous 0/1 system `S v == 0, v in {0,1}^50` where `S` is the 40 short kernel vectors - rank 40, so 10-dimensional solution space. Brute-force all `2^10` 0/1 assignments to the 10 free columns, back-substituting the 40 pivot coordinates. Output: the zero vector plus exactly 10 non-zero 0/1 vectors - the secret rows of `X`.

**Solve for the weights:** with `X` known, `a == (X X^T)^{-1} X h (mod M)`. The recovered weights reproduce all 50 published sums exactly. Then `key = SHA256(",".join(sorted(a)))` decrypts the flag.

```
pip install fpylll sympy pycryptodome
python3 solve.py
# -> [+] FLAG: isfcr{0rth0g0n4l_l4tt1c3_1s_th3_tr1ck}
```

Runtime: a few seconds (one LLL of a 50-dim lattice, then `2^10` back-substitutions). With `m = 50 > n = 10` the data is massively overdetermined, and the 0/1 constraint makes `ker(X)` a low-covolume lattice full of tiny vectors - no subset-search over the 2^500 selection space needed.
