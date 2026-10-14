# the-aggregate-remembers

**Event:** CryoVault CTF 2026
**Category:** ai
**Flag:** `isfcr{9b1aa6a53205a859c14cc5e4}`

---

## TL;DR

A federated linear-regression client leaked its per-round weight updates. Each round's
update is `delta = -lr * (weighted_mean_gradient + weight_decay * weights)`. We invert
that to recover the *mean gradient of each client at each training checkpoint*, show
the target client's per-checkpoint gradient lies on a rank-2 affine map (so its batch is
exactly two records), project into the resulting 2-D subspace, and solve a small
nonlinear least-squares for the two 16-byte raw records.

Recovered records (ASCII-sorted, lowercase hex):

```
07841f68cb73fe5aac5cbf66f113f992
ff1247cd40f11a77f9495f7ba9648a20
```

Flag: `isfcr{9b1aa6a53205a859c14cc5e4}`

## Data model

`data.json`:

- `model.dimension = 16` - each raw record is 16 bytes.
- Feature map: `x[j] = (raw[permutation[j]] - center[j]) / scale[j]` for `j = 0..15`,
  then a constant bias `x[16] = 1`. So the weight vector is 17-D (`dimension + 1`).
- Every example has label `1`.
- `lr = 1/8`, `weight_decay = 1/64`.
- 3 clients: `['5bd9ed5b49', '6806bb153e', '41940163bb']`; target = `6806bb153e` (index 1).
- 6 checkpoints (each a 17-D weight vector) and 61 round updates. 60 are
  `cohort = "acquisition-A"`; one is `acquisition-B` (decoy / not used).
- Each update carries `checkpoint` (the pre-round weights `w`), `mix` (per-client mixing
  weights, integers 1..3), and the observed 17-D `delta`.

Loss is the mean half-squared error. With label `1`, the per-example gradient is
`(w·x - 1) x`. For a client `c` with batch `B_c` (fixed across rounds) define the mean
gradient

```
grad_c(w) = mean_{x in B_c} (w·x - 1) x = S_c w - t_c
S_c = mean_{x in B_c} x xᵀ   (17x17, symmetric)
t_c = mean_{x in B_c} x      (17)
```

The round update is

```
delta_r = -lr * ( sum_c (m_{r,c}/M_r) grad_c(w_r) + wd * w_r )
=>  g_r := -delta_r/lr - wd*w_r = sum_c beta_{r,c} (S_c w_r - t_c),  beta = mix/M
```

## Step 1 - recover each client's gradient at each checkpoint (identifiability)

Component `i` of `g_r` depends only on row `i` of each `S_c` and `t_c[i]`:

```
g_r[i] = sum_c beta_{r,c} * h_c(w_r)[i],   h_c(w) := S_c w - t_c
```

Because all rounds share only 6 distinct checkpoints, the per-component observation
matrix is `sum_c beta_{r,c} e_c ⊗ [w_r, -1]`, whose rank is exactly `3 clients x 6
checkpoints = 18`. Confirmed numerically: a global least-squares on the naive
`(A_c, b_c)` unknowns has rank 306 `= 18 x 17` (heavily underdetermined), but per
component it is rank 18. So the *only* thing identifiable is

```
h_c(w) = S_c w - t_c   for each client c and each of the 6 checkpoint weights w.
```

We solve a 60-equation least-squares per component for the 18 unknowns
`{h_c(w_k)[i]}` (coefficient `beta_{r,c}` on the matching checkpoint). Residual < 0.011,
rank 18 exactly. Using normalized `beta = mix/M`; the unnormalized variant gives rank-5
differences and huge residuals, confirming `mix` is normalized.

## Step 2 - batch size and the 2-D record subspace

For a client, `h_c(w_{k}) - h_c(w_{0}) = S_c (w_k - w_0)`. Since (for a 2-record batch)
`S_c = ½(x1x1ᵀ + x2x2ᵀ)`, every such difference is a combination of `x1` and `x2`, so
the matrix of differences has rank ≤ 2:

```
client 5bd9ed5b49 : [9.07e1, 4.60e1, 5.3e-2, 3.4e-2, 2.6e-2]
client 6806bb153e : [1.84e2, 5.44e1, 5.6e-2, 3.7e-2, 2.2e-2]   <-- target
client 41940163bb : [8.42e1, 3.54e1, 4.5e-2, 3.0e-2, 1.7e-2]
```

Two large singular values then noise ⇒ each client's batch is exactly **two** records,
and the record space `U = span{x1, x2}` is the 2-D column space of the differences.

## Step 3 - solve for the two records

`h_c(w) = ½( x1(x1·w) + x2(x2·w) − x1 − x2 )` for the 6 checkpoints, with the constraint
`x1[16] = x2[16] = 1` (bias feature). Non-linear least squares over `x` (initialized by
projecting into `U`) converges instantly. Raw bytes `raw[perm[j]] = x[j]*scale[j] +
center[j]` land within 0.2 of integers:

```
x1 -> [255, 18, 71, 205, 64, 241, 26, 119, 249, 73, 95, 123, 169, 100, 138, 32]
x2 -> [  7, 132, 31, 104, 203, 115, 254, 90, 172, 92, 191, 102, 241, 19, 249, 146]
```

Rounded to uint8 and hex-encoded (ASCII-sorted):

```
["07841f68cb73fe5aac5cbf66f113f992", "ff1247cd40f11a77f9495f7ba9648a20"]
```

## Verify

```
python3 unlock.py '["07841f68cb73fe5aac5cbf66f113f992","ff1247cd40f11a77f9495f7ba9648a20"]'
isfcr{9b1aa6a53205a859c14cc5e4}
```

`unlock.py` derives the AES-GCM key as `sha256(b'isfcr-ml\0' + json(answer))`, so only
the exact ASCII-sorted list decrypts - the flag is a hard correctness check.

## Reproduce

```
python3 solve.py     # (optional) shows the rank-306 naive system
python3 stage1.py    # recovers h_c(w) per client/checkpoint  -> H_normTrue.npy
python3 stage2.py    # U-projection fit (diagnostic)
python3 stage3.py    # full nonlinear fit -> answer.json
python3 unlock.py "$(cat answer.json)"
```

## Notes / pitfalls

- The `acquisition-B` round is decoy - restricted to `acquisition-A` as stated.
- `mix` must be normalized by its sum; unnormalized breaks the rank-2 signature.
- The whole attack hinges on the *checkpoint reuse*: with only 6 distinct weight
  vectors, per-component identifiability is capped at 18, which is exactly enough to
  pin down `S_c w - t_c` at those 6 points, and the rank-2 structure of a 2-record
  batch turns 6 points into an exactly solvable system.

