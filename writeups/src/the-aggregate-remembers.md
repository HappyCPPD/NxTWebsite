# the-aggregate-remembers

**Event:** CryoVault CTF 2026
**Category:** ai
**Flag:** `isfcr{9b1aa6a53205a859c14cc5e4}`

---

A federated linear-regression client leaked its per-round weight updates: `delta = -lr * (weighted_mean_gradient + weight_decay * weights)`. The task is to invert that to recover the target client's *raw training records*.

**Data model:** 16-byte records map through a permutation/center/scale feature transform to a 17-D feature vector (16 features + bias); all labels are `1`; 3 clients mix per round with integer weights; 6 distinct weight checkpoints are reused across 61 rounds.

**Step 1 - per-checkpoint gradient recovery.** Expanding the round-update equation, `g_r[i]` (a component of the un-scaled gradient) depends only on row `i` of each client's second-moment matrix `S_c` and `t_c[i]`. Because only 6 distinct checkpoints appear across 60 rounds, the per-component observation matrix has rank exactly `3 clients × 6 checkpoints = 18` - the *only* identifiable quantity is `h_c(w) = S_c w - t_c` at each of the 6 checkpoints per client. A 60-equation least-squares per component recovers all 18 unknowns with residual < 0.011 (confirmed exactly rank 18; using *unnormalized* mixing weights instead of `mix/sum(mix)` breaks this to rank 5 with huge residuals, confirming the normalization convention).

**Step 2 - batch size is 2, and the record subspace is 2-D.** `h_c(w_k) - h_c(w_0) = S_c(w_k - w_0)`; for a 2-record batch `S_c` is rank-2 in outer-product terms, so the matrix of these differences has rank ≤ 2. Singular values confirm exactly two large values then noise for all three clients - each client's batch is exactly **two records**, and their span is the 2-D record subspace.

**Step 3 - solve for the two records.** A small nonlinear least-squares over the 2 unknown feature vectors (with the known bias constraint `x[16]=1`), initialized by projecting into the recovered 2-D subspace, converges instantly against the 6 checkpoint equations. Un-scaling (`raw = x*scale + center`, un-permuted) lands within 0.2 of integers.

```
["07841f68cb73fe5aac5cbf66f113f992", "ff1247cd40f11a77f9495f7ba9648a20"]
python
python3 unlock.py '["07841f68cb73fe5aac5cbf66f113f992","ff1247cd40f11a77f9495f7ba9648a20"]'
isfcr{9b1aa6a53205a859c14cc5e4}
```

`unlock.py` derives the AES-GCM key as `sha256(b'isfcr-ml\0' + json(answer))` - a hard correctness check requiring the exact ASCII-sorted list. The attack hinges on checkpoint reuse: with only 6 distinct weight vectors, per-component identifiability caps at 18, exactly enough to pin `S_c w - t_c` at those points, and the rank-2 signature of a 2-record batch turns 6 points into an exactly solvable system. The one `acquisition-B` round present in the data is an unused decoy.
