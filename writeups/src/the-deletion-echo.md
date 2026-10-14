# The Deletion Echo

**Event:** CryoVault CTF 2026
**Category:** ai
**Flag:** `isfcr{763c8479fac095a9e471ad3d}`

---

## 0. The handout

`the_deletion_echo.zip` contains exactly two files:

* `data.json` (230 KB) - a `contract` block, `snapshots`, `candidates`, `ingest` batches,
  and `queries`;
* `unlock.py` - takes a JSON list, `json.dumps` it, derives a key
  `scrypt(b'isfcr-ml\0' + enc, salt, n=131072, r=8, p=1, dklen=32)` and
  AES-GCM-decrypts a sealed blob; correct answer → flag.

The contract describes a fleet of ridge-regression releases over 12-D feature vectors
`x[j] = (raw[permutation[j]] − center[j]) / scale[j]` (no intercept), labels in `{0,1,2,3}`:

* `training`: `H = Σ x xᵀ + ridge·I`, `theta = H⁻¹ Σ x y`, `ridge` a multiple of 1/16 (unpublished);
* `oracle`: `mean = qᵀtheta + e_m` and
  `predictive_variance = noise_variance·(1 + qᵀ H⁻¹ q)·(1 + e_v)`, rounded to 12 sig-digits;
* `history`: snapshots unordered; some consecutive versions of one service; one stale redeploy;
  ingest batches unordered/unlabelled; **the deletion was fulfilled by exact retraining in the
  same release as one ingest batch**;
* `deletion`: the deleted records are a unique subset of `candidates`, once each;
* `encoding`: ASCII-sort `record-id:label` strings for every deleted record.

The quantity we must return is (deleted record id, its label) for each deleted record.

## 1. Inverting the oracle: H and theta fall straight out

There are 240 queries per snapshot and 5 snapshots. Two clean least-squares fits per snapshot
recover the whole model:

* **predictive_variance.** Write `qᵀMq = Σ_i M_ii q_i² + 2Σ_{i<j} M_ij q_i q_j`. So
  `pv` is *affine* in the 78 monomials `q_i q_j` (i≤j) plus a constant. A 79-parameter
  least-squares over 240 equations fits to a max residual of ~1e-8 (the 12-sig-digit rounding).
  The constant term is `noise_variance`; the rest gives `M = H⁻¹`, hence `H = M⁻¹`.
* **mean.** `mean = qᵀtheta`, 12 parameters, fits to ~1e-8. Recovered `theta` is *exact* to
  rounding.

Then the label moments are `T := H·theta = Σ_{records in the model} x_r·y_r` - a 12-vector per
release. `H` depends only on the *features* of the training records (not labels); `T` carries
all the label information.

## 2. The chain and the stale redeploy

Grouping the five snapshots by `H` collapses them to **four distinct models** - the pair
`snapshot-d1f54facd170` / `snapshot-80794d4ee21c` is bit-identical (`max|ΔH| ≈ 3.6`, versus
~10⁵ for genuinely different releases). That is the "stale redeploy".

The four models form the chain **A = 2ee90f53b5c2 → B = d1f54facd170 → C = e385b6f3720a →
D = 9ccbadef83c2**. Ordering follows from which differences are *sparse*:

```
A→B :  H_B − H_A  = Σ x xᵀ  over ingest-5798d74d (12 records)            (pure ingest)
C→D :  H_D − H_C  = Σ x xᵀ  over ingest-578b7698 (9 records)             (pure ingest)
B→C :  H_C − H_B  = Σ x xᵀ(ingest-e0449f2a) − Σ x xᵀ(26 candidates)      (the deletion release)
```

A→B and C→D are reconstructed to a max residual of ~5 on entries of magnitude ~10⁶ (pure
float noise on `inv(M)`), so they are exact single-batch additions. B→C is the release the
contract promises: one ingest batch **and** a deletion, fused by exact retraining.

## 3. Naming the deleted records

Because `H = Σ x xᵀ + ridge·I` and `ridge` cancels in a difference of releases, and because a
record's Gram matrix `x xᵀ` enters additively (independent of its label), the deleted set is
isolated directly:

```
target := − vec( H_C − H_B − Σ_{ingest-e0449f2a} x xᵀ )  ==  Σ_{deleted} vec(x xᵀ)
```

Greedily matching `target` against the 140 candidates' `vec(x xᵀ)` yields **26 records with
coefficient exactly 1.0** and a residual of ~5 (i.e. exact). No other subset reproduces the
difference. The 26:

```
record-0730706150 record-28c0bbf813 record-2e6662ecc6 record-3de105d25d record-3ee76f33c8
record-46126dd779 record-473e486afd record-49aa7c51a4 record-507645d5d9 record-58fad90382
record-5bc7d8554c record-66f65f5026 record-71fb3e266c record-7796490f27 record-77a4509144
record-8f4b4073f9 record-90769aad7a record-978b124800 record-9cddf7a4fb record-9cfdc74744
record-b9e67b6811 record-cf44aec78a record-cf4fee237a record-d32fd7d5d5 record-ebfb2ad09e
record-ee9e7ec4d8
```

## 4. Recovering the labels (the interesting part)

We now need each deleted record's label, plus - unavoidably - the labels of the *unlabelled*
ingest batch that shipped with the deletion. The label moments give one 12-vector equation:

```
T_C − T_B = Σ_{ingest-e0449f2a} x·y  −  Σ_{deleted} x·y
```

That is 12 equations in 10 + 26 = 36 integer unknowns `y ∈ {0,1,2,3}` - wildly
underdetermined as a *real* system. Two ways to screw this up:

* The **regression itself does not leak labels.** This release is deliberately
  over-regularised: `x_rᵀtheta` for training records is uncorrelated-ish with `y_r`
  (corr 0.42), predictions sit in [−2.7, 2.4] rather than on {0,1,2,3}. You cannot read a
  label off a prediction.
* **The min-norm / least-squares solution is not the answer** (it produces values like −3.56,
  clearly outside the label set).

The way through is that the system is exactly integral. `scale ∈ {1,2,4}`, so `4·x` is an
integer vector; with integer labels `4A·y = 4·ΔT` where `A = [X_batchᵀ | −X_deletedᵀ]` is a
12×36 **integer** matrix and the right-hand side is a **12-vector of integers** (we verify
`4·ΔT` rounds to integers within 0.02). Now:

```
vol( box ) / covol( column lattice of 4A )
        =  4³⁶ / √det( 4A · (4A)ᵀ )   ≈  4.7e21 / 4.3e37   ≈  1e-16
```

so the box `[0,3]³⁶ ∩ {4A y = 4·b}` contains **essentially surely exactly one** integer point.
A tiny MILP - 36 integer variables, 12 exact equality constraints, bounds `[0,3]` - returns it
(solved to optimality, residual 0). The first 10 values are the ingest batch's labels; the last
26 are the deleted records' labels (indices aligned with the list above):

```
ingest-e0449f2a labels : 2 0 1 3 0 2 2 2 2 2
deleted labels         : 0 0 2 1 2 2 1 1 0 0 0 0 2 3 1 3 0 2 1 2 1 1 3 2 1 2
```

## 5. Encode and open

ASCII-sort the 26 `record-id:label` strings and hand them to `unlock.py`:

```bash
python3 unlock.py '["record-0730706150:0", ... ,"record-ee9e7ec4d8:1"]'
# -> isfcr{763c8479fac095a9e471ad3d}
```

The scrypt step (n=131072 → ~134 MB) is the only slow part.

## 6. Dead ends worth recording

* **Predicting labels from the model.** Predictions are over-shrunk (`corr(θᵀx, y) ≈ 0.42`).
  Calibrating a linear map on the *known*-label ingest batches gives max residual 1.8 - useless.
* **Ordering snapshots by value/ivory.** Only the *sparsity* of `H` differences orders the
  chain; cross-lineage differences (A→C, A→D, B→D) are dense and explain nothing by themselves.
* **Hoping the ingest batch's labels are "obvious"** (e.g. all zero) so `ΔT` isolates the
  deleted labels - false; the min-norm solve is non-integer.
* **Naive LLL/Babai on an embedding** to hit the box: the HNF particular solution has ~1e22
  coordinates and float Babai `round()` loses everything. The MILP on the *original* small-integer
  system is the robust route.
* An earlier bug - implementing the column-HNF negation as `A[:,c] -= (−2)·A[:,c]`
  (i.e. `·3`) instead of `·(−1)` - manufactured a spurious divisor-3 obstruction and briefly
  looked like "no integer solution exists". Fixing it made all 12 HNF denominators 1.

## 7. Files

* `solve.py` - end-to-end solver (oracle inversion → stale-collapse → chain → deletion set →
  integral label MILP → answer), prints ANSWER and FLAG.
* `data.json`, `unlock.py`, `the_deletion_echo.zip` - handouts, unchanged.

