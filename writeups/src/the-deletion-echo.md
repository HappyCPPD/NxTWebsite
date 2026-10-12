# The Deletion Echo

**Event:** CryoVault CTF 2026
**Category:** ai
**Flag:** `isfcr{763c8479fac095a9e471ad3d}`

---

A fleet of ridge-regression releases over 12-D features, with `H = Σ x xᵀ + ridge·I`, `theta = H⁻¹ Σ x y`. An oracle publishes, per query `q`: `mean = qᵀtheta` and `predictive_variance = noise_variance·(1+qᵀH⁻¹q)`, both rounded to 12 significant digits. 5 unordered snapshots, some consecutive, one stale redeploy; unordered/unlabelled ingest batches; the deletion was fulfilled by exact retraining fused with one ingest batch in the same release. Goal: name the deleted records and their labels.

**Step 1 - invert the oracle.** `predictive_variance` is affine in the 78 monomials `q_i q_j` (i≤j) plus a constant - a 79-parameter least-squares over 240 queries per snapshot fits to ~1e-8 residual (matching the 12-sig-digit rounding), recovering `H⁻¹` (hence `H`) and the constant `noise_variance`. `mean = qᵀtheta` is a separate 12-parameter fit recovering `theta` exactly. Then `T := H·theta = Σ x_r·y_r` - the "label moment" vector - carries all label information for a release.

**Step 2 - order the releases, find the stale redeploy.** Grouping the 5 snapshots by `H` collapses two of them to bit-identical matrices - the stale redeploy. The remaining four distinct models form a chain `A→B→C→D`, ordered by which `H`-differences are **sparse** (pure single-ingest-batch additions for A→B and C→D) vs. dense (the B→C transition, which fuses one ingest batch with the deletion - the release the contract promises).

**Step 3 - isolate the deleted record set.** Because `ridge·I` cancels in a difference of releases and `x xᵀ` enters additively independent of label, `target := -(H_C - H_B - Σ_ingest x xᵀ) = Σ_deleted x xᵀ`. Greedily matching `target` against 140 candidates' own `x xᵀ` finds **26 records with coefficient exactly 1.0** and near-zero residual - an exact, unique match.

**Step 4 - recover the labels via integer MILP.** The label-moment difference `T_C - T_B = Σ_ingest x·y - Σ_deleted x·y` gives only 12 equations in 36 unknown labels `y ∈ {0,1,2,3}` - wildly underdetermined as a real system, and the regression doesn't leak labels directly (predictions are over-shrunk, corr with true labels only 0.42). The resolution: since `scale ∈ {1,2,4}`, `4x` is integer, so `4A·y = 4ΔT` is an exact **integer** system; the box `[0,3]^36` intersected with this affine constraint has covolume ratio ~1e-16, so it contains essentially surely exactly one integer point. A small MILP (36 integer variables, 12 equality constraints, bounds [0,3]) finds it exactly.

```
ingest-e0449f2a labels : 2 0 1 3 0 2 2 2 2 2
deleted labels         : 0 0 2 1 2 2 1 1 0 0 0 0 2 3 1 3 0 2 1 2 1 1 3 2 1 2
bash
python3 unlock.py '["record-0730706150:0", ... ,"record-ee9e7ec4d8:1"]'
# -> isfcr{763c8479fac095a9e471ad3d}
```

Dead ends recorded: predicting labels from the shrunk regression itself (useless, corr 0.42); assuming the ingest batch's labels are trivially all-zero (the min-norm solve is non-integer, so this fails); naive LLL/Babai lattice rounding on an embedding (the HNF particular solution has astronomically large coordinates and float rounding loses everything - the MILP on the original small-integer system is the robust route); and an HNF sign bug (`·3` instead of `·(-1)`) that manufactured a spurious divisor-3 obstruction before being caught.
