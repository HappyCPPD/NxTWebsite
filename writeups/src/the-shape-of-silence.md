# the-shape-of-silence

**Event:** CryoVault CTF 2026
**Category:** ai
**Flag:** `isfcr{577027585a0778773aa949d9}`

---

## Challenge
`data.json` describes a black-box model `f: R^6 -> R` that "returns exact rational
outputs". We are given:
- `model_version`: `v-8fb4ff`, `dimension`: 6
- `anchors`: 16 labelled points `(x, y)`
- `captures`: 22 records, each with a `model_version` and `clouds` = two clusters of
  7 points `(x, y)` each
- `targets`: 24 unlabelled inputs

We must output `f(target)` for all 24 as reduced rational strings and feed them to
`unlock.py` (AES-GCM; key = SHA256(`isfcr-ml\0` + JSON of the answer)).

## Step 1 - The model is piecewise-linear (integer weights)
A `cloud` has exactly **7 points in R^6**. Seven points determine an affine function
uniquely (7 unknowns, 7 equations), so *any* cloud is trivially "affine-fittable". The
signal is that **every** one of the 44 cloud fits came out with **exact integer
coefficients** (e.g. cap0/cloud0 → `b=-2, g=(-15,-11,12,-5,-2,-1)`).

For a smooth (polynomial/analytic) model, random tight clusters would fit with
non-integer rationals. Getting clean integers for all 44 clouds means each cloud lies
inside a region where `f` is *exactly* an affine map with integer coefficients:
`f` is piecewise-linear (a ReLU network with integer weights).

Confirmed: a degree-2 global polynomial leaves residual ~11, degree-4 ~0.28, i.e. no
low-degree smooth fit; and each cloud's 7 points are all on one side of every recovered
hyperplane (no cloud straddles a kink).

## Step 2 - Recovering the ReLU units (and spotting the version trap)
A `capture`'s two clouds sit on opposite sides of one kink (they "straddle" it). For a
ReLU unit `ReLU(w·x+t)` the gradient jump across its hyperplane is `v·w` and the
intercept jump is `v·t`. So from each capture:
```
Δg = g1 - g0 = v·w      (primitive direction w, scale v)
Δb = b1 - b0 = v·t   =>  t = Δb / v
```
Taking the 13 distinct primitive directions from all 22 captures, the offsets `t` came
out **identical for every capture that shared a direction** - a strong ReLU signature.

But the *base* term `c = g - Σ_active (Δg)` was **not constant** across clouds, which
looked like "not a ReLU net". The resolution:

> **`model_version` is a real trap.** 4 captures (indices 0, 8, 18, 19) are tagged
> `v-41e59d`; the other 18 are `v-8fb4ff`. They are *two different models*.

Re-running the analysis on **v-8fb4ff only**:
- 18 captures → **9 distinct units** (not 13).
- A consistent choice of which side of each hyperplane is "active" exists (2^9 search),
  giving a constant base term `c = (-3,-2,-5,0,1,-5)`, `d = 0`.

The 4 `v-41e59d` captures simply belong to a different function - they are 56 points that
the v-8fb4ff net correctly does *not* match.

## Step 3 - Assembling and verifying the net
Model: `f(x) = c·x + d + Σ_{j=1..9} [active_j(x)] · (inc_j·x + s_j)`,
`active_j(x) = [w_j·x + t_j > 0] XOR flip_j`.

- `inc_j` solved exactly from `g - c = Σ active_j · inc_j` (36 clouds × 6 eqs, rank 9).
- `s_j, d` solved exactly from `b = d + Σ active_j · s_j`.
- All solved values are integers (float residual ~1e-13).

**Verification:** the reconstructed net reproduces `y` exactly on
- all 18 v-8fb4ff captures' cloud points (252/252), and
- all 16 anchors (16/16).

Total **268/268 exact**, and the only mismatches anywhere are the 56 points from the
other model version. Because the 16 anchors (points the net was *not* fit on, in cells
never sampled by clouds) are reproduced exactly, the net genuinely generalises - so its
values on the 24 targets are correct.

## Step 4 - Submit
```
python3 final.py            # prints the 24 reduced rationals
python3 unlock.py '["5441/64", ...]'
# isfcr{577027585a0778773aa949d9}
```

## Key lessons
- 7 points in R^6 = a minimal affine probe; exact **integer** fits ⇒ piecewise-linear.
- Paired "clouds" straddling a kink reveal ReLU units via `(Δg, Δb)`.
- **Always split by `model_version`** - the dataset mixed two models on purpose.
- Anchors are the generalisation check that licenses extrapolating to the targets.

