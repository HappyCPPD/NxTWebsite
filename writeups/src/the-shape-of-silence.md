# the-shape-of-silence

**Event:** CryoVault CTF 2026
**Category:** ai
**Flag:** `isfcr{577027585a0778773aa949d9}`

---

A black-box model `f: R^6 -> R` returning exact rational outputs. Given 16 labelled anchors, 22 "captures" (each with two 7-point clusters), and 24 unlabelled targets to predict.

**Step 1 - the model is piecewise-linear with integer weights.** Seven points in R^6 determine an affine fit uniquely. The signal is that **all 44 clouds fit with exact integer coefficients** - a smooth/polynomial model would need non-integer rationals for random tight clusters. Confirmed independently: a global degree-2 polynomial fit leaves residual ~11, degree-4 ~0.28 - no smooth low-degree fit exists, and every cloud's 7 points sit strictly on one side of every recovered hyperplane. Conclusion: `f` is a ReLU network with integer weights.

**Step 2 - recovering ReLU units, and the version trap.** Each capture's two clouds straddle one kink; for a unit `ReLU(w·x+t)`, the gradient jump `Δg = v·w` and intercept jump `Δb = v·t` give the offset `t = Δb/v`. Across the 22 captures, the recovered offsets `t` were identical for every capture sharing a direction - a strong ReLU signature - but the base term was **not constant** across clouds. The resolution: **`model_version` is a deliberate trap** - 4 of the 22 captures are tagged a *different* model version (`v-41e59d` vs. `v-8fb4ff`) and simply belong to a different function entirely. Restricting to the 18 same-version captures resolves cleanly to **9 distinct ReLU units** with a consistent activation-side choice (found by a `2^9` search) giving a constant base term.

**Step 3 - assembling and verifying.** `f(x) = c·x + d + Σ_j [active_j(x)]·(inc_j·x + s_j)`. Solving the resulting linear systems for `inc_j`, `s_j`, `d` gives exact integers (float residual ~1e-13). **Verification: the reconstructed net reproduces all 252 same-version cloud points AND all 16 anchors exactly (268/268)** - critically, the anchors were never used for fitting, so exact reproduction on them licenses extrapolating to the 24 targets.

```
python3 final.py
python3 unlock.py '["5441/64", ...]'
# isfcr{577027585a0778773aa949d9}
```

Key lessons: 7 points in R^6 is a minimal affine probe, and clean integer fits signal piecewise-linearity; paired clusters straddling a kink reveal ReLU units via `(Δg, Δb)`; always split by `model_version` when a dataset field hints at provenance - two models were deliberately mixed; anchors are the generalisation check that licenses trusting extrapolated predictions.
