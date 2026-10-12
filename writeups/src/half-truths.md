# half-truths

**Event:** CryoVault CTF 2026
**Category:** crypto
**Flag:** `isfcr{l1st_d3c0d1ng_p4st_th3_r4d1us}`

---

`chall.py` samples a random degree-39 polynomial `f` over GF(p), p = 2³¹−1, and hands out `n = 512` Shamir shares `(i, f(i))` for i = 1..512. On return, exactly `t = 185` are honest and `327` have been replaced by uniform random values. Nothing records which are which. The flag key is `sha256(",".join(f's coefficients))`, AES-GCM.

The docstring taunts that Berlekamp-Welch/Gao/every classical decoder corrects up to `(N−K)/2` errors, needing `T ≥ (N+K)/2 = 276 > 185`. But "no unique-decoding argument reaches it" invites **list decoding**.

**Why it is solvable:** RS list decoding (Sudan 1997, Guruswami-Sudan 1999) decodes beyond half the minimum distance up to the Johnson bound. With `n = 512, k = 40`: unique-decoding radius `236` errors (need `t ≥ 276`); Johnson bound tolerates `t ≳ 144`. We have 327 errors, comfortably inside the Johnson bound.

**Sudan interpolation (multiplicity 1):** find `Q(x, y) = Σ q_j(x) y^j` vanishing at every received point. Two requirements pick `D`: existence (monomial count `> 512`) and correctness (`D < t=185`). For `k = 40`, `D = 180` gives 515 monomials (`>512`) and `180 < 185` - the unique sweet spot, `ℓ = 5`. Built the 512×515 matrix and solved by RREF over GF(2³¹−1); kernel dimension **7**. Every nonzero kernel element is divisible by `(y − f(x))`.

**Root finding - Roth-Ruckenstein, de-branched:** recover `f` one coefficient at a time via `y ← a_d + x·y`, requiring the lowest-order x-term to vanish. Naive single-`Q` branches on all roots of a degree-≤4 polynomial `S(a)` and blows up (7 minutes CPU, unfinished). **Fix:** run RR on **four independent kernel polynomials simultaneously** and intersect root sets at each step - the true `f` is a root of every kernel element, so branching collapsed to exactly 1 candidate at every one of the 40 steps. Modular root extraction via `gcd(S, x^p − x)` + Cantor-Zassenhaus.

Two implementation bugs cost time: (1) building `(x+r)^((p−1)/2) − 1` by prepending `−1` instead of subtracting from coefficient 0 → infinite loop; (2) using polynomial remainder instead of quotient when dividing out a known factor → roots silently discarded.

**Result:** after 40 RR steps exactly one candidate `f` remained, agreeing with 185 of 512 shares exactly matching `t`.

```
FLAG: isfcr{l1st_d3c0d1ng_p4st_th3_r4d1us}
```

**Takeaways:** "past the unique-decoding radius" ≠ unsolvable - check the Johnson/list-decoding radius. The Sudan parameter `D` is chosen by a tight discrete count, not the asymptotic formula. Multiplicity-1 Sudan sufficed because `k−1` is small. Running root-finding across several independent kernel polynomials and intersecting roots is a cheap, general way to suppress RR branching.
