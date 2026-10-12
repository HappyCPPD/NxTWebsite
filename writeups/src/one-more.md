# one-more

**Event:** CryoVault CTF 2026
**Category:** crypto
**Flag:** `isfcr{r0s_1s_n0t_h4rd_f0r_l0g_p}`

---

Solved with the **polynomial-time ROS attack** (Benhamouda-Lepoint-Loss-Orrù-Raykova, Eurocrypt 2021): 256 parallel sessions, a few lines of modular arithmetic, ~4.5 s against the live service. No Wagner k-tree, no big memory.

**The service:** `wss://one-more.isfcr.xyz` is a blind Schnorr signing oracle on secp256k1. Per connection it draws a fresh secret `x ← Z_n` and publishes `X = xG`. Protocol: `open` returns `id k R` (`R = rG`); `sign <k> <c>` returns `s = (r + c·x) mod n` once per session; `submit` with a JSON list of signatures wins if `good > answered`. A submitted signature `[m_hex, Rx, Ry, s]` counts iff `s·G == R + H(R, m)·X`. Limits: `MAX_SESSIONS=512`, `MAX_SUBMIT=600`.

**Why the "obvious" attack is a trap:** the classical break is Wagner's `(ℓ+1)`-sum/k-tree attack on ROS, costing ~2³⁴ hash evaluations and tens of GB RAM for a 256-bit curve - infeasible on a 16 GB machine. Wagner is the *generic* algorithm, but ROS is not generically hard when the attacker controls the dimension: with `ℓ ≈ log₂(n) = 256` concurrent sessions, there is a **polynomial-time** solver.

**The math:** open ℓ sessions with nonces `R_0..R_{ℓ-1}`. For coefficient vector `a`, `R = Σ a_j R_j`, `s = Σ a_j s_j` gives `s·G = R + (Σ a_j c_j)·X`, valid iff `Σ a_j c_j ≡ H(R, m) (mod n)`. Use ℓ singletons (`a = e_j`, forcing `c_j = H(R_j, m_j)`) plus one aggregate (`a = ρ`).

**The binary-choice gadget:** for each session, prepare two messages, `d_j = (h_j^1 - h_j^0) mod n`. Pick `ρ_j = 2^j · d_j^{-1} (mod n)`. Flipping session `j`'s message changes the aggregate sum by exactly `2^j` - each session becomes an independent bit of weight `2^j`. Fix aggregate nonce `R* = Σ ρ_j R_j`, target `T = H(R*, m*)`, baseline `L0 = Σ ρ_j h_j^0`, `v = (T − L0) mod n`. Since `v < 2^256`, its binary expansion directly picks which message/challenge to use per session - no search.

**Assembling the win:** sign each session once (`c_j = h_j^{bit_j}`), submit 256 singletons + 1 aggregate = 257 valid signatures from 256 sign calls → `good = 257 > answered = 256` → one more!

```
X = 6e50692dae1d2014598197dc3bbc46e9...
opened 256 sessions
built challenges
signed 256 sessions
valid 257 answered 256
one more! isfcr{r0s_1s_n0t_h4rd_f0r_l0g_p}

real    0m4.497s
```

**Takeaways:** ROS is only hard generically - with `ℓ ≥ log₂ n` concurrent sessions the Benhamouda et al. solver is polynomial. The gadget (per-session binary choice + coefficient `ρ_j = 2^j · d_j^{-1}`) turns each session into an independent power-of-two bit, solved by reading off the binary expansion. Blind Schnorr is broken in the concurrent setting (reference: Benhamouda, Lepoint, Loss, Orrù, Raykova, *On the (in)security of ROS*, Eurocrypt 2021).
