# one-more

**Event:** CryoVault CTF 2026
**Category:** crypto
**Flag:** `isfcr{r0s_1s_n0t_h4rd_f0r_l0g_p}`

---

## 1. The service

`wss://one-more.isfcr.xyz` - about 40 lines of real crypto in `server.py`. It is a
**blind Schnorr signing oracle on secp256k1** (group order `n`, generator `G`).
Per *connection* it draws a fresh secret `x ← Z_n` and publishes `X = xG`.

Protocol (one command per websocket message):

```
server → "X <hex128>"                              # X = xG for this connection
open                → "id k R <hex128>"            # R = rG, r uniform, ser(P)=x||y (64B)
sign <k> <c>        → "s <int>"                    # s = (r + c·x) mod n, ONE answer per session
submit  then <json> → "valid <good> answered <ans>"
                       + "one more! <FLAG>"  iff good > ans
```

A submitted signature `[m_hex, Rx, Ry, s]` counts iff

```
s·G == R + H(R, m)·X        with   H(R,m) = SHA256(ser(R) ‖ m) mod n
```

and messages must be **distinct**. Limits: `MAX_SESSIONS=512`, `MAX_SUBMIT=600`,
`MAX_COMMANDS=1088`, and a 1800 s per-connection timeout.

**Win condition:** hand back strictly **more** valid signatures than the number of
`sign` calls the oracle answered.

This is textbook blind-Schnorr *one-more unforgeability*. The service even tells you
the deal: "one signature per session, no exceptions - come back with more than that."

---

## 2. Why the "obvious" attack is a trap

The classical break is **Wagner's `(ℓ+1)`-sum / k-tree attack** on the ROS problem.
It works, but for a 256-bit curve it costs on the order of **2³⁴ hash evaluations and
tens of GB of RAM** for the k-tree. Two earlier sessions on this box burned all their
time trying to shoehorn that k-tree (≈ 29 - 59 GB working set) onto a 16 GB machine with
NVMe swap. That memory wall was the whole blocker.

Wagner is the *generic* algorithm for ROS. But ROS is **not** generically hard when the
attacker controls the dimension: if you can open **ℓ ≈ log₂(n)** concurrent sessions,
there is a **polynomial-time** solver (Benhamouda et al. 2021). secp256k1's order is
256 bits and the service allows up to 512 sessions - so ℓ = 256 sessions is plenty, and
the whole thing becomes deterministic linear algebra. That is the intended solution.

---

## 3. The math

### 3.1 Linear structure of combined signatures

Open ℓ sessions with nonces `R_0, …, R_{ℓ-1}`. We will hand session `j` a challenge
`c_j` and receive `s_j = r_j + c_j·x`.

Take any integer coefficient vector `a = (a_0,…,a_{ℓ-1})` and a message `m`, and form

```
R = Σ_j a_j R_j        s = Σ_j a_j s_j
```

Then

```
s·G = Σ_j a_j (r_j + c_j·x)·G = (Σ_j a_j R_j) + (Σ_j a_j c_j)·X = R + (Σ_j a_j c_j)·X
```

so `(R, s)` is a **valid signature on `m`** iff

```
Σ_j a_j c_j  ≡  H(R, m)   (mod n)          (★)
```

We get to choose the `a_j`, the messages, and (crucially) the challenges `c_j`.
Produce ℓ+1 signatures satisfying (★) using only ℓ `sign` calls and you win.

### 3.2 The forgeries

Use **ℓ singletons** plus **one aggregate**:

- **Singleton `j`** (`a = e_j`): nonce `R_j`, message `m_j`. By (★) it is valid iff
  `c_j ≡ H(R_j, m_j)`. So whatever message we settle on for session `j` *forces* the
  challenge we must send: `c_j = H(R_j, m_j)`.

- **Aggregate** (`a = ρ`, a vector we design): nonce `R* = Σ_j ρ_j R_j`, message `m*`.
  Valid iff `Σ_j ρ_j c_j ≡ H(R*, m*)`.

The trick is to give each session **two** candidate messages, so each `c_j` has two
possible values, and to engineer `ρ` so those binary choices add up to *any* target we
need - with no search.

### 3.3 The binary-choice gadget (the whole attack)

For each session `j`, prepare two messages and hash them:

```
h_j^0 = H(R_j, m_j^0)      h_j^1 = H(R_j, m_j^1)      d_j = (h_j^1 − h_j^0) mod n
```

Pick the aggregate coefficient

```
ρ_j = 2^j · d_j^{-1}   (mod n)
```

Now flipping session `j` from message 0 to message 1 changes its challenge by `d_j`, and
therefore changes the aggregate sum `Σ ρ_j c_j` by exactly `ρ_j · d_j = 2^j`. **Each
session is a clean, independent bit of weight `2^j` in the aggregate equation.**

Fix the aggregate nonce `R* = Σ_j ρ_j R_j` (independent of the bit choices), pick any
`m*`, and compute

```
T   = H(R*, m*)                      # the target (fixed)
L0  = Σ_j ρ_j · h_j^0   (mod n)      # baseline: all bits = 0
v   = (T − L0) mod n                 # v ∈ [0, n) ⊂ [0, 2^256)
```

The aggregate is valid iff `Σ_j ρ_j c_j ≡ T`, i.e.

```
L0 + Σ_{j: bit set} 2^j  ≡  T   (mod n)   ⇔   Σ_{j set} 2^j  ≡  v   (mod n)
```

Because `v < 2^256` and we have all 256 weights `2^0 … 2^255`, **`v` is just a 256-bit
number and its binary expansion tells us exactly which message to pick per session**:

```
bit_j = (v >> j) & 1        c_j = h_j^{bit_j}
```

No search, no birthday, no k-tree. Deterministic.

### 3.4 Assembling the win

Sign each session once with `c_j = h_j^{bit_j}` → get `s_j`. Then:

- 256 singletons: `(m_j^{bit_j}, R_j, s_j)` - each valid by construction.
- 1 aggregate: `(m*, R*, s* = Σ_j ρ_j s_j)` - valid because we forced `Σ ρ_j c_j ≡ T`.

All 257 messages are distinct (encode `j` and the bit in each `m_j`; `m*` is its own
tag). Result: **good = 257 > answered = 256 → "one more!"**

Resource budget: 256 `open` + 256 `sign` + `submit` + json = 514 commands ≤ 1088; 257
signatures ≤ 600. Comfortable.

---

## 4. Running it

```bash
# offline sanity check against the local stdio server (placeholder flag)
python3 test_local.py          # -> valid 257 answered 256  /  one more! isfcr{placeholder...}

# the real thing
python3 solve_live.py wss://one-more.isfcr.xyz
```

Live output:

```
X = 6e50692dae1d2014598197dc3bbc46e9...
opened 256 sessions
built challenges
signed 256 sessions
valid 257 answered 256
one more! isfcr{r0s_1s_n0t_h4rd_f0r_l0g_p}

real    0m4.497s
```

Most of the 4.5 s is network round-trips (512 of them) and the server verifying 257
signatures; local compute is ~0.7 s, dominated by the 256 scalar-mults for `R*`.

---

## 5. Files

| file            | role                                                               |
|-----------------|--------------------------------------------------------------------|
| `solve_ros.py`  | the attack: `build_forgeries(X, nonces)` → challenges + finisher   |
| `solve_live.py` | pipelined websocket driver (open → sign → submit)                  |
| `test_local.py` | end-to-end validation against `server.py --stdio` before any live run |
| `server.py`     | the challenge (blind Schnorr oracle)                               |

The old Wagner tooling (`bitksum.c`, `ksum.c`, `solve.py`, `poc_toy_*`, the swap/memory
notes in `HANDOFF.md`/`NOTES.md`) is **superseded** - kept only as a record of the dead
end.

---

## 6. Takeaways

- **ROS is only hard generically.** With `ℓ ≥ log₂ n` concurrent sessions the
  Benhamouda et al. solver is polynomial - Wagner's k-tree is a huge overkill that this
  challenge dangles to waste your time and RAM.
- **The gadget:** per-session binary message choice + coefficient `ρ_j = 2^j · d_j^{-1}`
  turns each session into an independent power-of-two bit, so the aggregate equation is
  solved by just reading off the binary expansion of `(T − L0) mod n`. No search.
- **Blind Schnorr is broken** in the concurrent setting; real deployments need
  ROS-resistant variants (e.g. Fuchsbauer - Wolf clause-Schnorr).
- Practically: when a "known hard" attack needs 32 GB and 2³⁴ work for a 256-bit CTF
  that resets keys per connection and *invites* hundreds of sessions, that's a tell to
  look for the polynomial concurrent attack instead.

**Reference:** Benhamouda, Lepoint, Loss, Orrù, Raykova - *On the (in)security of ROS*,
Eurocrypt 2021 - https://eprint.iacr.org/2020/945

