# Censored

**Event:** Kaspersky CTF 2026
**Category:** crypto
**Points:** 50
**Server:** `tcp.sasc.tf 41592`
**Flag:** `kaspersky{N0w_4ll_tH3_4nsW3rs_4r3_1n_y0ur_h4nds!!!!}`

---

## Overview

The challenge implements a Schnorr-like digital signature scheme (Schnorr over a
finite-field DSA group). Each signature operation returns not just `(R, s)` but
also a **diagnostic blob** containing masked partial information about the
signing nonce. With 36 signatures available, an attacker can unmask these
diagnostics, narrow each nonce to a ~2^240 range (leaking ~16 bits per nonce),
and then solve the **Hidden Number Problem (HNP)** via lattice reduction to
recover the long-term secret key.

Once the secret key is recovered, forging a signature for the target message
`give_me_gift` and submitting it yields the flag.

---

## Protocol

```
Censored diagnostics, probably fine
Try: PUB | SIGN <hex> | SUBMIT <hex> <R> <s>
```

- **PUB** - returns the DSA group parameters `(p, q, g, y)`, the remaining
  signature quota (36 total), and a randomly generated `calibration` object.
- **SIGN** `<hex>` - signs an arbitrary message (except `give_me_gift`) using a
  fresh random nonce. Returns `(R, s)` plus a diagnostic blob.
- **SUBMIT** `<hex> <R> <s>` - verifies the signature. If the message is
  `give_me_gift` and the signature is valid, returns the flag.

---

## Signature Scheme

Standard Schnorr-style identification converted to a signature:

- **Key generation:**
  - Private key: `sk ∈ [1, Q-1]`
  - Public key: `y = G^sk mod P`
- **Signing:**
  - Pick random nonce `nonce ∈ [1, Q-1]`
  - Compute commitment: `R = G^nonce mod P`
  - Compute challenge: `c = SHA256("challenge" || len(msg) || msg || R) mod Q`
  - Compute response: `s = (nonce + c · sk) mod Q`
- **Verification:**
  - Recompute `c = SHA256("challenge" || len(msg) || msg || R)`
  - Check: `G^s ≡ R · y^c (mod P)`

---

## The Diagnostic Leak

Each SIGN response includes a `diag` field:

```json
{
  "patch":   <12-bit integer>,   // XOR-masked with telemetry_mask
  "resid":   <6-bit integer>,    // XOR-masked with telemetry_mask
  "curv":    <8-bit integer>,
  "basin":   <3-bit integer>,
  "iters":   <integer>,
  "health":  "<hex string>"
}
```

The `patch` + `resid` fields combine to form an 18-bit `profile_value`:

```
profile_value = floor(sigma · 2^18)
```

where `sigma ∈ [0, 1)` is the normalized arc-length along a calibration curve
at the point corresponding to the nonce.

::: insight
The XOR masks depend on `SHA256("telemetry" || calibration_id || commitment || label)`,
all values known to the attacker after receiving the PUB data and the signature.
So we can fully unmask `profile_value`.
:::

---

## Calibration Curve Geometry

The calibration defines a parametric curve derived from a polar radius function:

```
r(θ) = (1 + 0.25·sin(3θ + π))^1.4 + 2·exp(-((θ - π/2)/0.3)^2)
```

Points on the curve: `(x, y) = (r(θ)·cos(θ), r(θ)·sin(θ))`

An affine transformation (random 2×2 matrix + translation) maps these to
`(u, v)` coordinates. The nonce maps to an angle `θ = 2π · nonce / Q`, and
then:

- `parameter = _path_parameter(nonce)`, maps nonce → angle on the
  transformed curve (incorporating the calibration's `phase` and `direction`)
- `sigma = profile.at(parameter)`, cumulative arc length at that angle,
  normalized to [0, 1]

A precomputed lookup table (LUT) with 2^15 = 32768 entries maps LUT index →
nonce via piecewise linear interpolation of the inverse function.

---

## From profile_value to Nonce Range

Given `profile_value = pv`:

```
sigma_low  = pv / 2^18
sigma_high = (pv + 1) / 2^18
```

We find all LUT segments whose sigma range overlaps `[sigma_low, sigma_high)`.
For each matching segment, the fractional overlap gives corresponding nonce
sub-intervals. Merging adjacent intervals yields the nonce range.

On average, each `profile_value` maps to a nonce range of width ~2^240
(about 16 bits narrower than the full 256-bit nonce space). Using 30
signatures, this provides ~480 bits of constraint - more than enough for HNP.

---

## Hidden Number Problem (HNP) Attack

For each signature `i` with known nonce range `[lo_i, hi_i)`:

```
s_i = nonce_i + c_i · sk  (mod Q)
nonce_i ∈ [lo_i, hi_i)
```

Let `mid_i = (lo_i + hi_i) / 2` and `X = max(hi_i - lo_i) / 2`. Then:

```
s_i - mid_i = x_i + c_i · sk  (mod Q)   where |x_i| ≤ X
```

Define `a_i = (s_i - mid_i) mod Q`. We have:

```
a_i ≡ x_i + c_i · sk  (mod Q)    with |x_i| ≤ X
```

This is the Hidden Number Problem: given many pairs `(c_i, a_i)`, find `sk`
such that each `a_i - c_i · sk ≡ x_i (mod Q)` with small `|x_i|`.

### Lattice Construction

We build a Q-scaled centered HNP lattice of dimension `(n+2) × (n+2)`:

```
     |  Q^2       0      ...      0      |   0     0  |
     |   0       Q^2     ...      0      |   0     0  |
     |  ...                             |          |
B =  |   0        0      ...    Q^2     |   0     0  |
     | c_0·Q   c_1·Q    ...  c_{n-1}·Q |   X     0  |
     | a'_0·Q  a'_1·Q   ... a'_{n-1}·Q |   0    X·Q |
```

where `a'_i = (a_i - X) mod Q` (centering the observation around 0 so the
error is bounded by ±X rather than [0, 2X]).

The target short vector is:

```
v = (x_0·Q, x_1·Q, ..., x_{n-1}·Q, -sk·X, X·Q)
```

Of length: `sqrt(n · (X·Q)² + (sk·X)² + (X·Q)²) ≈ sqrt(n+2) · X · Q`.

LLL finds a short vector in the lattice. Scanning rows where the last column
equals `X·Q` yields the secret key at column `n` (divided by `X`).

---

## Forging the Signature

With the recovered secret key `sk`:

1. Pick a random nonce `k`
2. Compute `R = G^k mod P`
3. Compute `c = SHA256("challenge" || len("give_me_gift") || "give_me_gift" || R)`
4. Compute `s = (k + c · sk) mod Q`
5. Submit: `SUBMIT 676976655f6d655f67696674 <R> <s>`

---

## Implementation

- `supercoolcryptolib.py`, challenge library (reused for calibration geometry)
- `solve_remote.py`, connects to the real server, collects signatures,
  computes nonce ranges, builds and reduces the lattice with fpylll, recovers
  the secret key, forges a signature, and submits it

Key dependencies: `fpylll` for LLL lattice reduction.

---

## Flag

```
kaspersky{N0w_4ll_tH3_4nsW3rs_4r3_1n_y0ur_h4nds!!!!}
```

---

## Notes

- The challenge name "Censored" refers to the diagnostic blob - the "censored"
  (masked) nonce data that isn't actually censored since the masks are
  computable from public data.
- In retrospect, the additional diagnostic fields (`curv`, `basin`, `iters`)
  provide even more bits (up to ~30 bits per signature), but the 18 bits from
  `profile_value` alone were sufficient with 30 signatures.
- The lattice construction requires careful scaling. The key insight is
  centering observation rows around 0 so entries are bounded by X rather than Q.
