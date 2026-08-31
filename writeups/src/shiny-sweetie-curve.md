# Shiny Sweetie Curve

**Event:** Kaspersky CTF 2026
**Category:** crypto
**Points:** 50 (63 at time of writing)
**Also shown as:** "Riffle Royale"
**Flag:** `kaspersky{g4mbl1ng_1s_b4d_t4k3_c4r3_0f_y0urs3lf}`

---

## The service

`GET /api/deal` returns:

```json
{
  "id": "<token>",
  "samples": ["<77-digit int>", ... x14],
  "target": 4294968905,
  "ttl": 300
}
```

`POST /api/submit` takes `{id, slot, value}` (`slot` is `0` for the LEFT card, `1`
for RIGHT) and checks `value` against a server-side secret with
`hmac.compare_digest`. Getting it right returns the flag.

The attached `server.py` shows what's actually happening:

```python
BITS = 255
LANE_SAMPLES = 7
TARGET_INDEX = (1 << 32) + 1609

def generate_instance():
    p = random_prime(BITS)                 # fresh 255-bit prime every round
    a, b = rnd.randrange(p), rnd.randrange(p)
    curve = Curve(p, a, b)                  # y^2 = x^3 + a x + b  (mod p)
    step = random_point(curve)
    jump = curve.mul(TARGET_INDEX, step)    # TARGET_INDEX * step

    u, v = random_point(curve), random_point(curve)
    xs0, _ = orbit(curve, u, step, 7)       # u, u+step, ..., u+6*step
    xs1, _ = orbit(curve, v, step, 7)       # v, v+step, ..., v+6*step

    mask = shuffle([0]*7 + [1]*7)           # interleave the two lanes
    samples = interleave(xs0, xs1, mask)    # only x-coordinates, shuffled order

    target0 = curve.add(u, jump)
    target1 = curve.add(v, jump)
    hand_values = (targets[mask[0]], targets[1 - mask[0]])   # LEFT, RIGHT
```

So: every round is a **brand-new random elliptic curve** (`p, a, b` all secret,
`p` is a fresh 255-bit prime). Two "lanes" walk the curve in fixed steps of a
secret point `D` from two secret starting points `u` and `v`. The 14 visible
numbers are just the x-coordinates of these 14 points, shuffled together but
with each lane's internal order preserved (a stable interleave). `LEFT` is
"the target for whichever lane produced the very first shown card"; `RIGHT` is
the other lane's target.

Nothing about `p, a, b, u, v, step` is ever sent to the client - only 14 raw
x-coordinates on an unknown curve mod an unknown prime.

## The math: recovering the curve from x-coordinates only

For a Weierstrass curve `y² = x³ + a x + b` and two points `A, B`, the
standard chord/tangent addition law gives `x(A+B)` and `x(A−B)` in terms of
`x_A, y_A, x_B, y_B`. Adding and multiplying those two expressions kills the
cross terms in `y_A y_B`, and `y_A², y_B²` get replaced with `x_A³+a x_A+b`
and `x_B³+a x_B+b`. The result is two identities that use **only
x-coordinates and the curve constants** - no `y` needed:

```
x(A+B) + x(A−B) = 2(x_A³+x_B³ + a(x_A+x_B) + 2b)/(x_A−x_B)² − 2(x_A+x_B)
x(A+B) · x(A−B) = (x_A²+x_A x_B+x_B²+a)²/(x_A−x_B)² − (x_A+x_B)·[the sum term] + (x_A+x_B)²
```

Apply this with `A = P_i` (the i-th point in a lane, known x) and `B = step`
(unknown x, call it `s`). Then `A+B = P_{i+1}` and `A−B = P_{i-1}`, both
known. Clearing denominators gives, for every interior index `i` of a lane:

* `EqSum_i(a, b, s)`, linear in `a, b`, quadratic in `s`
* `EqProd_i(a, b, s)`, quadratic in `a`, linear in `b`, quartic in `s`

(Verified numerically against a hand-rolled toy curve before trusting it on
the real data - both identities hold exactly mod `p`.)

With 3+ consecutive points in a lane we get enough of these to eliminate
`a, b` linearly (two `EqSum` equations solve `a(s), b(s)` as low-degree
polynomials in `s` over a constant denominator), substitute into two more
equations to get two univariate polynomials `F1(s), F2(s)`, and take their
**resultant**. That resultant is a pure integer built only from known
x-coordinates - and it is **guaranteed to be a multiple of `p`**, because
mod `p` the true `(a, b, s)` is an actual common root of `F1` and `F2`.

Do this twice with two different windows of points (5-6 points total) to get
two independent multiples of `p`, then:

```
p = gcd(R_A, R_B)
```

For a *wrong* grouping of points (not really from the same lane), `R_A` and
`R_B` are just unrelated large integers with no reason to share a 255-bit
factor - `gcd` is small. For the *correct* grouping, `gcd` lands exactly on
the secret prime. This turns "is this the right lane?" into a cheap,
mechanical check.

## Putting it together

1. **Find the partition.** The board shows 14 x-coordinates; 7 belong to
   `sample[0]`'s lane (interleaved order preserved). Brute-force which 6 of
   the other 13 join `sample[0]` (`C(13,6) = 1716` candidates), computing
   `R_A, R_B` and `gcd` for each - this is fast (~0.6 ms/candidate after
   hand-rolling the polynomial algebra instead of calling generic
   `sympy.solve`/`resultant` on symbols) so the whole search is ~1-2 seconds.
   A `gcd` with ~255 bits (and prime) is the hit.

2. **Recover `p, a, b, s`.** `p` from the gcd; `s` from the common root of
   `F1, F2` mod `p` (their `gcd` over `GF(p)[s]` is linear); `a, b` from the
   linear system, now fully numeric mod `p`.

3. **Resolve the sign ambiguity.** X-only relations can't tell `y` from `−y`.
   Compute both square roots of `x_u³+a x_u+b` and `s³+a s+b` (`p ≡ 3 mod 4`,
   so `y = v^{(p+1)/4} mod p` works directly - the server uses the same
   trick), try the sign combinations, and replay the addition chain
   `u, u+step, u+2·step, ...` to see which branch reproduces the known
   x-coordinates exactly.

4. **Extrapolate.** With real points `u` and `step` on a fully known curve,
   compute `u + TARGET_INDEX · step` with ordinary EC scalar multiplication
   and take its x-coordinate.

5. **Submit** `{id, slot: 0, value: <that x-coordinate>}`, `slot 0` because
   we anchored the search on `sample[0]`, whose lane is always the LEFT card
   by construction (`hand_values[0] = targets[mask[0]]`).

Result: `{"ok": true, "message": "kaspersky{g4mbl1ng_1s_b4d_t4k3_c4r3_0f_y0urs3lf}"}`.

## Dead ends worth noting

::: pitfall
- The obvious first guess - treat the 14 samples as `(x=1..14, y=sample)` and
  Lagrange-interpolate a degree-13 polynomial to evaluate at `target`, is a
  red herring. It *does* produce an exact integer (guaranteed by finite
  differences on consecutive integer nodes, not evidence of anything), but
  it's 197 digits and the server hard-caps input at 80 digits
  (`"the dealer cannot read that"`), and finite-difference GCD tests confirm
  there's no redundancy to exploit that way - degree is genuinely 13, full
  rank, nothing to interpolate.
- Guessing well-known 256-bit primes (secp256k1, Curve25519, NIST P-256,
  `2^256-189`, ...) also fails - `p` is freshly random *per round*, not a
  fixed system constant, which the digit-length distribution of samples
  across many rounds confirms (no consistent ceiling near any famous prime).
:::

Only once the attached `server.py`/`app.py` source was available did the real
shape of the problem - a fresh random elliptic curve per round, x-only leaked
points, `hand[slot]` semantics - become clear enough to solve properly rather
than guess.
