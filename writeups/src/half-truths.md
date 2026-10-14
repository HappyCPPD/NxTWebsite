# half-truths

**Event:** CryoVault CTF 2026
**Category:** crypto
**Flag:** `isfcr{l1st_d3c0d1ng_p4st_th3_r4d1us}`

---

## Challenge
`chall.py` samples a random degree-39 polynomial `f` over GF(p), p = 2³¹−1, and hands
out `n = 512` Shamir shares `(i, f(i))` for i = 1..512. On return, exactly `t = 185`
are honest and `512 − 185 = 327` have been replaced by uniform random values in GF(p).
Nothing records which are which. The flag is sealed under
`key = sha256(",".join(f's coefficients, low-order first, decimal))`, AES-GCM,
`nonce = b"half-truths-"`.

The docstring is a deliberate taunt:

> Reed - Solomon unique decoding - Berlekamp - Welch, Gao, the extended Euclidean key
> equation, every classical decoder - corrects up to (N−K)/2 errors, i.e. needs
> T ≥ (N+K)/2 honest shares. Here T is well under that. There is no unique-decoding
> radius argument that reaches this instance, and that is not an oversight.

Indeed `(N+K)/2 = 276 > 185`. But "no *unique*-decoding argument reaches it" is not
"undecodable": it is a textbook invitation to **list decoding**.

## Why it is solvable at all
Reed - Solomon list decoding (Sudan 1997, Guruswami - Sudan 1999) decodes beyond half the
minimum distance up to the Johnson bound. With `n = 512, k = 40`:

- unique-decoding radius: `(n−k)/2 = 236` errors → needs `t ≥ 276`.
- Johnson bound: `n − sqrt(n·k) = 512 − sqrt(20480) ≈ 368.9` errors → tolerates
  `t ≳ 144`.

We have 327 errors, comfortably inside the Johnson bound. So a list decoder will find f
among a tiny list of candidates.

## Sudan interpolation (multiplicity 1)
Sudan's algorithm looks for a nonzero polynomial

```
Q(x, y) = Σ_{j=0}^{ℓ-1} q_j(x) y^j,     deg q_j(x) ≤ D − (k−1)·j
```

that vanishes at every received point `(x_i, y_i)` - honest and liar alike (we cannot
tell them apart, so we impose the constraint on all of them).

Two competing requirements pick `D`:

1. **Existence:** the number of monomials `Σ_j (D − (k−1)j + 1)` must exceed the number
   of linear constraints `n = 512`, so that the homogeneous system has a nonzero
   solution.
2. **Correctness:** if `f` agrees with the received word on `t` points, then
   `Q(x, f(x))` is a polynomial of x-degree ≤ D with at least `t` roots. If `D < t`,
   it must be identically zero, hence `(y − f(x)) | Q`.

For `k = 40` (so `k−1 = 39`):

| D | monomials | > 512 ? | D < t=185 ? |
|----|-----------|---------|-------------|
| 179 | 510 | no | yes |
| **180** | **515** | **yes** | **yes** |

So `D = 180`, `ℓ = 5` (y-degree 4) is the unique sweet spot. Note this is *tight*:
the asymptotic Sudan bound would suggest needing ~200, but the small value of `k−1`
makes discrete/lattice effects generous enough that `D = 180` already works.

I built the 512×515 matrix `M[i, (j,d)] = y_i^j · x_i^d mod p` and solved `M·q = 0`
by RREF over GF(2³¹−1) (numpy int64, modular row reduction). Kernel dimension came out
to **7** - plenty of freedom.

Crucially, by requirement (2) **every** nonzero kernel element is divisible by
`(y − f(x))`. This is what makes the next step robust.

## Root finding - Roth - Ruckenstein, de-branched
Sudan gives `Q`; we still must extract the linear-in-y factor `y − f(x)`. The standard
tool is the Roth - Ruckenstein algorithm: recover `f = Σ a_d x^d` one coefficient at a
time by repeatedly substituting `y ← a_d + x·y` and requiring the lowest-order x-term to
vanish. At each step the next coefficient `a_d` is a root of a small polynomial
`S(a) = Σ_{i : ord_x(c_i)=m} lead(c_i)·a^i` of degree ≤ 4.

The naive single-`Q` version branches on all roots of `S` and blows up (my first run
burned 7 minutes of CPU without finishing the first steps - the list of partial
solutions grows like 4^depth).

**Fix:** run RR on **four independent kernel polynomials simultaneously** and, at each
step, take the *intersection* of their root sets. The true `f` is a root of every kernel
element, so the true coefficient `a_d` always lies in the intersection, while spurious
roots from one polynomial are killed by the others. Branching collapsed from ~4 per step
to exactly **1 candidate at every one of the 40 steps**.

Modular root extraction for the ≤4-degree `S`:
`g = gcd(S, x^p − x)` isolates the distinct linear factors (via `x^p mod S` by
square-and-multiply); Cantor - Zassenhaus then splits `g` into individual roots. Since
`p ≡ 3 (mod 4)`, degree-2 factors are also handleable directly.

Two implementation bugs cost time and are worth flagging for anyone re-implementing:

- Building `(x+r)^((p−1)/2) − 1` by *prepending* `−1` as a new low-order coefficient
  instead of subtracting from coefficient 0 → gcd always trivial → infinite loop.
- Using the polynomial **remainder** function to divide `g` by a known factor `h`
  (remainder is 0 for an exact factor) instead of a quotient function → every extra
  root silently discarded.

## Recovery and decryption
After 40 RR steps exactly one candidate `f` remained. Evaluating it against all 512
shares gives **185 agreements**, matching `t` exactly. The key
`sha256(",".join(map(str, coeffs)))` then decrypts the AES-GCM ciphertext and the tag
verifies:

```
FLAG: isfcr{l1st_d3c0d1ng_p4st_th3_r4d1us}
```

## Takeaways
- "Past the unique-decoding radius" ≠ "unsolvable". Check the Johnson / list-decoding
  radius before declaring an RS instance out of reach.
- The Sudan parameter `D` is chosen by a tight discrete count (`515 > 512` and
  `180 < 185`); don't trust the asymptotic formula to the integer.
- Multiplicity-1 Sudan sufficed here (multiplicity-2 Guruswami - Sudan is not needed),
  because `k−1` is small enough that lattice effects let `D` sit just below `t`.
- Running root-finding across several independent kernel polynomials and intersecting
  roots is a cheap, general way to suppress RR branching.

