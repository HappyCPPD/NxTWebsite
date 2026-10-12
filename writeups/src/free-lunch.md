# free-lunch

**Event:** CryoVault CTF 2026
**Category:** crypto
**Flag:** `isfcr{b4ckw4rds_1s_h4lf_th3_d3gr33}`

---

An arithmetization-oriented permutation on `GF(p)^2`, p = 2 (mod 3): `(x, y) <- ( cbrt(x + y + c_i), x )` for `i = 0 .. 19`. `cbrt(v) = v^e`, `3e = 1 mod (p-1)`, so cubing is a bijection and the round map is invertible. **CICO:** find `x` such that `P(x, 0)` has second output coordinate `0`. The flag is AES-GCM sealed under `SHA256(str(min_solution))`.

**Key observation - flatten the chain:** let `x_i` denote the first coordinate after round `i`, starting pair `(x_0, y_0) = (x, 0)`. Because `y_{i+1} = x_i`, the round relation becomes a scalar 3-term recurrence `x_{i+1}^3 = x_i + x_{i-1} + c_i` (with `x_{-1} = 0`), solvable in either direction: forward `x_{i+1} = cbrt(x_i + x_{i-1} + c_i)`, backward `x_{i-1} = x_{i+1}^3 - x_i - c_i`. The CICO constraint `P(x,0)[1] = 0` is exactly `y_20 = x_19 = 0`, and the start gives `x_{-1} = 0`.

**The trick:** encode `x_{i-1}` as a polynomial in the final coordinate `t = x_20`, imposing `x_19 = 0`: `P[20] = t, P[19] = 0, P[i-1] = P[i+1]^3 - P[i] - c_i`. Then `F = P[-1]` is the polynomial whose roots `t` satisfy both boundary conditions. The forward map raises degree by ~3 per round, but the *backward* recurrence only triples degree every **two** steps: `deg P = 1, 0, 3, 3, 9, 9, 27, ..., 3^10`, so `deg F = 3^10 = 59049` - tiny. The CICO reduces to finding GF(p) roots of a degree-59049 polynomial: `G = gcd(F, x^p - x)`.

Because `p = 2 mod 3` the cube root is a bijection, so there is no branching; the gcd came out of degree 2, i.e. **2 CICO solutions**. Walk the chain back to `x_0` from each `t`-root, keep the ones landing at `x_{-1}=0` with `P(x_0,0)[1]=0`, and take the smallest.

```
x = 1093395384440720767   (smallest of 2 solutions)
key = SHA256("1093395384440720767")
flag = isfcr{b4ckw4rds_1s_h4lf_th3_d3gr33}
```

Requires `python-flint` (fast `nmod_poly`) and `pycryptodome`:

```
python3 -m venv /var/tmp/flintenv
/var/tmp/flintenv/bin/pip install python-flint pycryptodome
/var/tmp/flintenv/bin/python solve.py
```

Runs in ~6 s; `deg F = 59049`, `deg gcd = 2`. The bit that makes it fast is doing the polynomial recursion **backwards** (cube only every other round) and using FLINT's `pow_mod` for `x^p mod F`.

**Lesson:** "Trivial to evaluate, huge forward degree" is a trap only if you attack the forward direction. The cube-root round is cheap to *invert*; expressing the condition in the inverse recurrence collapses the degree from `~3^19` to `~3^10` and makes the CICO a small root-finding problem.
