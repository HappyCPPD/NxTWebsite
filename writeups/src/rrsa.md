# RRSA

**Event:** October 2026 MetaCTF Flash CTF
**Category:** crypto
**Flag:** `SkillBit{aLLLways_th3_w4yy}`

---


## 1. The source

`rrsa.zip` ships `chal.py` plus one line of published output:

```python
from secret import *
r = 1333932344710022001826837667329537548527   # known, given

p = x * r + 1
q = y * r + 1
n = p*q

flag = b'SkillBit{REDACTED}'.hex()
flag = int(flag, 16)
ct = pow(flag, 65537, n)
print(f'{ct=}')
print(f'{n=}')
```

So both primes are of the form `(something)*r + 1` - i.e. **r divides p-1 and q-1**.
"Putting the R in RRSA."

## 2. The observation - recover x+y for free

Expand `n`:

```
n = (xr+1)(yr+1) = x*y*r^2 + (x+y)*r + 1
```

Therefore

```
n - 1 = r * ( x*y*r + x + y )
```

Let `A = (n-1)/r`. Then `A = x*y*r + (x+y)`, and taken mod `r`:

```
A % r == (x + y) % r
```

The primes sit near `sqrt(n) ~ 3e57`, while `r ~ 1.3e39`, so `x, y ~ 2.2e18` and
`x + y < r`. That means `(x + y) % r` **is** `x + y` exactly - no wrap. So:

* `s = A % r`            -> `s = x + y`
* `xy = (A - s) / r`     -> `xy = x*y`

`x` and `y` are the roots of `z^2 - s*z + xy = 0`, whose discriminant is the perfect
square `(x-y)^2`. Recover them, rebuild `p, q`, and decrypt.

## 3. Solve

```python
import math

ct = 1046038076233413876680986621738638966868902190991554511891709431142926821179422307244746230382433945021363558520372439295018128820530515472036158797508375
n  = 8747185035038982590352709040026122318881751481045969499780427282145739554557145347428163122801488496160428126673378817922050559571378731528689279527994219
r  = 1333932344710022001826837667329537548527

A  = (n - 1) // r
s  = A % r                 # = x + y  (since x+y < r)
xy = (A - s) // r          # = x * y

disc = s*s - 4*xy
t    = math.isqrt(disc)    # = x - y
x, y = (s + t)//2, (s - t)//2

p, q = x*r + 1, y*r + 1
assert p*q == n

phi = (p - 1) * (q - 1)
d   = pow(65537, -1, phi)
m   = pow(ct, d, n)
print(m.to_bytes((m.bit_length()+7)//8, "big").decode())
```

Output:

```
SkillBit{aLLLways_th3_w4yy}
```

The recovered plaintext is the challenge's own RSA plaintext (correct `SkillBit{` prefix)
and the factors multiply back to `n` - a structural oracle, not a guess.

## 4. Flag

```
SkillBit{aLLLways_th3_w4yy}
```

("always the way" - and yes, the four L's and the pun on lattice-free factoring are the
author's.)
