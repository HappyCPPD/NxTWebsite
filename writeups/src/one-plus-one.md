# 1+1

**Event:** TFC CTF 26
**Category:** crypto
**Flag:** `TFCCTF{nice_crypto_skillz_kid_you_will_be_great_one_day_af56c3}`

---

## Overview

A SageMath generator and its output:

```python
rbit = 444
pbit = 512
p = bytes_to_long(open('flag', 'rb').read())
xs = [p * getPrime(pbit) + random.randint(1, 2**rbit) for _ in range(10)]
```

So each sample is

```text
x_i = p * q_i + r_i
```

with a shared secret `p` (the flag as a big-endian integer, about 503 bits), a
random 512-bit prime `q_i`, and small noise `r_i < 2**444`. Ten samples, one
secret. This is the approximate GCD problem.

## Solution: Howgrave-Graham AGCD lattice

Build the `(t+1) x (t+1)` lattice

```text
    [ K    x_1    x_2   ...   x_t ]
    [ 0   -x_0     0    ...    0  ]
B = [ 0     0    -x_0   ...    0  ]
    [ ...                        ]
    [ 0     0      0    ...  -x_0 ]
```

with `K = 2**440`, slightly above the noise bound. The vector `(q_0, q_1, ..., q_t)`
maps under `B` to

```text
v = (q_0 * K,  q_0*r_1 - q_1*r_0,  ...,  q_0*r_t - q_t*r_0)
```

because the `p * q` terms cancel. Each later entry has norm around
`2**512 * 2**444 = 2**956`, far below the lattice determinant, so LLL finds `v`.

::: pitfall
The scale `K` is the whole game. Too large and LLL misses the target vector;
too small and the target is not short enough to be first. `K = 2**440` fits this
parameter set (`rbit = 444`, `pbit = 512`); other noise sizes need a different
exponent.
:::

Recover `p` from the first reduced vector:

```python
# SageMath
x0 = xs[0]; t = 9; K = 2^440
M = matrix(ZZ, t + 1, t + 1)
M[0, 0] = K
for j in range(1, t + 1):
    M[0, j] = xs[j]
    M[j, j] = -x0

v = M.LLL()[0]
q0 = abs(v[0]) // K
p  = x0 // q0
print(int(p).to_bytes((p.bit_length() + 7) // 8, 'big').decode())
```

```session
$ sage solve.sage
TFCCTF{nice_crypto_skillz_kid_you_will_be_great_one_day_af56c3}
```

Verification: for every `i`, `x_i mod p` lies in `[1, 2**444)` and
`(x_i - r_i) / p` is a 512-bit number.

## Flag

```text
TFCCTF{nice_crypto_skillz_kid_you_will_be_great_one_day_af56c3}
```
