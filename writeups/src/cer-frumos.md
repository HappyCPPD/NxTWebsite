# CER FRUMOS

**Event:** TFC CTF 26
**Category:** crypto
**Flag:** `TFCCTF{ursu_ursa_bea_ursus_intrun_urus_verzuliu}`

---

## Overview

The challenge seeds Python's `random` module with a 128-bit integer, prints 625
partial outputs, then derives an AES-256-CBC key and IV from two later outputs
and encrypts the flag. We get `out.txt`: 625 lines of 48-bit integers plus the
hex ciphertext.

```python
x = random.getrandbits(48)   # 32 + 16 bits from 2 tempered state words
random.getrandbits(16)       # discarded
print(x)
# ... after 625 samples ...
for _ in range(10):
    random.getrandbits(32)   # discarded
key = sha256(str(random.getrandbits(64)).encode()).digest()
iv  = sha256(str(random.getrandbits(64)).encode()).digest()[:16]
```

## Vulnerability

`random` is MT19937, a 624-word (19968-bit) state that is fully deterministic
once known. Each 48-bit sample leaks the entire lower 32 bits of one tempered
output plus the top 16 bits of the next. Across 625 samples that is more than
1000 tempered words against a 624-word state, so the state is over-determined
several times over.

::: insight
Every partial output is a linear constraint on the internal state. Feed enough of
them to a solver, or invert the temper and solve the GF(2) recurrence directly.
Either recovers the whole state, and with it every later output, including the
two words that seed the key and IV.
:::

## Solution

Model the 624 state words as symbolic 32-bit bitvectors in Z3, mirroring the
twist and temper from CPython's `_randommodule.c`. A `next_word()` helper tracks
the output index and re-twists on wrap. Then replay the exact call sequence:

```python
for x in samples:
    solver.add(next_word() == (x & 0xFFFFFFFF))          # lower 32 bits
    solver.add(Extract(31, 16, next_word()) == (x >> 32)) # top 16 of next word
    next_word()                                           # discarded 16-bit call

for _ in range(10):
    next_word()

key_lo, key_hi = next_word(), next_word()
iv_lo,  iv_hi  = next_word(), next_word()

assert solver.check() == sat
model = solver.model()
key_seed = u32(key_lo) | (u32(key_hi) << 32)
iv_seed  = u32(iv_lo)  | (u32(iv_hi)  << 32)
key = sha256(str(key_seed).encode()).digest()
iv  = sha256(str(iv_seed).encode()).digest()[:16]
flag = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(enc)
```

```session
$ python3 solve.py
key seed: 4364408293663289775
iv seed:  9427524340023772294
plaintext: TFCCTF{ursu_ursa_bea_ursus_intrun_urus_verzuliu}
```

## Notes

Z3 is overkill here. Given full lower-32-bit words for all 625 samples, inverting
the temper function and solving the linear recurrence over GF(2) recovers the
state far faster. Either way: never seed AES keys from `random`, use `secrets` or
`os.urandom`.

## Flag

```text
TFCCTF{ursu_ursa_bea_ursus_intrun_urus_verzuliu}
```
