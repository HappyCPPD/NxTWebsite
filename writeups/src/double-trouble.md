# Double Trouble

**Event:** ByteMe CTF 26
**Category:** crypto
**Points:** 100
**Flag:** `OWASP{soul_stone_claimed}`

---

## 1. Challenge

> Two RSA-encrypted messages. Two public keys. Something went wrong. Recover the flag.

The handout (`challenge.txt`) gives two `(n, e=65537, c)` triples:

```
Key 1
n = 13639479...5374891
e = 65537
c = 13452128...1741564

Key 2
n = 10916292...3822627
e = 65537
c = 88443378...513140
```

The title and "something went wrong" strongly hint at **broken key generation**, and
the "two keys" framing points at once class of bug: a **shared prime** between moduli
(poor randomness / same keygen seed reused).

## 2. Recon: factor with gcd

Two RSA moduli produced with a common prime `p` satisfy `gcd(n1, n2) = p > 1`. This is
the read-only first move for any multi-key RSA challenge - it costs nothing and either
finds the factor instantly or rules the class out.

```python
from math import gcd
p = gcd(n1, n2)
# p = 109714928822485954897904690473114488551232105385763078807669039918151906354922
#     02015663568997449999980997671332001553343189818494219016208453002488063093017
```

It's `> 1`, so both moduli are broken. No need to factor anything else.

## 3. Decrypt both ciphertexts

With `p` known:

```python
q = n // p
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
```

Results:

| Key | Plaintext (raw)                          |
|-----|-------------------------------------------|
| 1   | `CBYMHAI6NC44Iw0yMy4jKg0iKyAkIjclOg==`    |
| 2   | `GAMORA`                                  |

Key 1 is clearly **base64**. Key 2 is a short ASCII word - "GAMORA" (a Marvel
Guardians name, and the challenge is flagged OWASP-style) - which is exactly the shape
of a **one-time-pad / XOR key**.

That is the "something went wrong" of the title: the same secret material (`GAMORA`)
leaked as one plaintext *and* was reused as the XOR key for the other message - a
two-time-pad style failure.

## 4. Recover the flag

```python
import base64
b64 = base64.b64decode("CBYMHAI6NC44Iw0yMy4jKg0iKyAkIjclOg==")
# b'\x08\x16\x0c\x1c\x02:4.8#\r23.#*\r"+ $"7%:'
key = b"GAMORA"
flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(b64))
# b'OWASP{soul_stone_claimed}'
```

**Flag: `OWASP{soul_stone_claimed}`**

## 5. Reproduce

```bash
python3 solve.py
```

Stdlib only. Deterministic, single-shot.

## 6. Why it works / lessons

- Always try `gcd(n1, n2)` first on multi-key RSA - shared primes are the cheapest break.
- A decryptable short plaintext that looks like a word is often the *key* to another layer
  (here XOR). Read plaintexts as data, not just as candidate flags.
- "Something went wrong" + multiple public keys ⇒ keygen/randomness bug, not padding oracle.

