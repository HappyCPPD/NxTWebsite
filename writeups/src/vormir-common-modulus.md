# Vormir Common Modulus

**Event:** ByteMe CTF 26
**Category:** crypto
**Points:** 100
**Flag:** `OWASP{v0rm1r_tw1st3d_rsa_l34ks_th3_s0ul}`

---

## TL;DR
Classic **Common Modulus** attack. Two RSA ciphertexts `c1`, `c2` were produced
with the **same modulus `n`** but **coprime public exponents** `e1=65537`,
`e2=65539`, over the *same* plaintext. Their exponents satisfy
`a*e1 + b*e2 = 1`, so the plaintext is recovered directly:
`m = c1^a · c2^b mod n`.

## Given data (params.txt)
```
n  = 16380649768533394557837493376413306403300053927332145442950164332328030751564185489519565597585555867737606727528343
e1 = 65537
e2 = 65539
c1 = 13717084049277399427945358975177210874446528287993178469838547381506741616766449871863462627142297960244208456711847
c2 = 4601321998457411971134687661444766716276847022305030736758227088246554672740623255330037934526510403437754437399162
```

## Approach
1. Confirm `gcd(e1, e2) = 1` (both are primes, so yes).
2. Run the extended Euclidean algorithm to get `a, b` with `a·e1 + b·e2 = 1`.
   Result: `a = 32769`, `b = -32768`.
3. Compute `m = c1^a · c2^b (mod n)`, taking `c2^b` as
   `inverse(c2)^|b| mod n` since `b < 0`.
4. Decode `m` as big-endian bytes → flag.

## Solve
```bash
python3 solve.py
# OWASP{v0rm1r_tw1st3d_rsa_l34ks_th3_s0ul}
```

## Why it works
RSA encrypts `c = m^e mod n`. With two exponents on the same `n` and same `m`:
`c1^a · c2^b = m^(a·e1 + b·e2) = m^1 = m (mod n)`.
No factoring required - the weakness is reusing one modulus with multiple
exponents over the same message.

## Files
- `params.txt` - challenge input
- `solve.py` - common-modulus recovery script

