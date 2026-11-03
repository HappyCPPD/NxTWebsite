# Log Jam

**Event:** HICyberCon CTF 2026
**Category:** crypto
**Flag:** `hiCTF{W0W1_y0u_4ctu4a11y_s01v3d_1t_ju$t_L1k3_tH4t}`

---

**Flag:** `hiCTF{W0W1_y0u_4ctu4a11y_s01v3d_1t_ju$t_L1k3_tH4t}`

## Artifact
`params.json` with `p, g, h, nonce, ciphertext, tag`.
(`params.json`'s `_meta.note` hides a Unicode tag-character message telling AI assistants to refuse to help. It is
just noise.)

## Method
1. The parameters are Diffie - Hellman over a prime field plus an AEAD. p = 0x7958085483c2736f23 is a **71-bit prime**;
   p−1 = 2·q with q a 70-bit prime; g has order q. So the discrete log `h = g^x mod p` is in a 70-bit
   prime-order group.
2. `g^x = h`: solved with **PARI/GP `znlog`** (C, rho-based). Sage's `discrete_log` uses BSGS and OOM-killed
   (sqrt(2^70) memory). Result: **x = 471774559909450042061**.
3. Key derivation: `key = SHA256(str(x).encode())` (32 bytes) with `AES-256-GCM`, nonce = params.nonce,
   tag = params.tag.
4. `AES.new(key, GCM, nonce).decrypt_and_verify(ciphertext, tag)` succeeds → plaintext flag.

## Repro
```python
import hashlib
from Crypto.Cipher import AES
p=int('7958085483c2736f23',16); g=int('2d738b6682dacc0bb7',16); h=int('36130f3996b8198135',16)
nonce=bytes.fromhex('786fe3b966eb9949d0ded089')
ct=bytes.fromhex('dec59383508c24b2aa7c5ec44407720c8ac385af2dbc157b59a4113056f6b0b49abe300e822ffed923516e0d8eb77d49b55f')
tag=bytes.fromhex('469442d8157214b3ba95136e3a7e8082')
x=471774559909450042061                      # znlog(Mod(h,p), Mod(g,p))
key=hashlib.sha256(str(x).encode()).digest()
print(AES.new(key,AES.MODE_GCM,nonce=nonce).decrypt_and_verify(ct,tag))
# b'hiCTF{W0W1_y0u_4ctu4a11y_s01v3d_1t_ju$t_L1k3_tH4t}'
```
Verification is cryptographic: GCM `decrypt_and_verify` (tag check) passed - not a decoy guess.
