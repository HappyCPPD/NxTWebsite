# The Missing Archive

**Event:** SolarCTF
**Category:** crypto
**Flag:** `SOLARCTF{31a1e6f428f7b196ac1fe4}`

---

**Category:** Crypto (RSA) · **Author:** sAOeNT

> At 03:17, the archive node "Short Sleeves" disappeared from the radars. The emergency
> team reached the station too late: the connection was lost, the storage facility
> switched to isolation mode, and the operator left no explanation.
>
> Task: `generate.py`, `output.txt`

## 1. The scheme (from `generate.py`)

- The flag is 32 bytes, split evenly across `N_INSTANCES = 4`, so **8 bytes per instance**.
  Each chunk is placed as the **last 8 bytes** of a 32-byte message (24 random padding
  bytes prepended).
- Four independent **RSA-2048** instances (`p, q` are 1024-bit primes, `e = 65537`). The
  moduli share no common factor, so there is no GCD shortcut.
- **The leak:** for each instance one prime is leaked *partially*, the **top 518 bits**
  (`h = prime >> (1024 - 518)`). The low **506 bits are unknown**.
- So each instance is the classic **"factoring with known high bits"** problem: recover
  `p = (h << 506) + x` with `0 ≤ x < 2^506` via **Coppersmith / LLL**.

`output.txt` holds `N_INSTANCES=4`, `E=65537`, `len(flag)=32`, then four `(n, c, h)`
triples.

## 2. Factoring with Coppersmith

518 known bits out of 1024 is only just past the halfway bound, so a plain single-shot
Coppersmith (`copp.py`) needs a big lattice and still struggles. Guessing a few extra
high bits makes the unknown part smaller and the lattice happier:

- `copp.py` runs high-bit Coppersmith on one instance with lattice parameters `m = t = 26`
  (a 61-dimensional lattice) and prints `FACT idx p q` on success.
- `copp_bf.py` additionally guesses the next 4 bits of `p` (16 guesses `g`) and solves
  for the rest.
- `driver.py` fans `copp_bf` out over 4 instances × 16 guesses on 10 workers and cancels
  the pending guesses for an instance as soon as one of them factors it.

Each LLL run took roughly 250-760 s. The first driver pass factored instances 1, 2 and 3,
while instance 0 timed out on every guess. A second pass on instance 0 with a narrowed
guess space (`g = 4`, low guesses first) factored it as well, and three neighbouring
guesses all returned the same `p, q`.

```bash
# single instance, high-bit Coppersmith (m=t=26)
sage -python copp.py 0 26 26          # prints "FACT 0 p q" on success

# with top-4-bit guess g, brute force the 16 guesses for one instance
sage -python copp_bf.py 0:4:6 26 26

# all four instances, fanned out (writes factors.txt)
python3 driver.py
```

## 3. Decrypting and reassembling

With all four `p, q` pairs (each checked with `p·q == n`), it's plain RSA:
`d = e⁻¹ mod (p-1)(q-1)`, `m = c^d mod n`, keep the last 8 bytes.

One snag: `driver.py` writes lines as `FACT idx p q`, but the first version of
`decrypt.py` expected `idx p q` and silently skipped every line, then died with
`KeyError: 0`. Parsing the `FACT` prefix fixes it:

```python
from Crypto.Util.number import long_to_bytes, inverse
E=65537
v=[int(x) for x in open("output.txt").read().split()]
recs=[(v[3+3*i],v[4+3*i],v[5+3*i]) for i in range(4)]
f={}
for line in open("factors.txt"):
    s=line.split()
    if len(s)==4 and s[0]=="FACT": f[int(s[1])]=(int(s[2]),int(s[3]))
flag=b""
for i,(n,c,h) in enumerate(recs):
    p,q=f[i]; assert p*q==n
    flag+=long_to_bytes(pow(c,inverse(E,(p-1)*(q-1)),n))[-8:]
print(flag.decode())
```

| inst | decrypted tail (8 B) |
|------|----------------------|
| 0 | `SOLARCTF` |
| 1 | `{31a1e6f` |
| 2 | `428f7b19` |
| 3 | `6ac1fe4}` |

Concatenated in instance order:

```
SOLARCTF{31a1e6f428f7b196ac1fe4}
```

## 4. Takeaways

- Leaking just over half the bits of a prime is enough to factor RSA with Coppersmith,
  but near the bound it pays to brute force a few more bits rather than grow the lattice.
- Run the instances in parallel and cancel the losers. Most guesses are misses.
- When the math works and the script doesn't, check the file formats between your own
  tools first.
