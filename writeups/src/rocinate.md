# Rocinate

**Event:** HICyberCon CTF 2026
**Category:** crypto
**Flag:** `hiCTF{lmaoooo_w0t???y0u_d1d_17_??435p37++}`

---

**Flag:** `hiCTF{lmaoooo_w0t???y0u_d1d_17_??435p37++}`

---

## 1. Challenge

`extracted/chall.py` (also `extracted/chall.txt` = `print(a, b, N, Zs, Cs, Ts)`):

```python
flag = 'hiCTF{***}'
def lcg(a, b, x, N): return (a*x + b) % N

def gen_params(sz, n, s):
    p, q = getPrime(sz), getPrime(sz)
    N = p * q
    r = random.randint(1, N); Rs = [r]              # r0  -- FIRST random call
    e = random.randint(1, N)                        # e   -- SECOND
    a, b = random.randint(1, N), random.randint(1, N)   # a, b
    for _ in range(n - 1):
        Rs.append(lcg(a, b, Rs[-1], N))
    Cs = [random.randint(1, N) for _ in range(n)]
    Zs = [ri*pow(s, ci, N) for ri, ci in zip(Rs, Cs)]   # NOTE: no final % N
    Ts = [pow(ri, e, N) for ri in Rs]
    return a, b, e, N, Zs, Cs, Rs, Ts

a, b, e, N, Zs, Cs, Rs, Ts = gen_params(1024, 100, bytes_to_long(flag.encode()))
print(a, b, N, Zs, Cs, Ts)
```

We are given `a, b, N, Zs, Cs, Ts` (space-separated; `parse.py` → `data.json`).
`zs[i] = r[i]·s^{Cs[i]}`, `Ts[i] = r[i]^e`, and `r[i]` is the LCG orbit of the secret `r0`.
`r0`, `e`, `s` are unknown.

Plan: recover `r0` from the Mersenne-Twister stream used by `random`, then
`r[i] = LCG^i(r0)`, so `A_i := Zs[i]/r[i] = s^{Cs[i]} (mod N)`; since the published
`Cs[i]` are the exponents and `gcd(Cs)=1`, a single extended-Euclid combination gives `s` exactly.

## 2. Mersenne-Twister recovery (the hard part)

`Zs[i] ~4090 bits`, `N` is 2047-bit, so `a,b,Cs[i]` are 2047-bit `random.randint(1,N)` values.
Three traps:

1. **`randint(1,N)` is not a bare `getrandbits(2047)`.** It is `1 + _randbelow(N)`, i.e.
   `g = getrandbits(2047); while g >= N: g = getrandbits(2047)`. With `2^2047/N ≈ 1.28`
   the rejection probability is ≈ 0.219, so consecutive published draws are **not**
   contiguous in the MT word stream (whole 64-word rejected attempts are missing).
2. **`getrandbits(2047)` = 64 genrand words, LSB-first, and the 64th word is `>>1`** -
   its low bit is *lost*. So each draw exposes 64 words but the LSB of every `word[63]`
   is unobservable from the value.
3. **The twist is not injective**: CPython's in-place twist never uses `state[0]`, so a
   32-bit word is lost per inverse step - naive "untemper + inverse-twist all the way
   back" drifts. This is why earlier attempts failed.

Working method (`solver.py`):

* **Find a contiguous run.** Build the per-draw 64-word decomposition of
  `D = [a, b] + Cs`; a run `D[j..j+L-1]` is contiguous iff untempering its first 624 words
  and twisting reproduces the following words. The data yields runs of length 11 at
  `j = 20, 22` and of length 10 at `j = 17..26`.
* **Fix the lost LSBs.** Untemper the window (624 words) with the lost bits set to 0; the
  true state differs only by `U1 = untemper(1)` at the 9 truncated word positions
  (temper/untemper are GF(2)-linear). Brute-force the 2^9 choices, and keep the combo
  whose forward-generated MT stream reproduces **all** subsequent published `Cs`
  (rejection-aware). Exactly one combo passes (for the winning run: `j=17, combo=471`).
* **Walk backwards to the start.** For the anchor at absolute position `A = 64·T`
  (`T` = number of attempts before the anchor), untwist `K = ceil(A/624)` times; if the
  residual "free-word" corruption lands at negative positions the state is exact on
  `>=0`. Enumerate `T` and the two leading draws; `r0` is the first accepted block
  (value `< N`), `e` the second. Decisive check: `pow(r0, e, N) == Ts[0]`.

Run: `.venv/bin/python solver.py data.json`

```
runs: [(20,11),(22,11),(17,10),(18,10),...,(26,10)]
run j=20 L=11: 1 LSB combos pass ([186])
run j=22 L=11: 1 LSB combos pass ([302])
run j=17 L=10: 1 LSB combos pass ([471])
MATCH j= 17 T= 28 combo= 471 g= 1
r0 = 1235310913929046981501713248276380234...   (full value in final.py)
e  = 1179908898524522142711694858107463158...
s  = 57093359257736829004393844467680814825456194741017928601536104291193196400193820508821249982710098813
flag = b'hiCTF{lmaoooo_w0t???y0u_d1d_17_??435p37++}'
```

## 3. The exponent trick

With `r0` known, `Rs` follow from the published LCG. Then for every `i`:

```
A_i = Zs[i] · r[i]^{-1} mod N = s^{Cs[i]} mod N
```

Run the iterative extended Euclidean algorithm over the published exponents `Cs[0..99]`
to get Bezout coefficients with `Σ k_i·Cs[i] = g = gcd(Cs)`. Here `g = 1`, so

```
s = Π A_i^{k_i} mod N   (modular exponentiation handles negative k_i via inverses)
```

`s` is a ~27-byte integer → `long_to_bytes(s) = b'hiCTF{...}'`.

## 4. Proof (re-encryption) - `final.py`

```
MT stream forward from anchor reproduces 85/85 published draws (Cs[15..99] and later) exactly
backward walk (untwist x3, T=28) recovers r0 and e; e is the 2nd stream draw, consistent
Zs reproduced: 100/100
Ts reproduced: 100/100
Zs[i]/r[i] == s**Cs[i] for all i: True
flag = b'hiCTF{lmaoooo_w0t???y0u_d1d_17_??435p37++}'
VERIFIED
```

That is: the reconstructed MT19937 stream reproduces every published `Cs` value; the
recovered `r0,e` re-encrypt to all 100 published `Ts`; and the recovered `s` re-encrypts
all 100 published `Zs` **exactly** (`Zs[i] = r[i]·pow(s,Cs[i],N)`, no final reduction).
