# SPI TPM Free Trial

**Event:** HITCON CTF 2026
**Category:** crypto
**Flag:** `hitcon{531f_dE5i6N_cRy9T0Gr4Ph1C_41G0r1ThM_15_9r0B4b1Y_4_64D_1D3a_QQ}`

---

**Flag:** `hitcon{531f_dE5i6N_cRy9T0Gr4Ph1C_41G0r1ThM_15_9r0B4b1Y_4_64D_1D3a_QQ}`

> _self design cryptographic algorithm is probably a bad idea_ - the flag says it all.

This is a reverse-engineering challenge that turns into a lattice (Hidden Number Problem) attack.
The write-up is in two parts: (1) what the service actually is, and (2) the attack, including the
one subtlety that makes the difference between "impossible" and "~5 minutes on a laptop."

---

## 1. The target

```
ncat spi-tpm-rev.chal.hitconctf.com 1337        # PoW-gated
```

The handout boots an **aarch64 Linux VM** (a patched `qemu-system-aarch64` that implements three
custom `spi-tpm*` devices) whose PID 1 is a stripped static-PIE service speaking a line protocol
over serial. The service's crypto is delegated to a "TPM firmware" shared object
`libspi_tpm_firmware.so` - and crucially that `.so` is **native x86-64 with symbols**, so it can be
`dlopen`'d directly on the host and driven with arbitrary inputs offline. All attack development is
done against this firmware; the remote is only touched to capture one session.

### Protocol

```
budget                     -> "budget <remaining> queries <remaining>"
get_flag                   -> "flag <slot> <hexblob>"      (precomputed at boot)
genkey                     -> "key <slot>"                  (fresh random key in a new slot)
encrypt KEY COST HEX       -> "ciphertext <hexblob>"
decrypt HEX                -> "plaintext <hex>"
quit
```

Initial banner: `budget 1024 queries 27`. Every command (even errors) costs a query, and there is
a hard **27-query cap per connection**. Budget cost:

```
encrypt: COST * (ceil(len/4) + 32)
decrypt: nonce * (ceil(len/4) + 256)     # nonce read from the blob header
```

The flag is encrypted at boot under **slot-1** with a large, fixed `COST = 548787` and a random IV.
We hold a chosen-plaintext oracle under that **same slot-1 key** (`encrypt 1 <cost> <hex>`), which
is what the whole attack rests on.

### Blob format (verified against firmware + live service)

```
off 0   magic "STP1"
off 4   02 00 28 00            version / const
off 8   IV      (u32 LE)       fresh getrandom per encrypt
off 12  nonce = COST (u32 LE)
off 16  bytelen (u32 LE)
off 20  key-check (u32 LE)     <-- the leak (see §3)
off 24  MAC (16 bytes)
off 40  ciphertext             4 bytes per 32-bit plaintext word, LE, INDEPENDENT per word
```

(The very first pitfall: an earlier model read the ciphertext at offset 24 - that's the MAC. The
ciphertext starts at **offset 40**, and each 32-bit word is encrypted independently.)

### The cipher

For each little-endian 32-bit plaintext word `w`:

```
E0   = perm(w,  IV, j, COST, sel=0, dir=0)
fe   = Feistel^COST(E0, kA, kB)
ct_j = perm(fe, IV, j, COST, sel=1, dir=1->0)
```

* `perm` is a **TEA-variant and completely key-independent** - its schedule comes only from
  `(IV, block-index j, COST, selector)`. Because it's keyless, the *local* firmware can encrypt and
  decrypt *remote* blobs; we only ever need the key for the Feistel layer.
* `Feistel^COST` is a balanced 16/16 Feistel over the 32-bit block, run `COST` times. One round:
  `(L,R) -> (R ^ F0(L), L)`, with round selector `r & 3` (period 4).
* The **only secret** is the 128-bit key `(kA, kB)` (key bytes 0..15, full entropy from a real
  `getrandom` - no PRNG state to attack).

The round function (all constants are 64-bit; `sm` is the splitmix64 finalizer):

```
round_f(L, kA, kB, rsel):
    Z  = rol(kB,17) ^ kA ^ (L*C1) ^ (rsel*C2) ^ C3
    P  = sm(Z + GOLD)
    Y  = (rol(kA,29) ^ kB) ^ P
    out16 = fold16( sm(Y + GOLD) )

sm(x)  = x^=x>>30; x*=MA; x^=x>>27; x*=MB; x^=x>>31
fold16(v) = (v ^ v>>16 ^ v>>32 ^ v>>48) & 0xffff

C1=d6e8feb86659fd93  C2=a5a3564e27f8862f  C3=62696c696e2d7221
GOLD=9e3779b97f4a7c15  MA=bf58476d1ce4e5b9  MB=94d049bb133111eb
```

### Why you can't just decrypt the flag

The flag blob's `nonce = COST = 548787` is baked into the header and authenticated by the MAC.
A direct `decrypt` would cost `548787 * (ceil(70/4)+256) ≈ 1.5e8 >> 1024`, and the nonce can't be
lowered without forging the MAC. So the intended path is **recover `(kA,kB)` and decrypt offline.**

Dead ends (all measured, not assumed): the 4-round map has cycle length > 20M (no period
shortcut); `Feistel^a ∘ Feistel^b ≠ Feistel^(a+b)` (the round counter resets per call); the key is a
full 128 bits (no 32-bit reduction); SAT/SMT (z3, bitwuzla, CryptoMiniSat) all hang on the two
64-bit multiplies in `sm`, so inverting the round function algebraically from F0 samples is out.

---

## 2. Two oracles

An `encrypt 1 1 <N words>` (i.e. **COST = 1**, one Feistel round) gives us two very different
leakage channels, both under the flag's key:

### (a) F0 samples - a perfect *verifier*, useless as a *solver*

For COST=1 the Feistel is a single round, and since `perm` is keyless we can peel it off:

```
F0(L) = ( perm(ct_j, IV, j, 1, sel=1, dir=1) >> 16 ) ^ R      where (L,R) = (E0>>16, E0&0xffff)
```

So each ciphertext word yields one `(L, F0(L))` pair - 16 output bits of the round function at a
known 16-bit input, **key-independent to extract**. A single cheap encrypt gives hundreds of these.
They can't be *inverted* to the key (that's the SAT wall), but they make a near-perfect **filter**:
a wrong key matches ~182 independent 16-bit samples with probability 2^-2912. Zero false positives.

### (b) The key-check - a 9-bit leak of a bilinear form in the key

Byte 20 of every blob is

```
key-check = known_part(IV) ^ ( field(kA,kB,IV) >> 118 )
field(kA,kB,IV) = ( cA*kA + cB*kB + cC*(kA*kB) )  mod p,   p = 2^127 - 1
```

`known_part(IV)` is a public splitmix of `GOLD ^ IV ^ CT` (computable offline), and the public
coefficients `cA, cB, cC` are IV-derived. So **every blob leaks the top 9 bits of a known bilinear
form in the 128-bit key.** This is a Hidden Number Problem with a quadratic (`kA*kB`) cross term.

---

## 3. The attack: HNP over the key-check

With `n` leaks we get `n` equations

```
cA_i*kA + cB_i*kB + cC_i*(kA*kB) = leak_i * 2^118 + e_i   (mod p),   0 <= e_i < 2^118
```

Treat `(kA, kB, z=kA*kB)` as three hidden numbers (`kA,kB` are 64-bit; `z` is a ~127-bit nuisance).
Eliminate `z` by pairing each equation with equation 0, build the standard HNP embedding lattice,
LLL/BKZ-reduce, and the key sits at a short lattice vector. Measured planted-vector norm, relative
to the Gaussian heuristic of the lattice:

| leaks n | ratio ‖planted‖/GH | status |
|--------:|-------------------:|--------|
| 26 | 2.48 | wall - ~1e11 ball, infeasible |
| **27** | **1.975** | **tractable - ~1.6e9 ball** |
| 28 | 1.58 | easy (fpylll finds it in ~40 s) |
| 29 | 1.28 | trivial |

The planted vector is **not** the shortest vector and **not** a basis row - BKZ won't surface it
directly. You must enumerate the ball up to ~2·GH and filter. fpylll's evaluator stores every
solution it finds (RAM blow-up at this count), so a **streaming** enumerator with an on-the-fly
filter is required. The F0 samples from §2(a) are exactly that filter.

### The one subtlety that unlocks it: the 27th leak

A connection allows 26 `encrypt`s plus one `get_flag` = 27 blobs. The natural reflex is "`get_flag`
costs a query and returns the flag, not a leak → only 26 usable leaks," and at **n = 26 the attack
is a brick wall** (ratio 2.48).

But **the flag blob has its own key-check at offset 20**, computed with the same slot-1 key and a
fresh IV. It is a perfectly good 27th sample. Counting it moves the problem from n=26 (impossible)
to **n=27 (ratio 1.975)** - the difference between the two columns above. The capture script in this
repo had been discarding it:

```python
if B['blen']>4 and B['cost']>1000: flagblob=blob; continue   # <- the 27th leak, thrown away
```

Add it back (`leak = key_check ^ known_part(IV)`) and you have 27 leaks from a single connection,
no re-capture needed.

### The enumerator

A naive Fincke - Pohst that scans `[lo,hi]` at every level spins forever at the top level
(width ∝ √(R²/r_last)) on an LLL-only basis whose GSO profile spans ~1e15. Fixes:

1. **Schnorr - Euchner center-out ordering with early `break`** - at each level start at the rounded
   center and walk outward, stopping a direction the moment the 1-D term pushes the partial norm
   past the radius.
2. **BKZ-40 preprocessing** flattens the GSO profile (top level collapses to just 9 branches,
   `x_last ∈ [-4,4]`).
3. **F0 filter at the leaf**: reconstruct `(kA,kB)` from the vector's first two coordinates, check a
   couple of F0 samples as a cheap pre-filter, then all 182; exit on first match.
4. **Shard** the 9 top-level branches across cores.

Throughput ~3M nodes/s/core; the n=27 ball clears in a few minutes on 16 cores.

---

## 4. Putting it together

```bash
# 1. one remote connection: 26x  encrypt 1 1 <7 words>   +  get_flag
#    -> 26 leaks, 182 F0 samples, and the flag blob      (remote_pipe_3.json)

# 2. add the flag blob's own key-check as the 27th leak
python3 mk_remote27.py                         # -> remote27.json (27 leaks, 182 F0, flag)

# 3. build + BKZ-40 reduce the HNP lattice, radius 1.95*GH
python3 export_lattice.py remote27.json 27 latR27.txt 1.95 40

# 4. sharded streaming enumeration with the F0 filter (~5 min, 16 cores)
./shard_run.sh latR27.txt ./enum2 shardR27
#  -> FOUND kA=a255c9ac2ef7037f kB=e77aeddfd81acbd7   (0/182 F0 mismatches)

# 5. decrypt the flag blob offline: keyless perm inverse (native firmware) + Feistel^-548787
```

Validation before trusting any of it: on locally-generated data with a **known** key, n=27 was
solved in ~41 s and the recovered key matched exactly; n=28 was found too, confirming the
enumerator's correctness.

Final decryption (note: the firmware's native `perm` inverse must be used - a hand-rolled Python
inverse of the TEA-variant was subtly wrong):

```
flag blob: IV=ca54c2d6  COST=548787  bytelen=70
for each ct word j:
    fe = perm(ct_j, IV, j, COST, sel=1, dir=1)      # native, keyless
    E0 = feistel_inv(fe, kA, kB, COST)              # 548787 rounds, python
    w  = perm(E0,  IV, j, COST, sel=0, dir=1)        # native, keyless
```

```
hitcon{531f_dE5i6N_cRy9T0Gr4Ph1C_41G0r1ThM_15_9r0B4b1Y_4_64D_1D3a_QQ}
```

---

## 5. Takeaways

* **Count your oracles.** The whole challenge is balanced so that 26 leaks are a wall and 27 just
  barely work. The 27th leak is hiding in plain sight inside the flag blob you were going to fetch
  anyway. Throwing away the key-check on the `get_flag` response is the difference between
  "unsolvable" and "five minutes."
* **A borderline lattice wants a streaming enumerator, not a bigger `nr_solutions`.** The planted
  vector is near the edge of the ball; keeping the *k* shortest solutions never contains it. Stream
  the enumeration and filter with something that can't false-positive (here, 2912 bits of F0).
* **Keyless scaffolding is a gift.** Because `perm` and the F0 extraction are key-independent, every
  bit of attack development - and the final decryption of the *remote* flag blob - runs on the local
  `dlopen`'d firmware with no budget spent.
* And, per the flag: rolling your own ARX cipher and leaking 9 bits of a bilinear key-dependent
  checksum on every ciphertext is, in fact, probably a bad idea.

## Artifacts in this directory

| file | what |
|---|---|
| `model.py` | round function / Feistel reference |
| `hnp_enum.py` | HNP lattice construction (`field`, `build`, coeffs via `tool`) |
| `export_lattice.py` | build + LLL + **BKZ** reduce, dump basis/GSO/F0 for the C enumerator |
| `enum2.c` / `enum2` | streaming Schnorr - Euchner enumerator with F0 leaf filter |
| `shard_run.sh` | 9-way top-level parallel runner |
| `mk_remote27.py` | adds the flag-blob key-check as the 27th leak |
| `remote_pipe_3.json` | the captured session (26 leaks + 182 F0 + flag blob) |
| `remote27.json` | the same, with the 27th leak added |
| `notes/claude-scratchpad/tool` | native-firmware model of the key-check (`selftest`, `coeffs`, `sim`) |
