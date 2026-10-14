# The Ledger

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{lll_dense}`

---

**Prompt:** "Hand it 16 bytes. It will tell you nope."

## 1. Recon

`chall` is a stripped x86-64 ELF. Running it with no input prints
`need exactly 16 bytes of input`; with any 16 bytes it prints `nope.` and
on success `CORRECT -- the flag is the input you just gave me.`

```
$ printf 'AAAAAAAAAAAAAAAA' | ./chall
nope.
```

Imports: `fread`, `memcmp`, `puts`, `fprintf`. So it reads 16 bytes and
compares something derived from them against a hard-coded value.

## 2. Reversing the check

Disassembly of the main routine (`0x4003c0`):

1. `fread(buf, 1, 16, stdin)` - 16 bytes at `rsp+0x10`.
2. Zero a 64-byte (512-bit) accumulator `R` at `rsp+0x20`.
3. `r10 = 0x401360` - a table of 128 entries, **64 bytes each** (512-bit little-endian integers).
4. Loop `i = 0 .. 0x7F`:
   - test bit `i` of the 16-byte input (`byte[i>>3]`, bit `i&7`);
   - if set, add the whole 512-bit table entry `T[i]` into `R` with
     carry propagation (`add`/`adc` over 8 qwords, `r10 += 0x40`).
5. `memcmp(R, 0x401320, 64)` - compare `R` against a fixed 64-byte target.

So the check is:

```
sum over set bits i of  T[i]  ==  TARGET      (mod 2^512)
```

i.e. a **128-variable subset-sum / knapsack**: the 16-byte input is exactly
the 128-bit selector vector.

## 3. Data extraction

`.rodata` is mapped at vaddr `0x4012a0` = file offset `0x12a0`, so
`file_off = vaddr - 0x400000`.

- `TARGET` @ `0x401320`, 64 bytes
- `TABLE`  @ `0x401360`, 128 × 64 bytes

`extract.py` pulls these and reads each as a little-endian integer.

Key measurements:

- every `T[i]` is a 400-bit integer;
- `TARGET` is 406 bits, and `sum(T)` is 407 bits.

Because the total sum is `< 2^512`, **no modular wraparound ever happens** -
the check is an exact integer subset sum.

Density `d = n / bits = 128 / 400 ≈ 0.32`, far below the
Lagarias - Odlyzko threshold (0.9408), so a LLL/BKZ lattice attack recovers
the (essentially unique) subset.

## 4. Lattice solution

Standard low-density subset-sum lattice, dimension `n+1 = 129`:

```
B[i][i] = 2            (i = 0..n-1)
B[i][n] = T[i] * W
B[n][j] = 1            (j = 0..n-1)
B[n][n] = TARGET * W
```

A solution `x ∈ {0,1}^n` with `Σ x_i T[i] = TARGET` yields the short
lattice vector `(2x_0-1, ..., 2x_{n-1}-1, 0)`, entries `±1`.
`W = 2^12` sharpens the tail column.

LLL alone at delta 0.99 was not strong enough on the 400-bit entries; a
short **BKZ block size 20** finished the reduction and produced a row
`(±1,...,±1, 0)`. Reconstructing bits `x_i = (v_i+1)/2` and packing them
LSB-first into 16 bytes gives the input:

```
key hex  : 69736663727b6c6c6c5f64656e73657d
key ascii: isfcr{lll_dense}
```

(`solve2.py`, ~1 - 2 min.)

## 5. Verification

```
$ printf 'isfcr{lll_dense}' | ./chall
CORRECT -- the flag is the input you just gave me.
```

Sum check in `solve2.py` also prints `verify: True`.

## Flag

```
isfcr{lll_dense}
```

## Files

| file        | purpose                                   |
|-------------|-------------------------------------------|
| `chall`     | original binary                           |
| `extract.py`| parse ELF, dump table/target → `knap.json`|
| `solve2.py` | LLL+BKZ lattice solve (the working one)   |
| `knap.json` | extracted target + 128 vectors            |
| `key.bin`   | recovered 16-byte input                   |

Requires `fpylll` (`pip install fpylll`).

