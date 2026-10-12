# The Ledger

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{lll_dense}`

---

A stripped x86-64 ELF reads 16 bytes and compares a derived 512-bit accumulator against a hard-coded target. The check: zero a 64-byte accumulator `R`; for each of 128 bits of the 16-byte input, if bit `i` is set, add a 512-bit table entry `T[i]` into `R` with carry propagation; then `memcmp(R, TARGET, 64)`. This is a **128-variable subset-sum / knapsack**: the 16-byte input is exactly the 128-bit selector vector.

Extraction shows every `T[i]` is a 400-bit integer, `TARGET` is 406 bits, `sum(T)` is 407 bits - no modular wraparound ever happens, so the check is an exact integer subset sum. Density `d = 128/400 ≈ 0.32`, far below the Lagarias-Odlyzko threshold (0.9408), so LLL/BKZ recovers the (essentially unique) subset.

**Lattice:** standard low-density subset-sum lattice, dimension 129: `B[i][i]=2`, `B[i][n]=T[i]*W`, `B[n][j]=1`, `B[n][n]=TARGET*W` with `W=2^12`. A solution `x ∈ {0,1}^n` yields a short lattice vector `(±1,...,±1,0)`. Plain LLL at delta 0.99 was not strong enough on the 400-bit entries; **BKZ block size 20** finished the reduction and produced the needed row. Reconstructing bits and packing LSB-first gives the input.

```
key hex  : 69736663727b6c6c6c5f64656e73657d
key ascii: isfcr{lll_dense}
$ printf 'isfcr{lll_dense}' | ./chall
CORRECT -- the flag is the input you just gave me.
```

Requires `fpylll`.
