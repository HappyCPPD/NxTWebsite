# OUROBOROS

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{c0d3_th4t_3ats_1ts_t41l!!}`

---

A stripped ELF64 reads exactly 32 bytes; `mmap`+`mprotect`+`memcmp` is the classic JIT fingerprint - the program manufactures machine code at runtime, executes it, and `memcmp`s a buffer. No flag string in the binary.

**What the checker does:** four JIT blocks run in sequence. Each packs 8 input bytes into a 64-bit `word`, computes `seed = word ^ state` (state starts at a fixed constant), and **synthesises a function**: `code[i] = TEMPLATE[b][i] ^ byte_lane(splitmix64(seed + (g+1)*GOLDEN))`. The code is guarded by a splitmix64 chain hash that must match a stored 64-bit constant `E[b]`, then `mprotect`+called with the working buffer. After each block, `state` updates from a chain hash of the generated code - each block eats the previous block's tail, hence *Ouroboros*. After all four, `memcmp` against a 32-byte target.

**Why the guard looks unbreakable (and isn't):** the guard is a 64-bit preimage - brute force is `2^64` per block. **The way in is to recover the CODE, not the word.** Since `code = template XOR keystream`, and the first 8 bytes of every generated function are the fixed prologue `endbr64; push rbp; mov rbp,rsp`, that's free known-plaintext against the keystream: `K0 = code[0:8] XOR template[b][0:8]`, `seed = mixinv(V0) - GOLDEN` (splitmix64 finalizer is a bijection). From `seed` the entire keystream - hence the entire generated program, hence `word[b] = seed ^ state` - follows with no search.

**The four generated programs** turn out to be a fixed invertible byte mixing of the 32-byte buffer: XOR with `7*(i-13)`, in-place forward addition with neighbor, rotate-left-3, XOR with `31*i+0x3c`.

```
block 0  isfcr{c0
block 1  d3_th4t_
block 2  3ats_1ts
block 3  _t41l!!}
```

Concatenated: `isfcr{c0d3_th4t_3ats_1ts_t41l!!}` - "code that eats its tail!!". Verified two ways: all four JIT guard hashes match the stored constants, and the original binary prints `CORRECT`. JIT + `mprotect` + `memcmp` is a code-generation challenge, and generated code almost always has a fixed prologue - free known-plaintext against any `template XOR keystream` scheme.
