# OUROBOROS

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{c0d3_th4t_3ats_1ts_t41l!!}`

---

## 1. Triage

```
$ file chall
chall: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
$ printf 'A%.0s' {1..32} | ./chall ; echo $?
nope.
1
```

`strings`/imports give the whole story:

```
/lib64/ld-linux-x86-64.so.2   stdin  fread  mmap  mprotect  memcmp  puts  sysconf
need exactly %d bytes of input
nope.
CORRECT
```

`mmap` + `mprotect` + `memcmp` is the classic **JIT** fingerprint: the program
manufactures machine code at runtime, makes it executable, runs it, and then
`memcmp`s a buffer. There is no flag string in the binary - nothing to grep.

---

## 2. What the checker does

`.text` is tiny (0x4a6 bytes). The whole checker lives at `0x400400`.

### 2.1 Read + scratch buffer

```
fread(rsp+0x20, 1, 0x20, stdin)      ; 32 input bytes
cmp rax, 0x20 ; jne "need exactly 32 bytes"

; keep a copy of the input as the working buffer, reachable by the JIT code
movaps [rsp+0x40], input[0:16]       ; rdi for every generated call = rsp+0x40
movaps [rsp+0x50], input[16:32]
```

### 2.2 Four JIT blocks (0x4004dc .. 0x400704)

`sysconf(_SC_PAGESIZE)` sizes an anonymous RWX page (via `mmap`, prot=3). Then a
loop runs four times, `rbx = 0..3`. Each iteration:

1. packs `input[8*rbx : 8*rbx+8]` into a 64-bit `word`;
2. computes `seed = word ^ state` (state starts at `0x1f0d1e5cafeb00b5`, r9);
3. **synthesises a function** into the mmap page:

   ```
   for i in 0 .. len[b]-1:
       g   = i / 8
       V   = splitmix64( seed + (g+1)*GOLDEN )      # GOLDEN = 0x9e3779b97f4a7c15
       code[i] = TEMPLATE[b][i] ^ byte_{i%8}(V)      # byte-lane of V
   ```

   So the generated code is `template[b] XOR keystream(seed)`. The keystream is a
   splitmix64 stream whose mix inputs are an arithmetic progression `seed+2G,
   seed+3G, …`;
4. **guards** the code with a splitmix chain hash:

   ```
   h = 0xc0ffeebadc0de5
   for c in code: h = mix( (c ^ h) + GOLDEN )        # mix = splitmix64 finalizer
   assert h == E[b]                                   # else "nope."
   ```

5. `mprotect(page, RX)`, `call page` with `rdi = rsp+0x40` (the working buffer),
6. updates `state = chain_hash(code, state)` - **the code feeds the next block's
   key**. Hence *Ouroboros*: each block eats the previous block's tail. This is
   the "self-reference" the name points at.

After all four blocks:

```
memcmp(rsp+0x40, 0x401380, 0x20)     ; buffer must equal the 32-byte target
```

Table locations in `.rodata`:

| b | template ptr | len | guard target E[b] |
|---|---|---|---|
| 0 | 0x401520 | 85 | 0xb82e45fb0800fccb |
| 1 | 0x4014c0 | 93 | 0x1ac4e085b6b2582a |
| 2 | 0x401460 | 96 | 0x6d0da43dd8bb68ea |
| 3 | 0x401400 | 85 | 0x375dcfb81ce4e98e |

The memcmp target (`.rodata 0x401380`) is
`61fe0ffd8b2d62e9b00fa3299ef2c8b631edefb71365e23fb53f744312821488`.

---

## 3. Why the guard looks unbreakable (and isn't)

The guard is a 64-bit preimage: for a random word the chain hash matches `E[b]`
with probability 2⁻⁶⁴, and the unknown word is 64 bits. So there is exactly one
word per block, and brute force is 2⁶⁴ per block - infeasible.

**The way in is the opposite direction: recover the CODE, not the word.** The
generated code is a normal compiled C function, and all four functions share the
same prologue. Recover the code and the keystream falls out, which gives the
word directly.

### 3.1 Known-plaintext on the JIT

Because `code = template XOR keystream`, and the first 8 bytes of every generated
function are the fixed prologue

```
f3 0f 1e fa 55 48 89 e5      endbr64 ; push rbp ; mov rbp,rsp
```

we know keystream **group 0**:

```
K0 = code[0:8] XOR template[b][0:8]
V0 = int_le(K0)
seed = mixinv(V0) - GOLDEN
```

`mix` is the splitmix64 finalizer - a bijection - so `mixinv` is exact. From
`seed` the *entire* keystream follows (`V_g = mix(seed + (g+1)*GOLDEN)`), hence
the *entire* generated program, hence

```
word[b] = seed ^ state
```

No search at all. `state` is carried across blocks exactly as the binary does:
`state = chain_hash(code, state)`. Run this for b = 0..3 and the four words spell
the flag. Every recovered block's chain hash matches its stored `E[b]`, which is
independent proof the recovery is exact.

---

## 4. The four generated programs

Disassembling the recovered code (all share prologue/epilogue and loop `i<32`)
gives a clean four-stage byte transform of the 32-byte buffer `B`:

| b | len | operation |
|---|---|---|
| 0 | 85 | `B[i] ^= (7*(i-13)) & 0xff` |
| 1 | 93 | `B[i]  = (B[i] + B[(i+1) & 31]) & 0xff`  (in-place, forward) |
| 2 | 96 | `B[i]  = rotl8(B[i], 3)` |
| 3 | 85 | `B[i] ^= (31*i + 0x3c) & 0xff` |

Applying these four in order to the flag reproduces the `.rodata` target byte
for byte:

```
input = isfcr{c0d3_th4t_3ats_1ts_t41l!!}
final = 61fe0ffd8b2d62e9b00fa3299ef2c8b631edefb71365e23fb53f744312821488  <-- == target
```

So the acceptance condition is fully explained: the JIT blocks perform a fixed
invertible byte mixing of the input, and the flag is the input whose mixing lands
on the stored 32-byte constant.

---

## 5. The flag

```
block 0  isfcr{c0
block 1  d3_th4t_
block 2  3ats_1ts
block 3  _t41l!!}
```

Concatenated: `isfcr{c0d3_th4t_3ats_1ts_t41l!!}` - leetspeak for
*"code that eats its tail!!"* - which is precisely an **ouroboros**, and exactly
what the program does: the generated code's hash seeds the next block's code
generator.

---

## 6. Verification (the only oracle that counts)

```
$ python3 solve.py
recovered 32 bytes : b'isfcr{c0d3_th4t_3ats_1ts_t41l!!}'
flag               : isfcr{c0d3_th4t_3ats_1ts_t41l!!}
...
binary says        : CORRECT (exit 0)

$ printf 'isfcr{c0d3_th4t_3ats_1ts_t41l!!}' | ./chall
CORRECT
```

Two independent confirmations: (a) all four JIT guard hashes match the stored
constants, and (b) the original binary prints `CORRECT`.

---

## 7. Takeaways

* **JIT + `mprotect` + `memcmp` is a code-generation challenge, and the generated
  code almost always has a fixed prologue.** That prologue is free known-plaintext
  against any `template XOR keystream` scheme. Recover the keystream, and the
  "key" (`seed`) - and therefore the input word - falls out with no search.
* The scary 2⁻⁶⁴ hash guard is defence *in the wrong direction*: it stops you
  guessing the word, but the word is derivable from the code, so the guard is
  never brute-forced at all.
* Keep the recovered semantics as a second, independent check: replaying the four
  byte transforms reproduces the `.rodata` `memcmp` constant exactly.

**FLAG: `isfcr{c0d3_th4t_3ats_1ts_t41l!!}`**

