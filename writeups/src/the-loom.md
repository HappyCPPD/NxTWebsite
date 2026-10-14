# The-Loom

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{2nd_0rd3r_r3v_c3ll_aut0m8}`

---

## 1. Triage

```
$ file chall
chall: ELF 64-bit LSB executable, x86-64, ... stripped
$ strings -a chall | grep -iE 'correct|nope|byte'
need exactly %d bytes of input
CORRECT -- the flag is the input you just gave me.
nope.
$ printf 'A%.0s' {1..32} | ./chall
nope.        (exit 1)
$ printf 'abc' | ./chall
need exactly 32 bytes of input   (exit 2)
```

`.text` is only 0x341 bytes - small enough to read by hand. Everything lives in
one function at `0x4003c0` (called from `_start`), plus a tiny helper at
`0x4006c0`.

Imports of interest: `fread`, `memcmp`, `fprintf`, `puts`. No crypto library, no
syscalls - pure integer/bit arithmetic. Good sign: hand-rolled logic is
invertible by inspection.

---

## 2. What the checker does

### 2.1 Read + expand (0x4003c0 .. 0x40044e)

```
fread(rsp, 1, 0x20, stdin)          ; 32 bytes straight into the stack
cmp rax, 0x20 ; jne error           ; else "need exactly 32 bytes"

; zero a 256-byte buffer A at rsp+0x60
movaps [rsp+rdx+0x60..0x90], 0      ; (unrolled x4, eight times => 256 bytes)

; expand the 32 input bytes into 256 bits at rsp+0x160
for i in 0..255:
    byte = input[i >> 3]
    bit  = (byte >> (i & 7)) & 1    ; bt/setb
    B[i] = bit
```

So the state is a **256-bit array**, laid out LSB-first: bit `i` of the state is
bit `i%8` of input byte `i/8`.

### 2.2 The loom: ~1e6 iterations (0x400450 .. 0x4004ec)

```
r10d = 0xf4243                  ; = 1,000,003 outer iterations
rdi = C (rsp+0x260) ; r8 = A (rsp+0x60) ; r9 = B (rsp+0x160)

outer:
  for j = 0 .. 255:             ; rdx = j+1
      p = B[(j-2) & 255]
      q = B[(j-1) & 255]
      r = B[(j+1) & 255]
      s = B[(j+2) & 255]
      t = B[j]
      g = (t&p) ^ (q^r) ^ (q&r) ^ (t&s) ^ (p&s)
      C[j] = (g & 1) ^ A[j]
  r10d -= 1 ; if zero -> done
  ; rotate the three 256-byte buffers: (A,B,C) -> (B,C,A)
  swap(r8,r9,r10=rdi) via rax
  goto outer
```

Two things matter here:

* The update is **nonlinear** (`&` and `|` on bits), so it is not a GF(2)-linear
  sponge you can solve with linear algebra.
* The three buffers rotate as a 3-cycle. Tracking the *contents*, the middle
  buffer evolves as

  ```
  P[n+1] = g(P[n]) ^ P[n-1],     P[0] = bits(input),  P[-1] = 0
  ```

  i.e. an **order-2** (second-order) nonlinear recurrence - a "second-order
  cellular automaton". The name of the flag was the tell.

### 2.3 The verdict (0x40051e .. 0x4005c4)

After the loop, 1,000,002 rotations have happened and `1000002 ≡ 0 (mod 3)`, so
the buffer roles are back to `(A,B,C)`; the final outer iteration therefore wrote
its result into the C slot and left `P[1000002]` sitting in the B slot.

```
pack(rdi=C slot) -> rsp+0x20        ; == P[1000003]
pack(r9 =B slot) -> rsp+0x40        ; == P[1000002]

; first 4 qwords XOR-compared against movabs immediates (copy at .rodata 0x401320)
; then:
memcmp(rsp+0x40, 0x401340, 0x20)
```

`pack` (0x4006c0) is exactly the inverse of the expand step:

```
dst[0..31] = 0
dst[0] = src[0]
for i in 1..255:
    dst[i>>3] |= (src[i] & 1) << (i & 7)
```

So a passing run requires two consecutive states to equal two surfaced
constants:

```
P[1000003] = bits(C1),   C1 = 8096ab410e1e9d3e09ecec59ba2d5cae21a794644c57a1c0d28eee74099c8c5b
P[1000002] = bits(C2),   C2 = 662bd92e7103c809a6ef4e4f8073972e52cbce9ffbd27f756c854d24794a416a
```

---

## 3. The trick: second order ⇒ run it backward

Forward, 1e6 iterations of a nonlinear CA is a wall. But the recurrence is
**order two**, and that is its own inverse:

```
P[n+1] = g(P[n]) ^ P[n-1]     ⇔     P[n-1] = g(P[n]) ^ P[n+1]
```

Given the two consecutive published states (P[1000002], P[1000003]) we can walk
**backward** one step at a time, all the way to P[0], which is the bit-expansion
of the input. 1,000,002 cheap O(256) steps instead of guessing 256 bits.

```c
expand(C1, nxt);   // P[1000003]
expand(C2, cur);   // P[1000002]
for (k = 0; k < 1000002; k++) {
    gfun(cur, prev);                       // prev = g(P[n])
    for (j = 0; j < 256; j++) prev[j] ^= nxt[j];  // prev = g(P[n]) ^ P[n+1] = P[n-1]
    nxt = cur; cur = prev;
}
pack(cur, input);  // P[0] -> 32 bytes
```

`solve.c` is the full program. Output:

```
isfcr{2nd_0rd3r_r3v_c3ll_aut0m8}
input = 69736663727b326e645f30726433725f7233765f63336c6c5f617574306d387d
```

---

## 4. Verification

The recovered bytes are fed straight back into the original binary - the only
oracle that counts:

```
$ gcc -O2 -o solve solve.c && ./solve | head -c 32 | ./chall
CORRECT -- the flag is the input you just gave me.
$ echo "isfcr{2nd_0rd3r_r3v_c3ll_aut0m8}" | ...
```

Confirmed: `isfcr{2nd_0rd3r_r3v_c3ll_aut0m8}` (matches the event's `isfcr{...}`
format, cf. `free-lunch`, `hidden-weights`, `implicit-twins`). The flag string is
coherent English - *"2nd order rev cell autom8"* - so it is the intended answer,
not a coincidental preimage.

---

## 5. Takeaways

* The instruction "hand it 32 bytes, it says nope" plus a *tiny* binary points
  at a checkable predicate, not a game - the fastest path is to invert the
  predicate, not search the input space.
* A nonlinear, high-iteration map is not automatically hard: **state the update
  order**. Order-1 nonlinear maps may be hard to invert; order-2 maps falling out
  of a shift-register/`xor`-with-previous-state construction are reversible given
  two consecutive states. The challenge name (*The Loom*) and the flag (*2nd
  order*) both signpost exactly this.
* Always re-drive the original checker with the candidate - self-consistent
  algebra plus the real binary is airtight evidence.

**FLAG: `isfcr{2nd_0rd3r_r3v_c3ll_aut0m8}`**

