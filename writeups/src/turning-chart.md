# Turning Chart

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{3v3ry_r0ut3_r3m3mb3rs_1ts_0r1g1n}`

---

## TL;DR

* The prompt asks for a "course"; `?` is a **decoy** - it prints a retired dial
  `4 1 7 0 9 2 5 3 8 6` and exits. The blurb ("kept for the museum, not for navigation")
  is the tell that you should ignore it.
* Input must be exactly **39 bytes**: `isfcr{` + **32** `[a-z0-9_]` chars + `}`. The 32
  inner chars are copied **verbatim** into a 32-byte state array - there is no hashing of
  the input at all.
* A fixed **320-round "needle" state machine** then runs. Crucially, every round's
  parameters (which op, which indices, which operands) come only from a fixed xorshift
  PRNG seeded at `0x73b59a26` and rolling accumulators - **nothing depends on the input
  state**. So the whole program is a *fixed, invertible* sequence of 320 byte-ops.
* The final state is compared against 32 hard-coded bytes at `0x40211c`, XOR-masked by a
  second xorshift stream. Compute the required pre-mask final state, apply the op
  **inverses in reverse order**, and the 32 middle bytes fall straight out.

---

## 1. Recon

```
$ file turning_chart
ELF 64-bit LSB executable, x86-64, statically linked, stripped
$ strings -a -n 4 turning_chart | head
... "Course: " ... "Chart opened. Course restored." ... "Museum dial (retired): 4 1 7 0 9 2 5 3 8 6" ...
```

Running it:

```
$ ./turning_chart
enter course: ?                 # decoy path
Museum dial (retired): 4 1 7 0 9 2 5 3 8 6
```

Disassembly shows the accepted input shape: `strncmp(buf,"isfcr{",6)==0`,
`buf[38]=='}'`, and the 32 bytes `buf[6..38)` are `memcpy`'d into the state array. No
`sha`/hash call touches the input.

## 2. The state machine

Each of the 320 rounds derives, from the PRNG/accumulators only:

* a **selector** `sel` in `0..8` - chosen by indexing a fixed 10-entry dial built from
  `FNV-1a("a chart is a record of motion, not of place")` with PRNG byte #1;
* two state indices `i, j` (forced distinct) from accumulator-only arithmetic;
* an operand byte / shift `ecx` from the PRNG.

The nine ops observed (implemented and matched byte-for-byte in the solver):

| sel | operation |
|----|-----------|
| 0 | rotate an 8-byte window by `(ecx%7)+1` |
| 1 | rotate a 4-byte strided window by `(ecx%3)+1` |
| 2 | swap `s[i], s[j]` |
| 3 | `s[j] = (s[j] + ((ecx + s[i]) & 0xff)) & 0xff` |
| 4 | `s[j] ^= rol8(s[i], ecx)` |
| 5 | `s[j] = P256[(s[j] ^ ecx) & 0xff]` (runtime 256-byte S-box) |
| 6 | `t=s[i]; s[i]=s[j] ^ P256[(ecx + s[j]) & 0xff]; s[j]=t`-style combine |
| 7 | reverse a 4-byte window (`s[base+k] <-> s[base+7-k]`) |
| 8 | no-op at this site |

## 3. Method

1. **gdb**-logged the full 320-round op sequence (`OP r sel i j ecx r9 r14 edx esi`) at the
   dispatch point, plus the runtime 256-byte permutation `P256` and the final PRNG value
   (`EDI = 3162747899`).
2. Reimplemented the 9 ops in Python. Forward pass with an all-`'a'` input reproduced the
   binary's final state **exactly** (`forward match: True`) - the model is correct.
3. Recovered the required pre-XOR final state from the hard-coded target at `0x40211c`
   and the final xorshift stream (`EDI ^ 0xd06f27b5`).
4. Applied each op's inverse over `reversed(ops)` → the 32 middle bytes.

```
num ops 320 rounds 0 319
forward match: True
mid bytes: b'3v3ry_r0ut3_r3m3mb3rs_1ts_0r1g1n'
re-fwd match: True
```

## 4. Proof

```
$ printf 'isfcr{3v3ry_r0ut3_r3m3mb3rs_1ts_0r1g1n}\n' | ./turning_chart
Course: Chart opened. Course restored.
exit=0
```

## 5. Files

* `solve.py` - full forward/inverse emulator + solver (see `solve/`).
* The 32-byte S-box (`p256`) and the 320-round op trace are reproduced by the solver.

## 6. Takeaway

"Every route remembers its origin": the transform is a fixed, data-independent op program,
so it is trivially invertible. The decoy dial and the missing input dependency are the two
traps - the machine is a *bijection*, not a one-way function.

