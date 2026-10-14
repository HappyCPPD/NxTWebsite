# Faraday Cage

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{p3rmut3d_h4ndl3rs_v5_cust0m_ch4ch4_1n_th3_c4g3}`

---

**Unlock key (16-byte challenge response):** `LumosFaradCage01`
**Category:** reverse engineering (Android + native ARM64)

## 1. Recon
`Faraday.apk` (42 KB) - manifest package `com.lumos.faraday`, single activity.
Decompiling `classes.dex` with jadx shows almost no logic: the UI collects 32 hex
chars (16 bytes), requires **PAIR** first, then calls:

```java
public final class BulbNative { public static native byte[] submit(byte[] b); ... }
```
`submit(...)==null||length==0` → "unlock rejected"; otherwise the return value is
printed as a GATT notification (0xA008). So all the real work is native.

Two native libs ship: `libbulb.so` for `arm64-v8a` and `armeabi-v7a` (stripped, NDK r26c).
We worked the arm64 one.

## 2. Locating native `submit`
`readelf` shows only `JNI_OnLoad` exported. Disassembling `JNI_OnLoad` shows a
`RegisterNatives` call whose `JNINativeMethod` table lives at `0x6938` (RELATIVE relocs):
name→`"submit"`, sig→`"([B)[B"`, fn→**`0x54c8`**.

`0x54c8` is thin JNI glue: `GetArrayLength`, `GetByteArrayElements`, one core call
`fcn.000043dc(ptr, len, out, 0x80, &outlen)`, `ReleaseByteArrayElements`, and on non-zero
result `NewByteArray(outlen)` + `SetByteArrayRegion(out)`. So **`fcn.000043dc` is the checker**.

## 3. The checker is a bytecode VM
`fcn.000043dc` first calls `0x4470` then `0x4504`, then branches on a global at
`ctx+0x348`:

```
w8 = global[ctx+0x348]
if (w8 == 1) { out = derive(input); return 1 }     // "dev"/accepted path (0x45bc)
else         { *outlen = 0; return 0 }             // rejected
```

`0x4470` builds a VM context at `.bss` `0x7b10`: zeroes 0x360 bytes, copies a **96-byte
blob** from rodata `0x132a` to `ctx+0x50`, records the bytecode pointer `0x138a`/len `0xf0`,
and copies the 16-byte input to `ctx+0x248`.

`0x4504` is the dispatch loop: `op = bytecode[pc]`; `handler = table[op]`;
`handler(ctx, bc[pc+1], bc[pc+2], bc[pc+3])` returns the next `pc`; it halts when
`ctx+0x34c != 0` or `op > 0x2f`. The handler **table is built at runtime** by `0x5058`
(zero-init flag at `ctx+0x370`): it seeds a 48-byte permutation by decrypting a 104-byte
rodata blob at `0x1322`, XORing with a 6-byte pool, applying a helper, then a Fisher - Yates
shuffle, and finally maps shuffled indices through a 48-entry pointer table in
`.data.rel.ro` `0x67b8` into `ctx+0x368` (`0x7e78`). It also builds an inverse-S-box at
`0x7ff8` from the AES S-box at `0x147a`.

The `.rodata` holds the tell-tale `ERRATA L7-003: handler index equals opcode byte for
engineering builds. Rebind map is bypassed when LUMOS_DEV=1.` - the rebind map is exactly
that shuffled handler table.

## 4. Decoding the VM
The 48 handlers (at `0x4624…0x5058`) are a small RISC ISA operating on `ctx`:
32-bit registers `reg[i] = ctx[4i]`, a byte-addressable scratch array `mem[j] = ctx[0x40+j]`,
plus add/sub/mul/and/or/xor/shl/lsr/ror, immediates, byte/dword loads-stores, an
`Sbox`/`InvSbox` op, `gmul` (via helper `0x51b8` = **GF(2^8) multiply, polynomial 0x11d**),
a 32-bit matrix-op (helper `0x52c0`), a stack (`push`/`pop`/`call`/`ret`), and six
conditional jumps. Two terminals: `halt` and `set-result-and-halt`.

We reimplemented the whole ISA in Python (`solve/vm.py`) and validated it byte-for-byte
against Unicorn running the real `.so` (identical final `mem[0..15]` and result).

Decoding the 60-instruction bytecode yields the program:

```
mem[0..15] = input
repeat 4 rounds:                        # round r
    mem[i] = sbox(mem[perm[i]])         # SubBytes + a fixed byte permutation
    for w in 0..3: mem[4w..4w+3] = M * mem[4w..4w+3]   # custom MixColumns (GF(2^8))
    mem[i] ^= roundkey[r][i]            # AddRoundKey
# check: mem[0..15] must equal the 16-byte device key at mem[0x10..0x1f]
```

Where (all read from the 96-byte blob `0x132a`):
- **device key** = `f809792ec246f0098538517c71c64461`
- **round keys** = `ObjectSpacePrime`, `FaradayCageBuri`, `nLumosLEDBulbFl`, `asshTheFlagIsIn`
- **permutation** = `[0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11]`
- **MixColumns matrix** `M = [[2,3,5,1],[1,2,3,5],[5,1,2,3],[3,5,1,2]]` (note the 5s and the
  fact perm indices step by 5 - hence the flag's `p3rmut3d_h4ndl3rs` / `ch4ch4`.)

## 5. Inverting the cipher
Because every layer is invertible, we un-run 4 rounds from the target (= device key):
`un-AddRoundKey` → `un-MixColumns` (with `M⁻¹ = [[229,255,166,27],[27,229,255,166],
[166,27,229,255],[255,166,27,229]]`) → `un-permute` + `InvSbox`. Result:

```
input = 4c756d6f734661726164436167653031 = "LumosFaradCage01"
```

Feeding that back into the reference VM gives `result == 1`.

## 6. Getting the flag
With `result == 1`, `fcn.000043dc` takes the accepted branch and calls `0x45bc(input)`,
which builds a 53-byte string and copies it to the output buffer. Running the real native
code end-to-end in Unicorn (`solve/unlock_emulate.py`) returns exactly:

```
submit() returned: 1   payload length: 53
FLAG: isfcr{p3rmut3d_h4ndl3rs_v5_cust0m_ch4ch4_1n_th3_c4g3}
```

## 7. Verification / pitfalls
- **Independent paths agree:** pure-Python inversion and full ARM64 emulation both give the
  same key and flag.
- **Negative controls:** all-zero, random, and off-by-one keys are rejected (`w0=0`,
  `outlen=0`). Only the exact 16 bytes unlock - confirming the cipher comparison is real.
- **Decoys:** the string `isfcr{nope_this_is_a_decoy_please_move_on}` is present but never
  returned by `submit`.
- **Emulator gotcha that cost time:** the VM's `.bss` spans `0x7b10–0x80f8`; an I/O scratch
  buffer placed at `0x8000` was silently zeroed by the context reset (and RELATIVE relocs
  in `.data.rel.ro` are zero in the file - they must be applied before the handler table
  is meaningful). Both are noted for reuse.

