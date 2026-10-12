# Mirror Garden

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{m1rr0r_g4rden_bl00ms_@t_m1dn1ght_7f3a}`

---

An APK (925 KB) with a near-empty `MainActivity` that calls a single `native` method `bloom(byte[])` in `libgarden.so`, plus 1024 generated Java classes `one/sr/garden/leaf/L0000..L1023`, each with one `verify(byte[]) -> byte[]` method encoding a system of 8 equations over 16 byte-variables (using jadx's decompiled forms of `(a|b)-(a&b) == a^b` and `(x^y)+2(x&y) == x+y`).

**Solving all 1024 leaves:** a small symbolic evaluator textually rewrites each `long jN = ...` line into z3 32-bit BitVector operations, split on `||` for the final equality checks. All 1024 leaves are satisfiable; for each, `bArr2 XOR input[i&15]` yields a 48-byte value. 1023 of them decode to a well-formed `isfcr{<plant>_<hex>}` plus junk bytes - pure decoys. Exactly **one leaf (357)** fails that pattern - "the only leaf that remembers" - so its raw output must be post-processed by native code.

**Reversing `bloom()`:** the tiny native library (`.text` only 0x12b8 bytes) computes a constant leaf index via an internal mixing function that **never reads its input arguments** (emulated in Unicorn, confirmed `index = 0x1ab67d65 & 0x3ff = 357`), calls `one/sr/garden/leaf/L0357.verify()` via JNI reflection, XORs the 48-byte result against an internal state, then runs it through an internal "mirror" transform chain.

**Full emulation instead of hand-reversing the mirror VM:** rather than reimplementing the native transform routines by hand, the entire `bloom()` function is emulated in Unicorn with a **stub JNI environment** (mapped function-pointer table implementing `FindClass`, `GetStaticMethodID`, `CallStaticObjectMethodA`, array accessors, `NewStringUTF`, plus stubbed `snprintf`/`memcpy`), with `CallStaticObjectMethodA` honoured by substituting the precomputed leaf-357 result.

```
FINAL: isfcr{m1rr0r_g4rden_bl00ms_@t_m1dn1ght_7f3a}
```

Negative control: feeding all-zero or arbitrary 16-byte input into the same emulation stops at a length/guard check and returns `the mirror cracks.` - confirming only the true leaf-357 preimage produces the flag.

```
isfcr{m1rr0r_g4rden_bl00ms_@t_m1dn1ght_7f3a}
```

Reusable lessons: a tiny APK whose only logic is one `native` method means the JNI body *is* the challenge - read the function-pointer call sites rather than guessing the (large) JNI index table. 1024 generated classes are just constraint systems, solved per-leaf with z3. Emulating obfuscated native transforms with a stub JNI/libc is faster and exact compared to hand-reversing them, provided a negative control proves the result comes from the intended path.
