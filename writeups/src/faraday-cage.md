# Faraday Cage

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{p3rmut3d_h4ndl3rs_v5_cust0m_ch4ch4_1n_th3_c4g3}`

---

**Unlock key (16-byte challenge response):** `LumosFaradCage01`

A 42 KB APK (`com.lumos.faraday`) whose Java layer collects 32 hex chars and calls `native byte[] BulbNative.submit(byte[])`. All real logic is in `libbulb.so` (arm64-v8a).

**Locating native `submit`:** `JNI_OnLoad`'s `RegisterNatives` call points `"submit"`/`"([B)[B"` at a thin JNI glue function that calls one core routine, `fcn.000043dc`.

**The checker is a bytecode VM:** `fcn.000043dc` branches on a global flag (`1` = accepted "dev" path) after running a VM whose context is built from a 96-byte `.rodata` blob and a 0xf0-byte bytecode program. The dispatch table of 48 handlers is built **at runtime**: decrypting a 104-byte rodata blob, XORing against a 6-byte pool, applying a Fisher-Yates shuffle, then mapping shuffled indices through a pointer table - a deliberately obfuscated indirection. A nearby rodata string is the giveaway: *"ERRATA L7-003: handler index equals opcode byte for engineering builds. Rebind map is bypassed when LUMOS_DEV=1."*

**Decoding the VM:** the 48 handlers implement a small RISC ISA - registers, byte-addressable scratch memory, arithmetic/bitwise ops, an S-box/InvSbox op, a GF(2⁸) `gmul` helper (polynomial `0x11d`), a 32-bit matrix-op helper, a stack, and conditional jumps. Reimplementing the whole ISA in Python and validating it byte-for-byte against Unicorn emulation of the real `.so` confirms correctness.

Decoding the 60-instruction bytecode reveals 4 rounds of a **custom AES-variant cipher**: SubBytes with a fixed byte permutation stepping by 5, a custom MixColumns matrix `M = [[2,3,5,1],[1,2,3,5],[5,1,2,3],[3,5,1,2]]` (the 5s and step-by-5 permutation indices are the flag's "permuted handlers"/"ch4ch4" hint), and AddRoundKey with 4 round keys extracted from the 96-byte blob - the final state must equal a 16-byte device key.

**Inverting:** since every layer is invertible, un-run the 4 rounds from the target (device key) backward: un-AddRoundKey → un-MixColumns (using the inverse matrix) → un-permute + InvSbox.

```
input = 4c756d6f734661726164436167653031 = "LumosFaradCage01"
```

Feeding this back through the reference VM gives `result == 1`; the accepted branch then builds and returns the flag.

```
submit() returned: 1   payload length: 53
FLAG: isfcr{p3rmut3d_h4ndl3rs_v5_cust0m_ch4ch4_1n_th3_c4g3}
```

Verification: pure-Python inversion and full ARM64 Unicorn emulation independently agree; all-zero/random/off-by-one keys are rejected; a literal decoy string `isfcr{nope_this_is_a_decoy_please_move_on}` is present but never returned.
