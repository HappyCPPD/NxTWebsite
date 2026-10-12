# Oatmeal

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{5958fbb07efd243b}`

---

An imaged device ran an in-house vault app "SilverGate." Two files: `silvergate.apk` (the staging build) and `base.odex` (the device's actual optimized ART OAT file, `ART-OPT/13.0.0-r43`). The apk's `assets/notes.txt` is a planted decoy ("staging flag format… replace before shipping") - the odex is what actually ran on the device and is the file of interest.

**Three compiled methods** live in the odex: `checkFlag_v1_LEGACY`, `checkFlag_v2`, `finalizeFlag`.

`checkFlag_v1_LEGACY` requires 32-byte input and does a straight `memcmp` against a 32-byte constant that is itself a SHA-256 hash - a deliberately unsolvable, one-way dead end (confirmed: no known passphrase from `notes.txt` hashes to it).

`checkFlag_v2` is the real checker - a tiny stack-less bytecode VM requiring 24-byte input. Decoding its 2-bytes-per-instruction program (opcode=hi nibble, dst=lo nibble, operand byte) against three 24-byte constant tables shows the same 9-instruction block repeated 24 times, reducing to one constraint per byte:

```
rol8( ((in[k] + A_k) & 0xff) ^ B_k , 3 ) == C_k
```

directly invertible:

```
in[k] = ( ror8(C_k,3) ^ B_k ) - A_k   (mod 256)
```

giving the 24-byte secret `art_image_took_the_cake!`, forward-verified against all 24 constraints.

`finalizeFlag` is a straightforward FNV-1a-64 over the secret, XORed with a constant:

```
h = 0xcbf29ce484222325
for b in secret: h ^= b; h = (h * 0x100000001b3) & 2**64-1
h ^= 0xa55a96693c3cd2ad
finalizeFlag("art_image_took_the_cake!") = 0x5958fbb07efd243b
=>  isfcr{5958fbb07efd243b}
```

Decoys: two literal self-labelled decoy strings in the odex, a `deriveFlag`-produced "staging" hex blob that `notes.txt` explicitly says to replace before shipping, and the one-way SHA-256 constant from `v1_LEGACY`. Method note: a real device runs the compiled odex, not the marketing APK - when both are present, the odex is authoritative.
