# Night Batch

**Event:** HICyberCon CTF 2026
**Category:** rev
**Flag:** `hiCTF{c0b0l_p4ck3d_d3c1mal_n1ghtly_b4tch!}`

---

**Category:** rev / COBOL · **Artifact:** `extracted/night-batch` (Linux x86-64 ELF, stripped, GnuCOBOL runtime)

## Flag
```
hiCTF{c0b0l_p4ck3d_d3c1mal_n1ghtly_b4tch!}
```
Account key: `481702596318740925` (18 digits). Verified: `./night-batch 481702596318740925` prints the
flag; the neighbouring keys and the other congruent candidate are rejected ("account rejected").

## What it is
A GnuCOBOL binary (`core.libcob` module descriptors, `cob_move_display_to_edited`, `EC-*` codes).
Usage `./night-batch <account-key>`. The author obfuscated *their own* literals with **XOR 0x5A**
(`account rejected` exists only as `d[0x4d0a0] ^ 0x5A`); everything else in the file is plaintext
libcob runtime text. The 835-digit decimal constant next to "end of program, please press a key to
exit" is not a modulus - it is the decimal expansion of **ln(2)** (filler/decoy; all its slices and
reversals are rejected as keys).

## Validation, part 1 - 23 digit conditions (this is what needed solving)
The key must be exactly 18 characters (`if (DAT_00460130 == 0x12)`), read into the COBOL field at
`0x460140` (space-padded). The COBOL program then runs a nested ladder of 23 conditions; each ends
with `FUN_00413920(&DAT_0045e360, N)` which returns 0 iff the computed value equals `N`. Call sites:
`0x400d93, 0x400e88, 0x40105c, 0x401132, 0x401291, 0x401405, 0x40152d, 0x401706, 0x4017d1,
0x40189b, 0x401965, 0x401a2b, 0x401af0, 0x401c89, 0x401d8a, 0x401e50, 0x401f9a, 0x4020a1,
0x4021eb, 0x4022bb, 0x402357, 0x40241d, 0x4025b6`. Targets in order:
`8, 3, 1, 7, 7, 7, 9, 2, 7, 6, 2, 3, 2, 2, 5, 5, 1, 9, 4, 4, 4, 0, 94`.

Empirically (see method below) 21 of the 23 conditions are **linear combinations of the 18 digits
taken mod 10** (the last one mod 100, target 94 - a weighted digit sum), and two of them (the 1st
and the 21st) contain a **product** of two digits. Examples of the reconstructed conditions
(d = the key's digit array, 0-based):

```
c1 :  d1*d10                        ≡ 8
c2 :  d8 + d4 + d3                  ≡ 3
...
c23:  9*d16 + 2*d15 + 5*d10 + 5*d6 + 4*d3  ≡ 94   (mod 100)
```

The 17-entry pointer table at `0x44cf00` resolves to `0x460100 + {0a,01,03,08,04,06,05,02,11,07,
09,0b,0c,0d,0f,10,0e}` - a permutation of the key's digit offsets (the derived field holds each digit
as `digit<<4 | 0xF`); the numeric literal descriptors are `0x44cdb0=2, 0x44cdd0=3, 0x44ce10=1,
0x44cdf0=10, 0x44cd30=100, 0x44cd50=9, 0x44cd70=5, 0x44cd90=4`. With the two product conditions
included the system has exactly one solution.

## Validation, part 2 - the 42-byte reveal (proven byte-for-byte)
Once all 23 conditions pass, control reaches `0x400b86 → FUN_00402f40`, which:
```
seed      = SHA-256(key18)                       # 0x402f79 (rdi=key, esi=0x12)
for c = 0,1,…:  ks = SHA-256(seed ‖ BE32(c))     # BE because of `bswap eax` at 0x402fb2
out[i]    = TABLE[0x44d0c0 + i] XOR ks[i]        # 42 bytes
success  ⟺ SHA-256(out) == 2c146846b66a3fbd181654efa527e4886dbc8ff6323aeadbb0a680efaef6a08f
on success: fwrite(out, 1, 42, stdout) + '\n'    # 0x4030c4
```
`0x4027e0` is plain SHA-256 (0x80 padding, 64-byte blocks, 64-bit length).

## How it was solved
1. `FUN_00413920` converts the computed field (`FUN_0040fe00`) and compares to `N`. Patching it to
   always report "equal" (`0x4139a3: jl → NOP NOP`, `0x4139a5: setg al → xor eax,eax`) makes the
   ladder run all 23 conditions, so the reveal path becomes reachable *and* observable.
2. With a gdb breakpoint at `0x41399e` (right after the numeric conversion) the probe prints
   `(COND, N)` for each condition - i.e. the *computed value*, not just pass/fail.
3. Probe with the all-zero key (all CONDs 0) and with each single-digit perturbation `d_j = 1`:
   the difference matrix is exactly each condition's coefficient on digit `j`. Confirmed the model
   by predicting a random key's values: **all conditions matched once taken mod 10** (and mod 100
   for the last), apart from the two product-type conditions.
4. Solve the 22 congruences (18 unknowns in 0..9) with z3, enumerate the few solutions, and test each
   by simply running the binary - the first congruent candidate `431702596318740925` is rejected
   (fails a product condition), the second `481702596318740925` prints the flag.

Runnable artifacts: `nb_probe2` (patched oracle binary, created from `night-batch`), the gdb probe
harness, and the coefficient/solve scripts recorded in the ledger. The original `night-batch` is
untouched.
