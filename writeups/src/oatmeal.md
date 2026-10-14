# Oatmeal

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{5958fbb07efd243b}`

---

## Challenge
> A device belonging to a person of interest was imaged last week. It was running
> an in-house vault app called SilverGate. Two files came back from the image.
> See what you can pull out of them.
> Attachment: `silvergate.apk`, `base.odex`. Flag format: `isfcr{...}`.

Two artifacts:
- `silvergate.apk` - the **staging** build (`com.silvergate.vault`, `classes.dex`,
  compiler metadata `"version":"8.2.2-dev"`).
- `base.odex` - the **optimized (real) app code** for the device, an ART OAT file
  (`oat\n243`, `ART-OPT/13.0.0-r43`, `art.compiler.filter=speed-profile`, tag
  `ARM64-A75-v4.3`). The odex is the file of interest: it is what actually ran.

The apk's `assets/notes.txt` is a planted in-fiction artefact that both hints and
misleads ("staging flag format … replace before shipping", "SHA256 constant …
derived from the lowercased passphrase", two strings `isfcr{` / `oatmeal` labelled
"known-benign"). Treat it as narrative, not ground truth.

## Structure of `base.odex`
```
0x000  OatHeader + key/value store
0x180  3 x 24-byte constant tables (T0,T1,T2)  <- bytecode VM keystream sources
0x1c8  32-byte EXPECTED = 42b39944397bbbe271c695b40844f3f41c3a2b5a8d1c0400ce733878dbc44bb2
0x1e8  "isfcr{%016llx}\0"                       <- THE REAL FLAG TEMPLATE
0x1ff  "[dbg] checkFlag_v2 entered: %d bytes\n"
0x221  "isfcr{dev_overlay_do_not_submit_18ca3b}"   <- decoy
0x245  "isfcr{preprod_token_v3_40df11a0ce9c}"      <- decoy
0x290  bytecode program for checkFlag_v2 (0x212 bytes)
0x4b0  LockActivity.checkFlag_v2        (ARM64, bytecode interpreter)
0x7e0  LockActivity.checkFlag_v1_LEGACY (ARM64)
0x820  LockActivity.finalizeFlag        (ARM64)
0x890  4096-byte blob beginning "dex\n035" with an encrypted body
0x1890 "compiled by art-opt v13.0.0-r43 (sr) do not distribute"
```
The odex names exactly three methods: `checkFlag_v1_LEGACY`, `checkFlag_v2`,
`finalizeFlag`.

## The three compiled methods

### `checkFlag_v1_LEGACY` @0x7e0 - decoy / dead end
Requires input length `0x20` (32) and does a straight `memcmp(input, EXPECTED)`
against the 32-byte SHA-256 constant at 0x1c8. Since EXPECTED is a SHA-256 hash,
this path is one-way - deliberately unsolvable. (And `sha256("art_image_took_the_cake!")`
≠ EXPECTED, confirming EXPECTED belongs to a *different*, unrecoverable "staging"
passphrase named in `notes.txt`.)

### `checkFlag_v2` @0x4b0 - the real checker (a tiny stack-less bytecode VM)
Requires input length `0x18` (24). It walks the bytecode at 0x290, 2 bytes per
instruction: `op = hi nibble`, `dst = lo nibble`, plus one operand byte.

| op | handler | semantics |
|----|---------|-----------|
| 1 | `ldrb w12,[x27,op]` | `r[dst] = input[op]` |
| 2 | const from T0 | `r[dst] = T0[op] ^ ((op*0xa7)^0x5c & 0xff)` |
| 3 | const from T1 | `r[dst] = T1[op] ^ (((op+0x18)*0xa7)^0x5c & 0xff)` |
| 4 | const from T2 | `r[dst] = T2[op] ^ (((op+0x30)*0xa7)^0x5c & 0xff)` |
| 5 | `mov w12,w11` | `r[dst] = imm(op)` |
| 6 | `add` | `r[dst] = r[dst] + r[op]` |
| 7 | `eor` | `r[dst] = r[dst] ^ r[op]` |
| 8 | `lsl/lsr` | `r[dst] = rol8(r[dst], op & 7)` |
| 9 | `cmp`+`b.ne fail` | **assert `r[dst] == r[op]`** |
| a | `mov w0,#1; ret` | return true |

The program runs 24 identical blocks `(MOVI/XOR into r7 — dead), LD r0=in[k],
LDC0 r1=A, ADD, LDC1 r1=B, XOR, ROL 3, LDC2 r1=C, CMPEQ`. So for each of the 24
bytes the constraint is

```
rol8( ((in[k] + A_k) & 0xff) ^ B_k , 3 ) == C_k
```

Invert:

```
in[k] = ( ror8(C_k,3) ^ B_k ) - A_k   (mod 256)
```

Result: **`art_image_took_the_cake!`** (24 bytes). All 24 constraints
forward-verify (`solve.py`).

### `finalizeFlag` @0x820 - the flag producer
```
h = 0xcbf29ce484222325            ; FNV-1a-64 offset basis
for b in input[0:24]:
    h ^= b
    h  = (h * 0x100000001b3) & 2**64-1   ; FNV prime
h ^= 0xa55a96693c3cd2ad           ; movk-built constant
return h
```
Called with the 24-byte secret. (It also loads `x4 = 0x1e8` but never uses it -
that address is exactly the `"isfcr{%016llx}"` string, the author's fingerprint
that finalizeFlag's uint64 is formatted by that template.)

## Flag
```
finalizeFlag("art_image_took_the_cake!")
  = fnv1a64(...) ^ 0xa55a96693c3cd2ad
  = 0x5958fbb07efd243b
=>  isfcr{5958fbb07efd243b}
```

## Decoys (do not submit)
| value | origin |
|-------|--------|
| `isfcr{dev_overlay_do_not_submit_18ca3b}` | literal, self-labelled decoy in odex |
| `isfcr{preprod_token_v3_40df11a0ce9c}` | literal, self-labelled decoy in odex |
| `isfcr{3427210a3c383432300a213a3a3e0a213d300a36343e3074}` | `LockActivity.deriveFlag` of the secret - the **staging** format the apk ships and `notes.txt` says to replace |
| `42b399…44bb2` (SHA-256) | `v1_LEGACY` constant, one-way |

## Reproduce
```
python3 solve.py          # -> "FLAG: isfcr{5958fbb07efd243b}"
```
Pure stdlib; parses the tables/program straight out of `base.odex`.

## Method notes
- `silvergate.apk` is the marketing/staging build; the **odex is authoritative**.
  A real device runs the compiled odex, and the odex's embedded dex body is
  encrypted (`dex\n035` magic in the clear, body high-entropy) - the real
  `LockActivity` lives behind it. The three compiled methods are enough to solve:
  one dead-end hash check, one invertible VM, one flag finaliser.
- The planted `notes.txt` steers you to `deriveFlag`/`EXPECTED` (both decoys).
- ARM64 via capstone; the VM program was decoded by hand from its interpreter.

