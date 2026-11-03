# Ghost in RAM

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{gh0st_pr0c3ss_rng_pwn3d}`

---

**Flag: `hiCTF{gh0st_pr0c3ss_rng_pwn3d}`** (30 bytes)

## Artifact
`ghost-in-ram.zip` → `mem.elf`, **2,164,394,051 bytes**. `file` identifies it as an
**ELF 64-bit LSB core dump, QEMU**; kernel banner inside: `Linux version 7.0.12+kali-cloud-amd64`
(SMP PREEMPT_DYNAMIC). So this is a full QEMU guest memory image, not a LiME/AVML capture.
5 LOAD segments (QEMU physical memory 0 - 0x80000000 plus high RAM).

## Recovering the flag - single-byte-XOR scan
The flag is hidden **obfuscated** (not plaintext), consistent with
*"Something was hiding in there, and it took a secret to the grave."*

Scan the whole image for any single-byte XOR key that turns a 6-byte window into the
plaintext prefix `hiCTF{`. (Efficient O(n) method: the *consecutive-byte XOR signature*
of `hiCTF{` is key-independent - `[0x01, 0x2a, 0x17, 0x12, 0x3d]` - so one pass finds all
candidate windows for every key at once.)

```
$ python3 gir_verify.py
candidates found: 6
  pos=0x21d4073 xor_key=0x00 -> hiCTF{stop_here}. No further steps needed.   <- BAIT
  pos=0x21dc26f xor_key=0x00 -> hiCTF{d3bug_m3}                             <- BAIT
  pos=0x2dcb928 xor_key=0x5a lenfield(16 bytes before)=30
                             -> hiCTF{gh0st_pr0c3ss_rng_pwn3d}
  (a second copy of the same blob sits at 0x3f6f928)
```

Ciphertext at `0x2dcb928`:
`32 33 19 0e 1c 21 3d 32 6a 29 2e 05 2a 28 6a 39 69 29 29 05 28 34 3d 05 2a 2d 34 69 3e 27`
Decode: `flag[i] = ct[i] ^ 0x5a`.

## Two independent verifications
1. **Key derived from the plaintext prefix**: all six bytes of `hiCTF{` agree on key `0x5a`
   (the key-independent consecutive-XOR signature matches the whole 6-byte pattern), and the
   decoded 30 bytes are printable and end in `}`.
2. **Structural oracle**: the `u64` field **16 bytes before** the ciphertext is **30** -
   exactly the decoded flag length, and exactly the size (`0x1e`) of the planted binary's
   `.bss` symbol `flag_obf` (its vaddr-only symtab has no section headers; symbol names sit at
   file offset 758664). Two independent copies of the blob exist in memory and are byte-identical.

## Decoys (do NOT submit)
`hiCTF{stop_here}` ("No further steps needed."), `hiCTF{d3bug_m3}`, and a literal `BAIT` string,
carried inside binaries named `decoy1_logwriter`, `decoy2_thumbd`, `decoy3_confparse`.

## Mechanism
The planted host binary (carved at image offset `0x3ec6838`) is an **LCG ("steady CPU")**
daemon that obfuscates its flag with a **single-byte XOR (0x5a)** and stores it in `.bss`
as `flag_obf` (30 bytes) with `flag_obf_len` alongside - i.e. the hidden process that
"took a secret to the grave", recovered from raw memory without a symbol table for the
2.16 GB image.

## Reproduce
```bash
python3 gir_verify.py            # key-independent signature scan; prints the flag
```
