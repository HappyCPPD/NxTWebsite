# Last Execution

**Event:** HICyberCon CTF 2026
**Category:** rev
**Flag:** `hiCTF{3x3c_9_r3m3mb3rs_4ll_but_th3_l4st_h4lt_l13s}`

---

**Category:** rev / custom VM + crypto · **Artifact:** `extracted/last_execution.img` (8,650,752 B, magic `EXE9CORE`)

## What it is
A custom container that holds a *cold image* of a fictional "EXE-9" core, plus a plaintext
operator manual (`PRIMER`, segment 10) that fully specifies the machine. All multi-byte fields
are **big-endian**: header (magic/version/N=24/EXEC_SEED/TABLE_SEED/ENTRY=1/MANUAL=10) then a
24-entry × 0x40 segment table at 0x100 (id, type, offset, size, flags, aux, crc32, name) -
every segment CRC verifies.

Deliberate traps in the manual (the image is a minefield of decoys): the page-rotation seed
rotation is **17**, not the printed 19; the dispatch bias is `pc >> 3`, not `pc >> 4`; the TBL row
recurrence adds `i*13`, not `i*11`. The decoy flag `hiCTF{f4k3_fl4g}` is scattered all over the
image, and the console dump's register file is the *true* final state with a single bit flipped
(R2 bit 12) - that is the "l13" in the flag.

## Solution outline
1. Parse header + segments (big-endian), verify CRCs.
2. Recover page rotations empirically: for each 256-byte page, the only rotation that makes every
   8-byte word's `rd/ra/rb` fields ≤ 15 pins the value uniquely (36 pages recovered, zero miss);
   the closed form `m0 = ROL64(EXEC_SEED ^ (SEG_ID*K), 17)`, `m = ROL64(((m ^ w ^ X)*K), 31)` with
   `K = 0x9E3779B97F4A7C15`, `X = 0xA5A5A5A5A5A5A5A5`, `w` = first u64 of the previous page, fits
   all of them.
3. Emulate: rotating dispatch `idx = (op_byte + (pc>>3) + AUX) mod 256`, chained `HALT`
   (`next_id = imm32 ^ low32(R1)`), writable segments allowing `STW/STB`, `LDRR` reading TBL rows
   with the `rr[i] = (rr[i-1]*17 + stored_row[i-1][0] + 13*i) mod 64` chain.
   Gate: running `EXEC_SELFTEST` standalone reproduces the primer's SHA-256
   commitment `0b6d8d47…bbbcf2` over `be64(R1..R4)` **exactly**.
4. Full chain `EXEC_MAIN -> EXEC_FOLD_A -> EXEC_FOLD_B -> EXEC_LIMIT -> EXEC_FINAL -> EXEC_LIMIT ->
   EXEC_FINAL -> END` - note the console log's "…->EXEC_FINAL" omits LIMIT, and FOLD_B links to
   id 5 (LIMIT), not 4. `EXEC_LIMIT` is a *trap/countdown* (R9 = 0x123456789abc iterations) whose
   loop is periodic; it must be fast-forwarded, not skipped, because it feeds the 2nd EXEC_FINAL
   run. EXEC_FINAL runs twice; the self-modified counter at 0x2048 (written by MAIN via its
   STW into the writable EXEC_FINAL segment) selects the branch, and the 2nd run (R5 == 2)
   terminates with `next_id = 0xFFFFFFFF`. The chain ends with R15 = `0x5354414C`
   ("STAL") and `next_id = 0xFFFFFFFF`; final R1..R4 are the true state.
5. key = SHA-256("LASTEXEC" || be64(R1)||be64(R2)||be64(R3)||be64(R4) || "LASTEXEC");
   S-box from `DLOOK` logical rows 0..3 (Fisher - Yates); undo the 16-byte column rotation on
   `WILL_SEAL`, SEAL-256-decrypt (16 rounds, per-block permutation `P`/inverse), strip PKCS#7.

Cross-check that the crypto path is right: the *console* state decrypts `TEST_SEAL_2` to the decoy
`hiCTF{f4k3_fl4g}`, while the emulated final state decrypts `WILL_SEAL` to the real flag.

Runner: `solve_final.py` (also `solve3.py`). Output:

```
R15 = 0x000000005354414C
fold0(xor) = 0xF823B4260904B088     fold1(add) = 0x782AB6EF390CF07A
key = ac35ec6ed245d7238d9784ae097766613649315beb12b8ba9836dda56ccd54a3
WILL_SEAL plaintext : b'hiCTF{3x3c_9_r3m3mb3rs_4ll_but_th3_l4st_h4lt_l13s}'
TEST_SEAL_2 (console state) : b'hiCTF{f4k3_fl4g}'
```

## Flag
```
hiCTF{3x3c_9_r3m3mb3rs_4ll_but_th3_l4st_h4lt_l13s}
```
