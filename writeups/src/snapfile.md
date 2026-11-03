# Snapfile

**Event:** HICyberCon CTF 2026
**Category:** rev
**Flag:** `hiCTF{r3c0nstruct3d_th3_sn4pf1l3_by73_by_by73}`

---

**Flag:** `hiCTF{r3c0nstruct3d_th3_sn4pf1l3_by73_by_by73}`

## Summary

`snaptool` (stripped Crystal x86-64 ELF) validates a 104-byte (0x68) `.snap`
header, verifies a custom 64-bit checksum, and - on success - prints the
snapshot's embedded label, which is the flag. No sample `.snap` ships with the
challenge, so the format had to be reconstructed from the binary alone.

The whole validator lives inside the (inlined) user `main` at `0x400d50`
(entry `0x42e8e0` → `0x43a749` → user main). The interesting block is
`0x402c26` - `0x4032b8`. Any failing check jumps to `0x4035e4`, which prints
`invalid snapfile` and exits 1.

## `.snap` file layout (104 bytes)

| Offset | Size | Meaning | Required value |
|-------:|-----:|---------|----------------|
| 0x00 | 4 | magic | `SNAP` (`53 4E 41 50`) |
| 0x04 | 2 | version, **big-endian** u16 (read as `rol ax,8`) | `0x0002` |
| 0x06 | 1 | format flags | `0x03` |
| 0x07 | 1 | reserved | `0x00` |
| 0x08 | 8 | format tag, ASCII | `SNAP-LNG` |
| 0x10 | 4 | **BE** u32 section A offset | `0x28` |
| 0x14 | 4 | **BE** u32 section A length | `0x10` (16) |
| 0x18 | 4 | **BE** u32 section B offset | `0x38` |
| 0x1c | 4 | **BE** u32 section B length | `0x20` (32) |
| 0x20 | 4 | **BE** u32 section C offset | `0x58` |
| 0x24 | 4 | **BE** u32 section C length | `0x08` (8) |
| 0x28 | 16 | section A payload | (free) |
| 0x38 | 32 | section B payload | (free) |
| 0x58 | 8 | section C payload | (free) |
| 0x60 | 8 | **checksum**, big-endian u64 | computed |

Structural consistency checks enforced by the binary:

* total length `== 0x68`
* `A.off + A.len == B.off` (0x28+0x10 = 0x38)
* `B.off + B.len == C.off` (0x38+0x20 = 0x58)
* `C.off + C.len == 0x60` (0x58+0x08 = 0x60)
* the six u32 fields at 0x10/0x14/0x18/0x1c/0x20/0x24 are read through a
  big-endian accessor `FUN_00438800(buf,len,offset)` (with bounds/overflow
  guards).

### Checksum algorithm (``0x402dbb`` - ``0x402e4b``)

A 64-bit rolling hash over header bytes **0x08..0x5F** (88 bytes), FNV-ish with
a xor-shift finalizer:

```python
MASK = (1 << 64) - 1
h = 0x1357bdf02468ace1
for i in range(0x08, 0x60):          # 88 bytes
    h = ((h + header[i]) * 0xd1b54a32d192ed03) & MASK
    h ^= h >> 29
# stored field = little-endian-friendly: written BIG-ENDIAN at 0x60
checksum = (h ^ 0x58) & MASK
```

The final check is `(BE_u64(header[0x60:0x68]) ^ hash) == 0x58`, i.e. the
8-byte field is `hash ^ 0x58` stored big-endian.

### Label / flag decoding

On success the tool runs a second stage (`0x402e66` - `0x4032b8`):

1. `FUN_00438890(0x28, …, buf)` computes `SHA256(header[0x00:0x28])`.
2. A 46-byte label is reconstructed in a fresh buffer:
   `label[i] = key[i] ^ ciphertext[i]` (`xorps`/`xorpd` bulk-copy loop at
   `0x403200`), where the two operand tables are Crystal globals materialised at
   startup (pointers in `.bss` at `0x48eb90` / ciphertext buffer).
3. The decoded label is re-hashed with SHA256 and compared (`bcmp` at
   `0x403290`) against an embedded constant; then a single
   `write(1, label, 47)` (`0x4032b3` → `0x433d40`) prints it.

The label is a fixed constant (it does **not** depend on the section payloads),
verified by running with all-zero sections and with random sections - both
produce the same flag. The header SHA-256 is used only inside this stage.

## Reconstructing a valid file

`mk.py` in this folder builds a byte-exact valid `.snap` (`solution.snap`):

```python
import struct
MASK=(1<<64)-1; MULT=0xd1b54a32d192ed03
def checksum(hdr):
    h=0x1357bdf02468ace1
    for i in range(8,0x60):
        h=((hdr[i]+h)*MULT)&MASK; h^=h>>0x1d
    return (h^0x58)&MASK
h=bytearray(0x68)
h[0:4]=b'SNAP'; h[4:6]=struct.pack('>H',2); h[6]=3; h[7]=0
h[8:16]=b'SNAP-LNG'
for off,val in [(0x10,0x28),(0x14,0x10),(0x18,0x38),(0x1c,0x20),(0x20,0x58),(0x24,0x08)]:
    struct.pack_into('>I',h,off,val)
struct.pack_into('>Q',h,0x60,checksum(h))
open('solution.snap','wb').write(h)
```

## Proof of success

```
$ ./snaptool solution.snap
hiCTF{r3c0nstruct3d_th3_sn4pf1l3_by73_by_by73}
exit=0
```

Hex dump of `solution.snap` (104 bytes):

```
00000000: 534e 4150 0002 0300 534e 4150 2d4c 4e47  SNAP....SNAP-LNG
00000010: 0000 0028 0000 0010 0000 0038 0000 0020  ...(.......8...
00000020: 0000 0058 0000 0008 0000 0000 0000 0000  ...X............
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: fd47 ab98 9124 f3f2                      .G...$..
```

Negative control: a truncated/bad file yields `invalid snapfile` with exit 1.
