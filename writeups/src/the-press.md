# the-press

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{r4ng3_c0d3r_b1t_3x4ct_y0!}`

---

A stripped ELF reads exactly 32 bytes and compares a derived 36-byte output against a hardcoded `.rodata` blob via `memcmp`. Only `fread`, `memcmp`, `fprintf`, `puts` are imported - everything is hand-rolled, no crypto library. The leading `0x00` and trailing `0x00` of the target blob are the tell: this is an **LZMA-style range coder** stream (leading dummy cache byte, flush padding).

**Reading the algorithm:** the program XOR-diffs the 32 input bytes (`D[0]=M[0]`, `D[i]=M[i]^M[i-1]`), then encodes the 32 diff-bytes with an order-1 byte-context binary-tree model: context = `prev_byte*256 + node`, 8 bits per byte MSB-first, `prob` init `0x800`/total `0x1000`/shift 12, bit0: `p += (0x1000-p)>>4`, bit1: `p -= p>>5`, normalize while `range < 1<<24`. `shift_low` at `0x400700` is textbook LZMA `RangeEncoder::ShiftLow`. Five calls to `shift_low` at the end is the standard LZMA flush.

**Inversion:** because the encoder is deterministic, run the matching **range decoder** over the 36-byte target to recover the 32 diff-bytes `D`, then un-diff via prefix XOR (`M[i] = D[0]^...^D[i]`, not `D[i]^D[i-1]` - a pitfall that cost time).

```python
def decode(data, nbytes):
    code = int.from_bytes(data[1:5], "big")
    rng = 0xFFFFFFFF; pos = 5; probs = [0x800]*65536
    out, prev = [], 0
    for _ in range(nbytes):
        node = 1
        for _ in range(8):
            idx = prev*256 + node; p = probs[idx]
            bound = (rng >> 12) * p
            if code < bound:
                rng = bound; probs[idx] = p + ((0x1000-p)>>4); node <<= 1
            else:
                code -= bound; rng -= bound; probs[idx] = p - (p>>5); node = (node<<1)|1
            while rng < 0x1000000:
                rng = (rng<<8)&0xFFFFFFFF; code = ((code<<8)|data[pos])&0xFFFFFFFF; pos += 1
        out.append(node & 0xFF); prev = out[-1]
    return out, pos
D = 691a1505110909465a09546c3c535457412d3d53452b6c4b4c57172b2649115c
M = isfcr{r4ng3_c0d3r_b1t_3x4ct_y0!}
```

Validated by re-encoding `M` and matching the 36-byte target byte-for-byte, and confirmed against the live binary. "the-press" = compression (a printing press "compresses" type onto a page); the `%d`/`0x20` constant and leading/trailing zero bytes were the breadcrumbs: 32 in, 36 out, LZMA-style flush → range coder → invert it.
