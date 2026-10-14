# the-press

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{r4ng3_c0d3r_b1t_3x4ct_y0!}`

---

## 1. Triage

The prompt: *"Hand it 32 bytes. It will tell you nope."*

```
$ file chall
chall: ELF 64-bit LSB executable, x86-64, stripped

$ echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA | ./chall
nope.
```

`strings` gives the tell:

```
need exactly %d bytes of input
CORRECT
nope.
```

So it reads exactly 0x20 (32) bytes and compares *something* to a hardcoded
blob. The success string is `CORRECT`; the `%d` format string for the length
error also says the required count is embedded as an immediate (0x20).

`objdump -d` shows the whole logic inlined in `main` at `0x4003c0`, with a
single `memcmp` call. Crucially the binary imports **only** `fread`, `memcmp`,
`fprintf`, `puts` - no crypto library. Everything is hand-rolled.

## 2. The `.rodata` target

```
$ objdump -s -j .rodata chall
 4012d0 434f5252 45435400 6e6f7065 2e000000  CORRECT.nope....
 4012e0 00691a0d 05110909 4e93af58 eb280076  .i......N..X.(.v
 4012f0 31442538 27504c83 a26d5ede a325465d  1D%8'PL..m^..%F]
 401300 d7b19000                             ....
```

`main` does `memcmp(0x4030a0, 0x4012e0, 0x24)` - i.e. it compares a **36-byte
output buffer** against this hardcoded 36-byte blob. So the target is:

```
00 69 1a 0d 05 11 09 09 4e 93 af 58 eb 28 00 76
31 44 25 38 27 50 4c 83 a2 6d 5e de a3 25 46 5d
d7 b1 90 00
```

The leading `0x00` and the trailing `0x00` are a strong hint: this is a
**range-coder byte stream** (the classic LZMA coder emits a leading dummy
`cache` byte of 0 and pads on flush).

## 3. Reading the algorithm

The interesting region is `0x400470` - `0x400571`. Annotated:

```
400470  movzx ebp, [rsp+r13]        ; ebp = input[i]
400475  test  r13, r13
400478  je    .noprev
40047a  xor   bpl, [r15+r13]        ; r15 = rsp-1  -> ebp ^= input[i-1]
.noprev:
40047e  movzx ebp, bpl              ; ebp = differential byte D[i]
400482  shl   r12d, 8               ; r12 = prev_byte << 8
400486  mov   r11d, 7               ; bit index 7..0
40048c  mov   ebx, 1                ; binary-tree node
4004a0  ...                         ; per-bit loop
```

Per bit:

```
        r10 = ebp >> bit            ; the ACTUAL bit from the input
        r9d = esi >> 12             ; esi = range
        edx = prob[prev*256 + node] ; u16 model
        r9d *= edx                  ; r9d = bound = (range>>12)*prob
        r10 &= 1
        jne  bit1
  bit0: range  = bound
        prob  += (0x1000 - prob) >> 4
  bit1: range -= bound
        low   += bound
        prob  -= prob >> 5
  norm: while range <= 0xffffff: shift_low(); range <<= 8
  tree: node = node*2 + bit
```

`0x400700` is textbook **`shift_low`** (LZMA `RangeEncoder::ShiftLow`):

```
carry = low >> 32
if carry != 0 or (uint32)low < 0xFF000000:
    emit(cache + carry)
    emit 0xFF + carry (pending-1) times
    cache  = low >> 24
    pending = 1
else:
    pending += 1
low = (uint32)low << 8
```

State layout:

| addr       | meaning                        | init        |
|------------|--------------------------------|-------------|
| `0x4030e0` | `pending` (LZMA `cacheSize`)   | 1           |
| `0x4030e8` | `cache`                        | 0           |
| `0x4030ec` | `range`                        | 0xFFFFFFFF  |
| `0x4030f0` | `low` (64-bit)                 | 0           |
| `0x403080` | output length                  | 0           |
| `0x4030a0` | output buffer (0x24)           | - |
| `0x403100` | probability table, 65536 × u16 | 0x0800      |

`0x400420` initialises the whole 0x20000-byte probability table to `0x0800`
(half of the model total `0x1000`, i.e. p = 1/2), confirming the model.

At `0x400558` the program calls `shift_low` five times in a row - the standard
LZMA **flush**. Then it checks `out_len == 0x24` and `memcmp`s against the
target.

**Conclusion:** `chall` is a **range ENCODER**. It reads 32 bytes, XOR-diffs
them (`D[0]=M[0]`, `D[i]=M[i]^M[i-1]`), encodes the 32 diff-bytes with an
order-1 byte-context binary-tree model, and compares the 36-byte coded stream
to the hardcoded target. We must find the 32-byte `M` that encodes to it.

The model:

* context = `prev_byte * 256 + node` (node = 1 then `2*node+bit`)
* 8 bits per byte, MSB first
* `prob` init `0x800`, total `0x1000`, shift `12`
* bit 0: `p += (0x1000 - p) >> 4` ; bit 1: `p -= p >> 5`
* normalize while `range < 1<<24`

## 4. Inversion

Because the encoder is deterministic, the inverse is the matching **range
DECODER** run over the 36-byte target. It consumes exactly the bytes the
encoder produced (verified: 36 in, 36 consumed) and yields the 32 diff-bytes
`D`. Un-diffing (prefix XOR) gives `M`.

```python
def decode(data, nbytes):
    code = int.from_bytes(data[1:5], "big")   # first byte is the dummy 0x00
    rng  = 0xFFFFFFFF
    pos  = 5
    probs = [0x800] * 65536
    out, prev = [], 0
    for _ in range(nbytes):
        node = 1
        for _ in range(8):
            idx   = prev * 256 + node
            p     = probs[idx]
            bound = (rng >> 12) * p
            if code < bound:
                rng = bound
                probs[idx] = p + ((0x1000 - p) >> 4)
                node <<= 1
            else:
                code -= bound
                rng  -= bound
                probs[idx] = p - (p >> 5)
                node = (node << 1) | 1
            while rng < 0x1000000:
                rng  = (rng << 8) & 0xFFFFFFFF
                code = ((code << 8) | data[pos]) & 0xFFFFFFFF
                pos += 1
        out.append(node & 0xFF)
        prev = out[-1]
    return out, pos
```

Two gotchas that cost time:

1. **The un-diff is a prefix XOR, not `D[i]^D[i-1]`.** Since
   `D[i] = M[i]^M[i-1]`, we have `M[i] = D[0]^…^D[i]`. Using
   `D[i]^D[i-1]` produces garbage.
2. **Validate by re-encoding.** The decoder output alone isn't proof; feeding
   `M` back through the encoder must reproduce the 36-byte target *byte for
   byte*. It does (`MATCH: True`).

## 5. Result

```
D = 691a1505110909465a09546c3c535457412d3d53452b6c4b4c57172b2649115c
M = isfcr{r4ng3_c0d3r_b1t_3x4ct_y0!}
```

Confirmed against the shipped binary:

```
$ python3 -c "import sys;sys.stdout.buffer.write(b'isfcr{r4ng3_c0d3r_b1t_3x4ct_y0!}')" | ./chall
CORRECT
```

## 6. Why it's "the-press"

The name is a hint at *compression* (a printing press "compresses" type onto a
page). The `%d`/`0x20` constant and the leading/trailing zero bytes were the
breadcrumbs: 32 in, 36 out, LZMA-style flush → range coder → invert it.

## 7. Files

* `chall` - original challenge binary (untouched)
* `solve.py` - decoder + encoder + round-trip self-check; prints the flag
* `HANDOFF.md` - paste-ready summary
* `WRITEUP.md` - this document

