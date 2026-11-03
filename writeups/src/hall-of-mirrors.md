# Hall of Mirrors

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{h1dd3n_numb3r_l4ttice_le4k}`

---

**Flag:** `hiCTF{h1dd3n_numb3r_l4ttice_le4k}`

Artifact: `hall-of-mirrors.wav` (s16le, 48 kHz, stereo, 1560.000 s, data @ byte 216).

---

## Stage 0 - The spectrogram text (where the key lives)

The tone grid is at **t ≈ 19.42 - 20.85 min**, drawn with a comb of **35 tones**:
`f_k = 6799.8 + 194.09·k Hz`, k = 0..34, with an empty band at k = 14..20 so the grid
forms **two 14-row text lines**.

Rendered as a contrast-whitened tonogram with 44-frame cells:

```
MIRRORS1   SM64/GAP/PAR
K=9C4F1E7A3B50D682
```

* `MIRRORS1` = the frame magic; `SM64` = SplitMix64; `GAP/PAR` = step / parity.
* **The key is `9C4F1E7A3B50D682`** - note the 15th hex digit is **`8`**, not `B`.
  (It is easy to misread as `…D6B2`, and that one glyph stops anything from extracting.
  Confirmed by brute-forcing all 240 single-hex-digit alternatives → only `…D682`
  produces a valid frame.)

## Stage 1 - CARRIER (MirrorStego v1)

Per datasheet [1], on the `data` chunk's interleaved int16 LE samples `S[0..M)`:

```
SplitMix64(K) seeded with K = 0x9C4F1E7A3B50D682 ; p = -1
per hidden bit:
    d1 = next(); p += 1 + (d1 % 4096)
    d2 = next(); w = (d2 >> 17) & 0xFF
    bit = popcount(low_byte(S[p]) ^ w) & 1     # MSB-first into bytes
frame: "MIRRORS1" | payload_len u32LE | crc32 u32LE | payload
```

Yields a 6266-byte payload, **CRC32 verified** (`0xE2046FB1`), magic `MVM1`.

Decoy (ignore): `hiCTF{just_lsb_n0ise}` at packed byte offset 512 of the plain
LR-interleaved LSB lane.

## Stage 2 - PROCESSOR (MVM1)

Payload = `MVM1 | code_len u32 | data_len u32 | entry u16 | rsv u16 | code | data`
(6107 B code, 143 B data, entry 0). Emulated per datasheet [2] (64 KiB CODE/DATA,
R0..R15, 256-deep stack, R15 = FNV-ish fetch hash updated with every opcode, incl. the
`SMC` xorshift self-decrypt). It halts after 20395 steps emitting **5083 bytes** =
the `MIRRORS1` TLV.

## Stage 3 - PAYLOAD TLV & UNSEALING

TLV records: secp256k1 `n, p, a=0, b=7, Gx, Gy`; point `Q`; `L = 12`;
`count = 48` tuples `(A,B,C)`; sealed blob (33 B).

`B` is a valid curve x-coordinate for **all 48** tuples ⇒ `B = r`.
Signatures are ECDSA `(r,s,z) = (B, C, A)` with **biased nonces**: each nonce has its
top `L = 12` bits zero (`k < 2^244`).

Hidden-number lattice (dimension 50, integer construction), basis rows
`n²·e_i`, `(r_i/s_i·n …, 2^244, 0)`, `(z_i/s_i·n …, 0, 2^244·n)`; LLL → short vector
`(k_0…k_47, d·2^244, 2^244·n)`.

```
d = 0x278c1c0ea08921ba895d3d4c971e4e0a8c8b29d8016f42d9861fe49c6fa826c6
verified: d·G == Q   (secp256k1)
```

Then `key32 = KDF(d)` (datasheet [3]: FNV-ish 4-round KDF, seed `0x4D6972726F72734B`),
and the ChaCha-like 4×quarter-round stream (four u64 LE words, `ctr += 0x9E3779B97F4A7C15`,
`d ^= ctr`) XORs the sealed blob:

```
key32 = a34c6fd7c69371c4c72e14d046b00a2c147f00067dfff01aaec8ef0097d10fdc
sealed 1c71b4d26735249c83c32848085ceb62cce723aa6e1f4fac7b9b33efe30d896e90
      ^ keystream
flag  hiCTF{h1dd3n_numb3r_l4ttice_le4k}
```

## Pitfalls hit

* The tone grid is **weak** (~3 - 6 dB above rain) - needs whitening + long time
  averaging; naive renders look like noise.
* The published spacing 194.4 Hz is really **194.09**; comb must be refit at high
  resolution (N=65536) or rows drift off after ~13 tones.
* A single misread hex glyph (`B` for `8`) silently breaks the whole carrier -
  brute-force single-digit alternatives when a verified spec still yields no magic.
* 12-bit nonce bias is *just* enough for LLL at m=48 (gap ≈ 3.6 bits); the plain
  rational-matrix construction silently fails, use the exact integer form.
