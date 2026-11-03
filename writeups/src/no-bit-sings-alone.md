# No Bit Sings Alone

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{m4th3m4t!c5_g4v3_m3_4_l0t_Of_p4!n_8d52ae513}`

---

> A suspicious audio file. Nothing more.
> Or maybe that is exactly what it wants you to think.
> Listen carefully. Look deeper.

**Flag:** `hiCTF{m4th3m4t!c5_g4v3_m3_4_l0t_Of_p4!n_8d52ae513}`

Solver: [`solve.py`](solve.py) (`python3 solve.py suspicious.wav`; add `--banner` to dump the spectrogram text).

---

## TL;DR

| Layer | What's there | How to undo it |
|---|---|---|
| 1. Spectrogram banner (0.7 - 5.4 s, both channels) | `AES256GCM`, the nonce `N`, and the ciphertext `C0..C5` | Read the 5×7 pixel font (OCR by bitmap, not by eye) |
| 2. Guide tones (R channel, blocks 585 - 642) | One pure tone per 4096-sample block, at FFT bin `k` (always odd) | `k` is the step size: select `L[j·k mod 4096]` |
| 3. Matrix embedding (L channel LSBs) | Hamming(31,26) syndrome, columns rotated by `k` | 5 bits per block → 290 bits |
| 4. Finite-field transform | 32 values in GF(257), 9 bits each | Inverse NTT (length 32, ω = 240) → 32-byte AES key |
| 5. Crypto | AES-256-GCM | CTR-decrypt → length-prefixed flag |

---

## 1. Stuff you can see: the spectrogram banner

The file is a 59.8 s, 16-bit stereo WAV at 44.1 kHz. It contains only `fmt ` and `data` chunks, so there's no metadata. A spectrogram shows a block of text between 7 and 18 kHz in the first ~5 s:

```
AES256GCM
N=99CB9C49E4C83527CE6F89D9
C0=8A845BA500DE25B749F1FF63CCFF
C1=9D2D9FD8D2614E19BCA42CC7E438
C2=B31407AE896311C3AADCF9327610
C3=478444A09EF6FE3650DF7EBEC3B7
C4=1FF18CF0EB728DBFA791B7485D76
C5=7172AE849328715A10B5
```

**Don't read it by eye.** The font is a blocky 5×7 font, and `8 / B / 9 / 0 / D` look nearly identical in a blurry spectrogram. One wrong nibble breaks the decryption. It's better to recover the font grid exactly:

* **Rows:** the horizontal strokes are pure tones on a regular ladder, `f = 18002 − R·177.44 Hz` for R = 0…62. That's 8 text lines × (7 pixel rows + 1 blank row).
* **Columns:** sweeping the analysis-window offset and measuring contrast shows a period of exactly **1024 samples** per pixel column, so a character is 6 columns = 6144 samples. (Guessing the pitch as ~0.1367 s from the picture drifts by half a character across a line.)
* For each (row, column) cell, take the magnitude of a single DFT bin at the row frequency over that 1024-sample window. Then threshold.

The result is a perfectly clean bitmap. Only 20 distinct glyphs appear, so each one can be labelled once without ambiguity:

```
#   #        ###   ###   #### ####   ###   ####    #   ###  #####
##  # ##### #   # #   # #     #   # #   # #       ##  #   # #
# # #       #   # #   # #     #   # #   # #      # #  #   # #
#  ##        ####  #### #     ####   #### #     #  #   #### ####
#   # #####     #     # #     #   #     # #     #####     # #
#   #           #     # #     #   #     # #        #      # #
#   #        ###   ###   #### ####   ###   ####    #   ###  #####
  N     =     9     9     C     B     9     C     4     9     E
```

(8 is rounded on both halves, and 9 is the same shape with the lower-left stroke missing. B has a straight left side with square corners on the left. D is B without the middle bar, and 0 is rounded with a diagonal slash.)

So we have AES-256-GCM, a 12-byte nonce and 80 bytes of ciphertext. The thing we're missing is the key.

## 2. The guide: tones in the right channel

The hint says the channels have different roles, and that signals in the "observable" channel guide the search in the other one.

Near the end (≈54.3 - 59.7 s), the right channel has a staircase of high-pitched tones (14 - 19.4 kHz). Cutting R into 4096-sample blocks *aligned to sample 0* and taking a plain rectangular-window FFT shows that blocks **585 - 642 (58 blocks)** each hold a tone that falls *exactly* on one bin. Practically all of the high-band energy is in a single bin, and the neighbouring bins are ~0:

```
m=585 k=1781   m=586 k=1583   m=587 k=1463   m=588 k=1625   ...   m=642 k=1483
```

Every `k` is **odd**, so `gcd(k, 4096) = 1` and `j·k mod 4096` visits every position in the block exactly once. In other words, k is a step size, as the hint suggests ("modular arithmetic, repeated steps, positions wrapping around within a block").

## 3. The hidden layer: matrix embedding in the left channel

Reading the LSBs at those positions directly gives noise. The hint points to *parity relationships as in error-correcting codes*. This is **matrix embedding** (a.k.a. syndrome coding), where a group of `n = 2^p − 1` cover bits carries `p` message bits as the Hamming-code syndrome:

```
syndrome = XOR of column_index(i) over all i where bit_i = 1
```

The number of parameters is small, but every variant we tested produced a plausible-looking bitstream, so we needed a test that tells the right one apart. Layer 4 provides it: if the payload is 32 elements of **GF(257)** stored in 9 bits each, then *every* 9-bit chunk must be ≤ 256. For random bits, all 32 chunks pass with probability ≈ 0.5³² ≈ 2⁻³². Brute-forcing p ∈ [2,8], the start index, the sign handling and several "per-block arrangement" rules against that test gives exactly one family of hits:

* **p = 5**, i.e. Hamming(31,26): 31 samples per block → 5 bits per block, 58 × 5 = **290 bits**
* samples `L[block + (j·k) mod 4096]` for **j = 1…31**
* the cover bit is `sample & 1` (two's-complement LSB)
* **column index of the i-th selected bit = ((i − k) mod 31) + 1**. The tone frequency rotates the parity-check matrix from block to block ("the frequency information … also influences how those parity relationships are arranged")
* syndrome bits MSB-first

```python
syn = 0
for i in range(31):
    if L[base + ((i + 1) * k) % 4096] & 1:
        syn ^= ((i - k) % 31) + 1
```

290 bits = 32 × 9 + 2 padding zeros. All 32 values land in [0, 256]:

```
205 208 154 114 115 240 123 108 245 172  73 192 256 177  62 202
153   7  77 138 175   0   4  68 208  32  76 169 103  36 147 216
```

Note the `256`: it can't be a byte, which confirms we're working in GF(257).

## 4. The "frequency-like" transform: inverse NTT over GF(257)

A "reversible, frequency-like mathematical transformation" over a finite field is a **Number Theoretic Transform**. 257 is prime and 32 | 256, so GF(257) has 16 primitive 32nd roots of unity. Applying the inverse NTT with each candidate root (and with or without the 1/n scaling) gives candidate keys.

The GCM tag never verified with any split we tried (see the notes below). So instead of checking the tag, we decrypted each candidate in **CTR mode**, which is what GCM does underneath (keystream counter starts at 2), and looked for the flag format. Exactly one candidate decrypts to readable text:

```
ω = 240, scaled by 32⁻¹ mod 257
key = 8da8dca0aa79a8a2b1e1aef181e98e63fcca7da26d49d6dbffdb461e3ecd544d
```

```python
def inverse_ntt(vals, w=240, p=257):
    n = len(vals); n_inv = pow(n, p - 2, p)
    return [sum(v * pow(w, i * j, p) for j, v in enumerate(vals)) * n_inv % p
            for i in range(n)]
```

## 5. Decryption

```
AES-CTR(key, nonce || 00000002)  ->  00 32 "hiCTF{m4th3m4t!c5_g4v3_m3_4_l0t_Of_p4!n_8d52ae513}" ...
```

The plaintext starts with a 2-byte big-endian length (0x0032 = 50), followed by the 50-byte flag.

**Flag:** `hiCTF{m4th3m4t!c5_g4v3_m3_4_l0t_Of_p4!n_8d52ae513}`

---

## Notes / gotchas

* **Block alignment matters.** The tone blocks are aligned to multiples of 4096 from sample 0. Use a rectangular window so that an exact-bin tone shows up as a single spike. The Hann-windowed STFT views used for exploring smear it over 3 bins.
* **The ≤ 256 test was the key move.** It separates the extraction layer (code parameters, column arrangement) from the transform and crypto layers, so you can brute-force each one on its own instead of searching the product of all of them against the AES tag.
* **The GCM tag never verified** for any split of the 80 bytes we tried, with or without `AES256GCM` as AAD. The flag decrypts cleanly anyway (CTR mode doesn't need the tag). So either the trailing bytes were drawn in a different layout, or one of them is a misread nibble. It doesn't affect the flag.
* Text appears in both channels and the tones are in R only, so "the observable channel" is R, and the payload is in L's LSBs.
