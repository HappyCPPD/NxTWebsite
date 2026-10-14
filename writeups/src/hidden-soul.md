# Hidden Soul

**Event:** ByteMe CTF 26
**Category:** forensics
**Flag:** `OWASP{h1dd3n_s0ul_b3n34th_th3_sh4d0w}`

---

## Challenge
"A seemingly ordinary Soul Stone fragment contains a secret hidden inside its
pixels. Extract the concealed message."

- Attachment: `soul_fragment.png`
- 80×80, 8-bit RGB, non-interlaced PNG (19,353 bytes - large for only 19,200 px,
  a mild hint that low-order bits are doing work).
- Flag format: `OWASP{...}`

![The challenge attachment, an 80x80 PNG](../images/writeups/hidden-soul-attachment.png "160x160")

## Solution
Classic LSB steganography in the colour channels.

Triage:
```
file soul_fragment.png      # PNG 80x80 RGB
exiftool soul_fragment.png  # no interesting metadata
binwalk soul_fragment.png   # only the normal IEND zlib stream
zsteg -a soul_fragment.png  # <-- hit
```

`zsteg` reports the payload on the **`b1,rgb,lsb,xy`** pattern, i.e. the
least-significant bit of every R, G, B channel value, scanned row-major:

```
b1,rgb,lsb,xy  .. text: "OWASP{h1dd3n_s0ul_b3n34th_th3_sh4d0w}"
```

The payload is a plain ASCII string (no passphrase, no compression). Bits from
each channel are packed MSB-first into bytes; the flag is the opening ASCII run
that terminates at `}` followed by binary noise.

## Reproduce
```
python3 solve.py soul_fragment.png
# FLAG: OWASP{h1dd3n_s0ul_b3n34th_th3_sh4d0w}
```

The extractor is dependency-light (Pillow only) and does not rely on zsteg:
it reads the LSB of each R/G/B sample in row-major order and repacks
bits→bytes. Both methods agree.

## Evidence
- `soul_fragment.png` - original attachment
  sha256 `ebf0aaaeda9d05a25bd269c0f22c08b91176d3fbda25f3c853e08255beca5bfa`
- `solve.py` - independent extractor + verifier
- `zsteg_output.txt` - raw `zsteg -a` output (hit at `b1,rgb,lsb,xy`)
- `extract.log` - solve.py run log

## Negatives (do not re-derive)
- Appended/embedded archive after IEND: **none** (binwalk finds only the PNG IHDR
  zlib stream).
- EXIF / textual metadata chunks (tEXt/zTXt/iTXt): **none**.
- Passphrase-protected steghide/outguess: **N/A** - payload is raw LSB, no key.

## Difficulty notes
Single-pass solve: `zsteg -a` on the first look. The only "trick" is that the
message is bit-plane 1 of the *RGB* channels (not a single channel), so a naive
single-channel LSB dump misses it.
