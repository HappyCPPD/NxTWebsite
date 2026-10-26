# Ventilator303

**Event:** SolarCTF
**Category:** misc
**Flag:** `SOLARCTF{YuG0sl4v1a-Galaks1ja-DIY-Z1L0G80Z}`

---

**Category:** Forensics / Reversing · **Author:** M0shp1t

> This Balkan station broadcast at night; it didn't play music, but it could be used to
> learn how to create even a flight simulator. The recording you are holding is dated
> April 19, 1987.
>
> Task: `ventilator303.wav`

**Flag:** `SOLARCTF{YuG0sl4v1a-Galaks1ja-DIY-Z1L0G80Z}`

---

## 1. Recon

The only file is a 168-second mono WAV:

```
RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 44100 Hz
```

The flavour text is the whole hint. A "Balkan station broadcasting at night, not
music, dated 1987" is **Radio Belgrade's "Ventilator 202/303" show**, which in 1980s
Yugoslavia broadcast *computer programs as audio* so listeners could record them to
cassette. The "learn to make a flight simulator" line points at the **Galaksija**, a
DIY Z80 home computer from Belgrade.

So the WAV is a tape-loading signal. Listening/looking at the waveform confirms it: a
pilot tone, then a long data block, then a trailing tone.

## 2. Identifying the modulation

Measuring full-cycle periods via zero-crossings shows two dominant tones in a clean 2:1
ratio:

| tone | period | meaning |
|------|--------|---------|
| ~2400 Hz | ~18 samples | mark |
| ~1200 Hz | ~37 samples | space |
| ~1000 Hz | ~44 samples | pilot/leader |

Run-length analysis of the mark/space bursts shows **mark runs are even, space runs
come in the ratio that makes every bit the same duration**. That is the
**Kansas City Standard / CUTS** encoding:

- bit `1` = **2 cycles of 2400 Hz**
- bit `0` = **1 cycle of 1200 Hz**
- both occupy one bit cell (~1/1200 s), i.e. ~1200 baud

Bytes are framed serially: **1 start bit (0) + 8 data bits (LSB first) + 1 stop bit (1)**.

## 3. Demodulating robustly

Naïve per-cycle thresholding "almost" worked but left a handful of bit-slips in long
uniform regions - enough to corrupt the payload. Band-limiting in the recording shifts
zero-crossings, producing a spread of ambiguous half-pulse widths.

The decoder that nailed it byte-perfect:

1. **FSK discriminator** - quadrature-correlate the signal against 2400 Hz and 1200 Hz
   over a short sliding window, take `E2400 - E1200`. Positive = mark, negative = space.
2. **Transition counting** - between consecutive sign-changes of the discriminator the
   value is constant; the number of bits in that span is `round(gap / Tb)` with
   `Tb ≈ 36` samples. This is self-clocking and tolerant of tape-speed drift.
3. **Deframe** start/data(LSB)/stop into bytes.

### Verifying correctness

The decoded stream begins with a human-readable header:

```
VENTILATOR-303 TAPE v1
NAME: GALAKSIJA-DEMO
FORMAT: ZXTAP
LEN: 16659
CSUM: 88D9
```

The payload is a **ZX Spectrum `.TAP` file**. Two independent checks proved the decode
was byte-perfect:

- **All four TAP blocks' per-block XOR checksums pass.**
- The header's `CSUM: 88D9` is the **CRC-16/CCITT** (poly `0x1021`, init `0xFFFF`) of the
  16659-byte payload. ✅

## 4. The TAP file

| block | type | details |
|-------|------|---------|
| 0 | Program header | name `GALAKSIJA `, autostart |
| 1 | BASIC program | prints `VENTILATOR-303` / `LOADING FOR THOSE WHO WAIT`, loads the code |
| 2 | CODE header | name `GALAKSIJA`, **len 16448, load 0x8000 (32768)** |
| 3 | CODE data | 16448 bytes of Z80 machine code |

No flag appears in plaintext anywhere - the BASIC loader is just cosmetic. The flag
lives in the Z80 CODE block and is produced at runtime.

## 5. Reversing the Z80 code (loaded at 0x8000)

Disassembly reveals a decode loop at `0x82A2`:

```asm
82A2  LD HL,0x83D4 ; seed  -> state
82A5  LD DE,0x83C4
82AB  LDIR          ; state = bytes at 0x83D4 = 19 04 87 19  (LE -> 0x19870419)
82AD  XOR A
82AE  LD (0x83C2),A ; i = 0
82B1  LD A,(0x83C2)
82B4  CP 0x2B       ; 43 iterations
82B6  RET Z
82B8  CALL 0x8202   ; state = LCG(state)
82BB  LD HL,0x8403  ; ciphertext base
82C4  ADD HL,DE     ; + i
82C5  LD A,(HL)     ; cipher[i]
82C6  LD HL,0x83C6
82C9  XOR (HL)      ; ^ state byte 2  ((state>>16)&0xFF)
82CA  LD (0x83C3),A ; = plaintext char
...                  ; print char at screen position table[0x83D8 + i]
8306  INC A
8307  LD (0x83C2),A ; i++
830A  JR 0x82B1
```

The routine at `0x8202` is a 32×32 shift-add multiply plus an add - a classic
**Linear Congruential Generator**:

```
state = (state * 0x41C64E6D + 0x3039) mod 2^32
      = (state * 1103515245 + 12345) mod 2^32     ; the ANSI C rand() constants
```

with the keystream byte taken as `(state >> 16) & 0xFF`.

Data tables:

- `0x83D4` : 4-byte seed `19 04 87 19` → `0x19870419` - literally **19/04/87**, the
  recording's date.
- `0x83D8` : 43-byte **position table** - each decrypted char is drawn to a scrambled
  screen cell, so the on-screen result reads correctly.
- `0x8403` : 43-byte **ciphertext**.

## 6. Solve

```python
code   = open('code_good.bin','rb').read()   # the extracted 16448-byte CODE block
cipher = code[0x403:0x403+43]
postab = code[0x3d8:0x3d8+43]

state = 0x19870419
plain = bytearray()
for i in range(43):
    state = (state*1103515245 + 12345) & 0xFFFFFFFF   # LCG step before each char
    plain.append(cipher[i] ^ ((state >> 16) & 0xFF))

flag = [' ']*(max(postab)+1)
for i in range(43):
    flag[postab[i]] = chr(plain[i])      # reorder by on-screen position
print(''.join(flag))
```

Output:

```
SOLARCTF{YuG0sl4v1a-Galaks1ja-DIY-Z1L0G80Z}
```

## 7. Takeaways

- Old-radio "data over audio" nostalgia → **Kansas City Standard FSK**, not the ZX ROM
  pulse format (the author modulated a ZX `.TAP` with KCS tones).
- A discriminator + transition-counting demodulator beats per-cycle thresholding on
  drifting/band-limited tape audio.
- TAP per-block XOR + the header's CRC-16/CCITT gave strong oracles to confirm a
  byte-perfect decode before spending time on the Z80.
- The keystream seed `0x19870419` is the challenge date - a nice touch.
