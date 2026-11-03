# Dead Air

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{s1l3nc3_w4s_th3_m3ss4g3_6r3v}`

---

Station KESTREL. Flag format `hiCTF{}`.

## Artifacts
`dead-air.zip` ->
- `kestrel_last_recording.wav` - stereo 16-bit PCM, 44100 Hz, 47.24 s
- `kestrel_logbook.7z` - password protected

## Chain

1. **WAV is two operators on two stereo channels.**
   - **Ch0** (~700 Hz carrier, on/off keyed) = the operator who "spoke out loud".
     OOK envelope -> Morse:
     `KESTREL STATION OFF AIR KEY IS NIGHTJAR LISTEN WITH YOUR EYES`
     - key = **NIGHTJAR**
     - "listen with your eyes" = look at the spectrogram
   - **Ch1** = the operator who "never made a sound you could hear".
     Full-band spectrogram draws large glyphs at 5-8 kHz:
     `KSTR-7742-VXQ`

2. **7z password** = `KSTR-7742-VXQ`. Extracts:
   - `logbook_page.png` - 28 coded glyphs (01..28)
   - `operator_codepad.png` - code pad mapping glyph -> char for the
     alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_` (37 symbols, index 0..36)

3. **Glyph decoding.** Each cell encodes its symbol in TWO redundant ways:
   the black stroke + start-dot shape, and a faint 3x3 dot constellation.
   Both agree. Template-matching each logbook glyph (rotation/flip invariant)
   to the pad glyphs yields ciphertext:
   `59R_6L3Q9BYGBQ3QZAYZMP3QIZ92`

4. **Vigenère** over the same 37-symbol alphabet, key `NIGHTJAR`:
   P = (C - K) mod 37
   -> `S1L3NC3_W4S_TH3_M3SS4G3_6R3V`
   = "SILENCE WAS THE MESSAGE" (+ a trailing fragment `6R3V`).

## Flag
`hiCTF{s1l3nc3_w4s_th3_m3ss4g3_6r3v}` (ACCEPTED - the decode lowercased; the uppercase form was rejected)

Note: the trailing `6R3V` decodes deterministically (glyphs 25-28 = I,Z,9,2,
each verified against the pad at high confidence and via their unique dot
constellations reached only by the Z/3,I/G disambiguation that keeps the first
23 chars perfectly clean). Every alternative disambiguation corrupts earlier
words (S1L3NCZ / THZ / W4SBTH3), so this reading is the only consistent one.
