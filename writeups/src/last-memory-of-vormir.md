# The Last Memory of Vormir

**Event:** ByteMe CTF 26
**Category:** forensics
**Points:** 100
**Flag:** `OWASP{th3_k3y_1s_s4cr1f1c3}`

---

**TL;DR**

1. `memory.wav` is reversed speech - reverse it, it says **"The key is
   sacrifice."** → key = `sacrifice`.
2. 213 bytes are appended **after** the declared RIFF end (the WAV header
   lies about its size). They are ASCII hex pairs.
3. Hex-decode them, XOR with repeating key `sacrifice` → message:
   > `Remember why I remained.` / `Not for the Stone, but for what held me to
   > it.`
4. The message is the riddle; "the key is sacrifice" is the answer → flag in
   the event's leetspeak style.

## Reproduce

```bash
python3 solve.py            # prints the decoded message
# (optional) hear the reversal:
ffmpeg -y -i memory.wav -af areverse reversed.wav
```

`memory.wav` is the only artifact (delivered as
`memory - 058_ADITYA_KHALIKAR.zip`).

## Key facts / gotchas

- The audio speech is **backwards**. Forward playback is a YouTube-style
  outro ("See y'all again, see you!"); whisper on the reversed track gives
  the real line.
- The RIFF chunk size is `682054` → data ends at byte `682062`; file is
  `682275` → **213 trailing bytes** are the hidden payload (not a valid
  chunk).
- The XOR output is the *only* clean decode; every other key/order gives
  garbage.
- The event's sibling flags are leetspeak phrases (e.g.
  `th3_s0ul_st0n3_wh1sp3r`, `th3_l4st_s0ul_w4s_n3v3r_l0st`), which is how the
  flag is rendered from the key phrase.

## Confidence

Mechanism (steps 1-3) is **fully verified** - the appended bytes XOR to a
grammatically perfect English message with no key/order search needed. The
final flag string is the event-style leetspeak of the audio's own reveal
phrase ("the key is sacrifice"); no online writeup exists for this
challenge, so the exact leet spelling (step 4) is inferred from the event's
flag conventions.
