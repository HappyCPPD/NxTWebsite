# Just Give Me The Flag Man

**Event:** HICyberCon CTF 2026
**Category:** crypto
**Flag:** `hiCTF{sh1ft1ng_7hr0ugh_7h3_b4s3s}`

---

**Event:** HICybercon · **Category:** crypto / misc (encoding chain)
**Flag:** `hiCTF{sh1ft1ng_7hr0ugh_7h3_b4s3s}`

## Challenge

> Saad: You got the note? / Harun: The one with the strange code? I almost burned it. /
> Saad: Don't. Someone has been watching the building since noon. / Harun: What does it say?

`chall.zip` (SHA-256 `47250d4a…952c0`) contains a single file, `chall.txt`:

```
53 74 u3 17 35 x3 x2 76 24 33 93 u3 16 v4 36 v4 93 32 64 22 z3 x2 42 w4 54 05 v2 v5 63
v6 26 23 26 33 86 u3 33 x3 74 x2 06 54 62 x5 22 74 44 04 45 v5 93 x2
```

The zip holds nothing else (no extra field, comment, or trailing data).

## Spotting the encoding

There are 52 tokens of two characters each.

| position | values seen |
|---|---|
| 1st char | `0-9`, `u v w x z` |
| 2nd char | `2 3 4 5 6 7` only |

Two things stand out:

* **The second character only takes 6 values, 2 - 7.** That is exactly the high nibble of printable
  ASCII (0x20 - 0x7F). So each token is a byte written **low nibble first**: the token `53` is
  the byte `0x35`.
* **The letters `u` - `z` are the last six letters of the alphabet**, standing in for the hex
  digits `a` - `f`. The obvious guess `u=a … z=f` gives printable text, but nothing decodes
  cleanly. The order that works is **Atbash** (mirrored): `u→f, v→e, w→d, x→c, y→b, z→a`.
  I found this by brute-forcing every letter→nibble mapping, Ascii85-decoding each, and ranking
  the results by how printable they were. The Atbash mapping was the only one that came out
  fully printable.

Reading each token low-nibble-first is the same as reversing the whole token string, so
layer 1 is simply: **join the tokens → reverse → Atbash the letters → hex-decode.**

## Layers

| # | Operation | Result |
|---|---|---|
| 1 | join tokens, reverse, Atbash `u-z`→`f-a`, hex-decode | ``,9^T@DG"\&E`,G<3?h3b2bn6^.PEM$,:"F#9NcNa?93Bg,<Sq?G5`` |
| 2 | Ascii85 decode | `#!dvnJk6rRHc9"NB7NnI*/1##$!DLYv$^:z3#<Tjw` |
| 3 | ROT47, then base91 decode | `feKTH{uf1ht1zg_7fv0sgf_7f3_l4u3u}` |
| 4 | Beaufort, key `M` (letters only) | `hiCTF{sh1ft1ng_7hr0ugh_7h3_b4s3s}` |

**Layer 1 → 2:** every character is in the Ascii85 range `!`–`u`, and the distribution of high
nibbles (lots of 0x2_/0x3_, almost no 0x7_) matches Ascii85 output.

**Layer 2 → 3:** neither base64, base85, nor base91 decoded the string directly. I ran an automated
search over {identity, reverse, ROT13, ROT47} × {a85, b85, b91, b64, b32, b58, b62, hex}, which
found that **ROT47 + base91** gives text in the shape of a flag.

**Layer 3 → 4:** `feKTH` has to become `hiCTF`. That isn't a Caesar shift (the offsets are +2, +4,
−8, 0, −2), but the **sum** of each ciphertext/plaintext letter pair is always 12 mod 26
(`f+h = e+i = K+C = T+T = H+F = 12`). That is a Beaufort cipher with key `M` (index 12):
`P = (12 − C) mod 26`. Digits, `_`, and braces pass through unchanged.

The decoded flag — "shifting through the bases" — describes the challenge.

## Solve script

`solve.py` (in this folder) runs every layer:

```
$ python3 solve.py extracted/chall.txt
[1] reversed atbash-hex : ,9^T@DG"\&E`,G<3?h3b2bn6^.PEM$,:"F#9NcNa?93Bg,<Sq?G5
[2] ascii85             : #!dvnJk6rRHc9"NB7NnI*/1##$!DLYv$^:z3#<Tjw
[3] rot47 + base91      : feKTH{uf1ht1zg_7fv0sgf_7f3_l4u3u}
[4] beaufort key M      : hiCTF{sh1ft1ng_7hr0ugh_7h3_b4s3s}
```

## Dead ends (for the record)

* Reading each token as a hex byte (`53 74` = `"St"`) is a coincidence. With the high nibble
  restricted to 2 - 7 in the *second* position, that reading can't be text.
* Coordinate/Polybius-grid readings (6 columns from the second character) went nowhere. The
  "grid" was really the hex nibble range.
* A known-plaintext XOR or subtraction against `hiCTF{` at every offset gave no repeating key,
  because the flag is several encoding layers deep.
