# Broken Signals

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{h34d3r_r3p41r_m4st3r}`

---

**Category:** forensics / file repair · **Artifact:** `extracted/broken_signal.dat`

## Hint
> "…it appears corrupted. The file cannot be opened by any standard application. Something is wrong with the file itself - can you repair it…?"

## Solve
`file` says `data`, but the structure is a PNG with a damaged header: the 4-byte
PNG signature has been zeroed out while the rest (chunk lengths, `IHDR`, CRCs) is intact.

```bash
xxd broken_signal.dat | head -1
# 00000000: 0000 0000 0d0a 1a0a 0000 000d 4948 4452  ............IHDR

python3 - <<'EOF'
d = bytearray(open('broken_signal.dat','rb').read())
d[0:4] = b'\x89PNG'                 # restore the PNG magic
open('fixed.png','wb').write(d)
EOF
```

Open `fixed.png` (400x300, 16-bit RGBA). The image itself renders the answer:

```
SIGNAL  INTERCEPTED
hiCTF{h34d3r_r3p41r_m4st3r}
```

## Flag
```
hiCTF{h34d3r_r3p41r_m4st3r}
```
