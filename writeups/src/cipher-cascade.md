# Cipher Cascade

**Event:** HICyberCon CTF 2026
**Category:** crypto
**Flag:** `hiCTF{l4y3r_by_l4y3r_unw1nd}`

---

**Category:** crypto / misc · **Artifact:** `extracted/cipher_cascade.txt`

## What it is
`=== INTERCEPTED TRANSMISSION ===` with the hint:

```
Hint: The outermost layer is reversed.
Layers applied (outermost to innermost): Reverse -> Base64 -> Hex -> ???
Encoded message:
=Q2NxcTM2EzMhZTM2gjNmVTN2MzMjZDNzkzNmVzY2YmNmVTN2MzMjZDNzkzNidzM1cDNwUjN3UzN
```

## Solve
Peel the layers literally, in order:

1. **Reverse** the whole encoded string.
2. **Base64-decode** it.
3. **Hex-decode** the result -> ASCII `uvPGS{y4l3e_ol_y4l3e_haj1aq}`.
4. The final `???` layer is **ROT13** -> `hiCTF{l4y3r_by_l4y3r_unw1nd}`.

```bash
python3 - <<'EOF'
import base64
s="=Q2NxcTM2EzMhZTM2gjNmVTN2MzMjZDNzkzNmVzY2YmNmVTN2MzMjZDNzkzNidzM1cDNwUjN3UzN"
r=s[::-1]
h=base64.b64decode(r).decode()            # 75765047537b...  (hex text)
import codecs
print(codecs.decode(bytes.fromhex(h).decode(), 'rot13'))
EOF
```

## Flag
```
hiCTF{l4y3r_by_l4y3r_unw1nd}
```
