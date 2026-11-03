# Whispers in the Margin

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{573g4n0gr4phy_!5_fun}`

---

**Category:** stego (document + image) · **Artifacts:** `extracted/chall/Those numbers are process counts.docx`, `extracted/chall/chall.jpg`

## Hint
> "…Inspect the provided documents closely - what appears empty might hold the key to unravelling the final secret."

## Solve - two layers, where the "joke" is actually the key

1. **DOCX whitespace stego.** The last paragraphs of the .docx contain nothing but
   runs of spaces and tabs. Each such paragraph is a 12-column bit row: space = `0`,
   tab = `1`; read each row as a 12-bit value and take `chr(value)`:

```python
import zipfile, re
z = zipfile.ZipFile('Those numbers are process counts.docx')
d = z.read('word/document.xml').decode()
msg = ''
for p in re.findall(r'<w:p [^>]*>.*?</w:p>', d, re.S):
    s = ''
    for m in re.finditer(r'<w:tab/>|<w:t xml:space="preserve">([ ]*)</w:t>', p):
        s += '1' if m.group(0).startswith('<w:tab') else '0'*len(m.group(1) or '')
    if len(s) == 12 and s != '1'*1 and '1' in s and s.count('0') != 12:
        msg += chr(int(s, 2))
print(repr(msg))     # 'haha! u got me, now what?'
```

2. **That sentence is the passphrase**, not a taunt. The companion `chall.jpg`
   (5182x3455) hides a steghide payload under exactly that string:

```bash
steghide extract -sf chall.jpg -p 'haha! u got me, now what?' -xf out.txt
cat out.txt
```

## Flag
```
hiCTF{573g4n0gr4phy_!5_fun}
```

Pitfall worth recording: the whitespace block must be decoded for **all** the
tail paragraphs - skipping the first content row of the block yields
`aha! u got me, now what?` (one `h` short) and steghide then rejects the passphrase.
