# Roof of Africa

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{h4kun4_m4t4t4_m34ns_n0_w0rr13s}`

---

**Category:** stego · **Artifact:** `extracted/roof_of_africa.jpg` (1600x1056 JPEG)

## Hint
> "…protected by the mountain's most famous number."

Africa's highest peak = Kilimanjaro, **5895 m**. That number is the steghide passphrase.


The challenge image:

![The challenge photo, roof_of_africa.jpg](../images/writeups/roof-of-africa-attachment.jpg "1200x792")

## Solve
```bash
steghide extract -sf roof_of_africa.jpg -p 5895 -xf roof.txt
cat roof.txt
```
(`steghide info` shows the file has embedded data; the mountain's height is the only key needed.)

## Flag
```
hiCTF{h4kun4_m4t4t4_m34ns_n0_w0rr13s}
```
("hakuna matata" = no worries - a nod to the mountain/lion theme.)
