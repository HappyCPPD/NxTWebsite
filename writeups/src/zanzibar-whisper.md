# Zanzibar Whisper

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{sp1c3_1sl4nd_s3cr3ts}`

---

**Category:** stego · **Artifact:** `extracted/zanzibar_whisper.jpg` (1024x683 JPEG)

## Hint
> "A mysterious image from the shores of Zanzibar … a whisper from the Spice Island."

## Solve
The JPEG carries a steghide payload with **no passphrase**:

```bash
steghide extract -sf zanzibar_whisper.jpg -p '' -xf zan.txt
cat zan.txt
```

## Flag
```
hiCTF{sp1c3_1sl4nd_s3cr3ts}
```
