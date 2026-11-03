# GhostBus

**Event:** HICyberCon CTF 2026
**Category:** misc
**Flag:** `hiCTF{gh0st_bu5_uart_n0nc3_r3v3al_9c3f12}`

---

**Category:** Hardware / firmware crypto · `ghost_bus.zip` (sha256 `8ffeac83…`)

## Artifact
- `capture.csv` / `capture.vcd` - UART bus probe between the hub MCU and the secure element
- `flash_dump.bin` (1 MiB) - external SPI NOR (holds a recovery copy of the firmware + a sealed record)
- `firmware.elf` - MCU firmware
- `diagram.png`, below

![Bus diagram: maintenance tool to hub over UART2, hub to secure element over UART1, the AA 55 frame format, and the SPI NOR memory map with the sealed region at 0x6A000](../images/writeups/ghostbus-diagram.png "780x440")

## Method
1. **UART decode.** Frames are `AA 55 <len> <cmd> <payload> CRC16/Modbus`.
   The MCU's "hidden read" request is `len=0, cmd=0x10`; the secure element's
   reply is `len=0x10, cmd=0x10` carrying a fixed 16-byte **nonce** (it returns
   the same nonce every read - not a fresh random):

   ```
   nonce = 9e3b7a44c1d05f82a6e1b4907cd3f5a2
   ```

2. **Key derivation** (firmware, capstone): `key = SHA256(salt24 || nonce)[:16]`,
   with `salt24` from rodata `0x08000ca0`
   (`04325a9c117f3da0c0ffee5aa55a00ff1234567890abcdef`):

   ```
   key = 664ecd32a0a21d02a90afb1efb6919b1
   ```

3. **Open the sealed region.** External flash holds the sealed v2 record (48 B)
   at **offset 0x6A000** (the v1 record at 0x68000 is "rotated out" decoy). Main
   reads it, **byte-swaps each 4-byte word**, then AES-128-**CBC**-decrypts with
   `IV = nonce`, strips PKCS#7 and validates `hiCTF{…}`.

## Repro
```python
#!/usr/bin/env python3
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

nonce = bytes.fromhex("9e3b7a44c1d05f82a6e1b4907cd3f5a2")          # capture.csv (ch1, len=0x10)
salt  = bytes.fromhex("04325a9c117f3da0c0ffee5aa55a00ff1234567890abcdef")  # fw rodata 0x08000ca0
key   = hashlib.sha256(salt + nonce).digest()[:16]                 # 664ecd32a0a21d02a90afb1efb6919b1

flash = open("flash_dump.bin", "rb").read()
rec   = flash[0x6A000:0x6A000 + 48]
sw    = bytearray()
for i in range(0, 48, 4):                 # byte-swap each 32-bit word (little<->big)
    sw += rec[i:i+4][::-1]

pt = Cipher(algorithms.AES(key), modes.CBC(nonce)).decryptor().update(bytes(sw))
print(pt[:-pt[-1]].decode())             # strip PKCS#7
```
Output:
```
hiCTF{gh0st_bu5_uart_n0nc3_r3v3al_9c3f12}
```

## Verification
The decryption ends in **7 bytes of clean PKCS#7 padding** (`0x07 × 7`) and a
well-formed `hiCTF{…}` token - the padding is the structural oracle that the
key/IV/word-swap are correct (`IV = nonce` confirmed by the fact that only the
first CBC block was garbage otherwise).
