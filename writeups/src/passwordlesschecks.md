# PasswordlessChecks

**Event:** October 2026 MetaCTF Flash CTF
**Category:** forensics
**Flag:** `MetaCTF{Nbu8W32GsvbSNSNS}`

---


## 1. What the artifacts are

`passwordless-checks.zip` ships two files:

- `NotAGame.exe` - an InstallShield CAB that installs an **RPG Maker VX** game
  (RGSS202E), title "NamingSimulator".
- `capture.pcapng` - a USBPcap trace of an **Xbox controller** (VID:PID `045e:0b12`,
  GIP protocol): 484 frames, 205 input reports.

The game is a joke wrapper: it exists only to *type something in*, and the pcap is the
recording of the controller typing it.

## 2. Extract and read the game

`NotAGame.exe` unpacks (InstallShield) to a VX project. `Game.rgss2a` is **RGSSAD v1**:

- magic key `0xDEADCAFE`, running key `k = k*7 + 3 (mod 2^32)`
- data XORed with the key's 4 little-endian bytes, advancing every 4 bytes
- **gotcha:** v1 has *no stored offset field* - a file's data follows its size field
  contiguously (a parser that assumes an offset reads one giant "file")

Decoding it yields `Data/*.rvdata`. `Data/Scripts.rvdata` decodes to 97 Ruby scripts. The
game is **stock RPG Maker VX** except `Map001`, which has exactly one command:

```
Name Input Processing (code 303), params [1, 16]   # actor 1, max 16 chars
```

So the whole game is: type a 16-character name on the stock VX character grid. The stock
VX `Window_NameInput` grid is:

```
A B C D E a b c d e
F G H I J f g h i j
K L M N O k l m n o
P Q R S T p q r s t
U V W X Y u v w x y
Z           z
(blank row)
1 2 3 4 5
6 7 8 9 0       _OK        # OK button = index 89
```

## 3. Decode the controller, replay the input

In the GIP input reports the **buttons word is at bytes 4-5**:

| bit | button |
|------|--------|
| 0x10 | A |
| 0x40 | X |
| 0x100 / 0x200 / 0x400 / 0x800 | Up / Down / Left / Right |

Replaying the 88 button events through the VX name-grid state machine (cursor moves ±10
for U/D and ±1 for L/R with the game's wrap rules; **X confirms the current cell's char**)
produces the 16-character string - which fills `max_char` exactly and is the flag body.

## 4. Solve (sketch)

```python
# 1. tshark is AppArmor-blocked under ~/Downloads -> copy the pcap to /tmp first.
#    $ cp capture.pcapng /tmp/ && cd /tmp
#    $ tshark -r capture.pcapng -T fields -e usb.capdata > cap.txt

import struct, itertools
rows = [list('ABCDEabcde'), list('FGHIJfghij'), list('KLMNOklmno'),
        list('PQRSTpqrst'), list('UVWXYuvwxy'), list('Z    z    '),
        list('          '), list('12345     '), list('67890') + list('    ') + ['OK']]
T = [c for r in rows for c in r]                      # grid, OK at index 89

seq, prev = [], None
for line in open('cap.txt'):
    b = bytes.fromhex(line.strip())
    if len(b) >= 6 and b[0] == 0x20:                  # GIP input report from 2.4.2
        btn = struct.unpack_from('<H', b, 4)[0]
        if btn and btn != prev:
            seq.append(btn)
        prev = btn

U, D, L, R = 0x100, 0x200, 0x400, 0x800
def move(bit, i, wrap):
    if bit == D: return i + 10 if i < 80 else (i - 80 if wrap else i)
    if bit == U: return i - 10 if i >= 10 else (i + 80 if wrap else i)
    if bit == R: return i + 1 if i % 10 < 9 else (i - 9 if wrap else i)
    if bit == L: return i - 1 if i % 10 > 0 else (i + 9 if wrap else i)

for wrap in (True, False):
    idx, out = 0, []
    for btn in seq:
        if btn in (U, D, L, R): idx = move(btn, idx, wrap)
        elif btn == 0x40: out.append(T[idx])          # X = confirm
    print(wrap, ''.join(out))
```

Output:

```
MetaCTF{Nbu8W32GsvbSNSNS}
```

## 5. Gotchas

1. `tshark` is AppArmor-confined under `/home/...` - copy the pcap to `/tmp` to read it.
2. RGSSAD **v1** has no stored offset field (see §2) - the classic parser bug here.
3. `wine` + `Xvfb` was used to validate the game logic against the real engine (the bundled
   `umeplus` font matters for the exact grid).

## 6. Flag

```
MetaCTF{Nbu8W32GsvbSNSNS}
```
