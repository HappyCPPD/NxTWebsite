# Echoes of Vormir: Mem-6

**Event:** ByteMe CTF 26
**Category:** forensics
**Points:** 250
**Flag:** `OWASP{soulstone_note_3c91}`

---

> *The final record. The expedition ends when the last note is found.*

Same `soul.mem` dump. This is the last artifact in the series - a small text "note" that was left on the machine (the *Vormir Expedition Log*).

## Solution

### 1. Carve the note

A small mapped text file (`expedition.txt`) is present in memory:

```bash
vol -f soul.mem windows.filescan.FileScan | grep -i expedition
vol -f soul.mem windows.dumpfiles.DumpFiles --virtaddr 0xdb0f7a385e00   # expedition.txt
```

### 2. Read it

```
Location: Vormir
Status: incomplete

Artifact reference:
4f574153507b736f756c73746f6e655f6e6f74655f336339317d

The trail ends with this record.
...
— Vormir Expedition Log
```

The "Artifact reference" is a hex string.

### 3. Decode the hex

```bash
echo 4f574153507b736f756c73746f6e655f6e6f74655f336339317d | xxd -r -p
# -> OWASP{soulstone_note_3c91}
```

`4f 57 41 53 50 7b` = `OWASP{`, and the rest decodes to `soulstone_note_3c91}`.

## Flag

```
OWASP{soulstone_note_3c91}
```

## Files in this folder
- `expedition.txt` - the forgotten note carved from memory (contains the hex-encoded flag)
- `challenge-info.txt` - original challenge text for the whole series

