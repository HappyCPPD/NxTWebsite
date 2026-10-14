# Red Skull's Trail

**Event:** ByteMe CTF 26
**Category:** osint
**Points:** 100
**Flag:** `OWASP{PhantomSoul}`

---

## Flag

```
OWASP{PhantomSoul}
```

## Solution

### 1. Google Drive File

The challenge provides a Google Drive link to `riddle - Hrishikesh More.txt`:

> The Soul Stone was supposed to be returned to its resting place on Vormir-616, but the record says different!!!
> Investigate who was the user.
> Remember, only Red skull can lead you to your destination.
> Only worthy one will be able to get the stone back.

Key clue: **Vormir-616** is a username to search for.

### 2. GitHub Repo

Searching GitHub for `Vormir-616` leads to: https://github.com/Vormir-616/Missing-Record

The repo contains `README.md`, `RECORD1` - `RECORD6`, and 21 commits.

Records 1, 2, 4, and 5 each name a user who returned the stone (`soulkeeper`, `vormir_watcher`, `echoofvormir`, `soulbound`). **RECORD3** was tampered with - git history shows it originally said "RECOVERED" but was changed to "UNRECOVERED" with the note "Find the user of the stone." The username was removed.

### 3. RECORD6 - Hidden Image

Git history reveals RECORD6 was originally uploaded as `soul_stone.png`, then renamed through several steps:

![RECORD6 as recovered from the repository](../images/writeups/red-skulls-trail-record6.jpg "420x420")

```
soul_stone.png → Nothing_suspicious.png → Nothing_suspicious.md → Nothing_suspicious → RECORD6
```

The file is still a valid PNG image (1254x1254).

### 4. Steganography - Trailer Data

Running `exiftool` on the PNG shows:

```
Warning: [minor] Trailer data after PNG IEND chunk
```

Extracting the bytes after the IEND chunk:

```python
data = open('RECORD6', 'rb').read()
iend = data.find(b'IEND')
trailer = data[iend+8:]
print(trailer)  # b'UGhhbnRvbVNvdWw=\n'
```

Base64 decoding:

```
echo "UGhhbnRvbVNvdWw=" | base64 -d
# PhantomSoul
```

**PhantomSoul** is the missing user from RECORD3 - the one connected to the Soul Stone.

## Tools Used

- Google Drive (view riddle)
- GitHub (repo + commit history)
- `git log`, `git show`, `git diff` (inspect tampered records)
- `exiftool` (detect trailer data in PNG)
- `base64 -d` (decode hidden string)

