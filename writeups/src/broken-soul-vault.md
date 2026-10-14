# Broken Soul Vault

**Event:** ByteMe CTF 26
**Category:** forensics
**Points:** 100
**Flag:** `OWASP{br0k3n_s0ul_v4ult_r3c0v3r3d}`

---

- Event: ByteMe CTF 26 (OWASP PCCOE, Pune) - 09 Oct 2026
- Category: Forensics
- Difficulty: Easy (100 pts)
- Author: Pratik Jadhav
- Flag format: `OWASP{...}`

## Flag

```
OWASP{br0k3n_s0ul_v4ult_r3c0v3r3d}
```

## Description

> The Soul Vault suffered metadata corruption during a recovery operation.
> Identify the valid recovered block and decode its contents.

## Attachments

- `metadata.bin.txt` (87 bytes)
- `vault.log` (133 bytes)

## Walkthrough

### 1. Read the vault log

`vault.log` describes the failed recovery session:

```
OPEN vault
AUTH keeper
READ /soul/fragment
ERROR checksum mismatch
RECOVER block=17
RECOVER block=18
NOTE corrupted metadata follows
```

Two blocks were pulled from the vault (17 and 18); the log warns the
metadata that follows is corrupted. The task is to pick the *valid* recovered
block and decode it.

### 2. Inspect the metadata

`metadata.bin.txt` is plain text despite the `.bin` name - always verify with
`file` / `xxd` first:

```
00ff11aa
4f574153507b6272306b336e5f7330756c5f7634756c745f7233633076337233647d
deadbeef
```

Line 1 (`00ff11aa`) and line 3 (`deadbeef`) are the block guard/delimiter
values; the middle line is the recovered block payload stored as ASCII hex.

### 3. Decode the payload

Hex-decode the middle line:

```
4f 57 41 53 50 7b 62 72 30 6b 33 6e 5f 73 30 75 6c 5f 76 34 75 6c 74 5f 72 33 63 30 76 33 72 33 64 7d
 O  W  A  S  P  {  b  r  0  k  3  n  _  s  0  u  l  _  v  4  u  l  t  _  r  3  c  0  v  3  r  3  d  }
```

This yields a well-formed flag, confirming it is the valid recovered block:

```
OWASP{br0k3n_s0ul_v4ult_r3c0v3r3d}
```

The plaintext reads "broken soul vault recovered", matching the challenge
story and the challenge name (Broken-Soul-Vault).

### 4. Automate it

`solve.py` performs the same steps (parse the lines, hex-decode each candidate,
validate against the `OWASP{...}` pattern):

```
python3 solve.py metadata.bin.txt
[*] metadata lines: ['00ff11aa', '4f574153507b6272306b336e5f7330756c5f7634756c745f7233633076337233647d', 'deadbeef']
[*] block 4f574153... -> OWASP{br0k3n_s0ul_v4ult_r3c0v3r3d}

[+] FLAG: OWASP{br0k3n_s0ul_v4ult_r3c0v3r3d}
```

## Key takeaways

- A `.bin` extension does not mean binary - check with `file` / `xxd`.
- "Corrupted metadata + valid block" prompts usually mean: parse the container,
  validate each candidate against the flag format, and keep the one that fits.
- Hex-dumping the guard values (`00ff11aa`, `deadbeef`) shows they are
  sentinels, not data - the only decodable payload is the middle line.

