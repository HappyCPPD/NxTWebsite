# Echoes of the Snap

**Event:** ByteMe CTF 26
**Category:** forensics
**Points:** 200
**Flag:** `OWASP{3ch03s_0f_th3_sn4p_r3m41n}`

---

**Description:** "A network capture contains several streams, but one
contains fragmented DNS TXT data carrying a hidden message."

Attachment: `capture.txt` (136 bytes)

## Walkthrough

The only artifact provided is `capture.txt`, a plain-text summary rather
than a real pcap:

```
NETWORK CAPTURE SUMMARY
stream 31: DNS TXT query
stream 31 TXT chunks:
4f574153507b3363683033735f30665f7468335f736e34705f72336d34316e7d
```

The description calls out a specific stream (31) and an "Xxx" TXT chunk
field. The value is a hex-encoded blob (even-length, only `[0-9a-f]`) that
maps directly onto readable ASCII. Decoding the hex yields the flag:

```
4f 57 41 53 50 7b 33 63 68 30 33 73 5f 30 66 5f 74 68 33 5f 73 6e 34 70 5f 72 33 6d 34 31 6e 7d
 O  W  A  S  P  {  3  c  h  0  3  s  _  0  f  _  t  h  3  _  s  n  4  p  _  r  3  m  4  1  n  }
```

The decoded text `3ch03s_0f_th3_sn4p_r3m41n` reads as leetspeak for "echoes
of the snap remain" - matching the challenge title.

## Solution

Reproducible one-liner:

```bash
printf '%s' "4f574153507b3363683033735f30665f7468335f736e34705f72336d34316e7d" | xxd -r -p
```

Or run the bundled `solve.sh`, which parses the hex straight out of
`capture.txt`.

## Key takeaway

Hex is the most common encoding for DNS TXT exfil payloads. Look for long
even-length `[0-9a-f]` runs and pipe them through `xxd -r -p` (or CyberChef
"From Hex").
