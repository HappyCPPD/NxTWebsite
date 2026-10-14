# Soul Memory

**Event:** ByteMe CTF 26
**Category:** forensics
**Points:** 100
**Flag:** `OWASP{s0ul_m3m0ry_n3v3r_d13s}`

---

- Event: CTF7 (Byteme 2026)
- Category: Forensics
- Author: Pratik Jadhav
- Points: 100 (Easy)
- Solves: 96
- Flag format: `OWASP{...}`

## Flag

```
OWASP{s0ul_m3m0ry_n3v3r_d13s}
```

## Challenge

> A memory dump from a Soul Vault process contains traces of a recovered
> fragment. Find the hidden information inside the process data.

Attachment: `memory_dump.txt` (148 bytes).

## Analysis

Despite the "memory dump" framing, the attachment is a small plain-text
`PROCESS MEMORY EXTRACT` - not a raw hex/core dump. So no volatility /
binwalk / strings-on-binary stage was needed; a single read reveals the whole
structure.

```
PROCESS MEMORY EXTRACT
pid=4041
module=soul-cache
user=keeper
cache_key=MEMORY_7
vault_hint=look_after_cache_key
data=OWASP{s0ul_m3m0ry_n3v3r_d13s}
```

The file is a key=value list. The `vault_hint=look_after_cache_key` line is
a decoy nudging you to hunt for hidden data after `cache_key=MEMORY_7`, but
the actual secret is simply carried in the `data=` field on the next line.

## Extraction

One-liner:

```bash
grep -o 'OWASP{[^}]*}' memory_dump.txt
# OWASP{s0ul_m3m0ry_n3v3r_d13s}
```

## Takeaway

The `data=` line held the flag in cleartext. The `vault_hint` text is a
rabbit hole; the real trick is just reading the process-extract artifact
end-to-end. Flag: `OWASP{s0ul_m3m0ry_n3v3r_d13s}`.

