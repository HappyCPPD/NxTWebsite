# Memory Liar

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{dk0m_unl1nk_3pr0c3ss_l1st_cr0ss_ch3ck_7c3a9f}`

---

**Flag:** `hiCTF{dk0m_unl1nk_3pr0c3ss_l1st_cr0ss_ch3ck_7c3a9f}`

## Files
- `memory-liar.zip` → `extracted/memory.raw` (16 MB, `data`, sha256 `3d3e5b2c5f379ead57d57382ec103b60b69ed66d1270656f1889585e95b2a749`)
- `extracted/region3.bin` (384 KB) - the live region of the dump
- `extracted/carved.exe` (PE32) - a padding-shifted copy of the same blocks

## Analysis

The image is 16 MB of mostly zero padding; a 64 KB-block non-zero scan localises the only live
region at `0x300000` - `0x35FFFF` (mirrored into `region3.bin`). No Volatility profile support was
needed - this is a synthetic image.

1. **Region map** - all data lives at `0x200000..0x35FFFF`; the rest is zeros.
2. **Decoy confirmed** - the "clean audit" log block is bait and self-describes as fake:
   ```
   [CONFIDENTIAL - ENDPOINT INCIDENT LOG]
   Host Audit: SEC-2026-10-19-094
   Status: System integrity validated. No hidden tasks or hooks found.
   Forensics Verification Token: hiCTF{th1s_1s_4_f4k3_d3c0y_fl4g_f0r_n00bs_883a1c}
   ```
   The "process list" only holds textbook built-ins:
   `System, smss.exe, csrss.exe, wininit.exe, services.exe, lsass.exe, svchost.exe, svchost.exe, explorer.exe, notepad.exe`.
3. **Hidden process (DKOM)** - grepping all `*.exe` names in the raw image surfaces one name that is
   **not** in the enumerated list:
   ```
   winxnet.exe   @ 0x35D174
   ```
   A DKOM rootkit unlinks the process's `EPROCESS` from `ActiveProcessLinks`, so every tool that
   walks `PsActiveProcessHead` (including the "clean" audit) misses it even though the process is
   still resident - hence "cross-check the process list" against an independent source (pool scan /
   raw byte scan). Technique marker + C2 in the image:
   ```
   ROOT9                    @ 0x35F000   (tag: DKOM rootkit)
   c2.darkshadow-apt.org:8443
   OP_SHADOW_LIAR_ACTIVE
   ```
4. **Recover the flag** - a record at `0x35F000`: tag `ROOT9`, then flags `05`, XOR key `5D`,
   length `0x33`, then 51 bytes of single-byte-XOR ciphertext. Key is stored in the clear; validated
   on the `hiCTF{` prefix (`0x35^0x5D='h'`, `0x34^0x5D='i'`, `0x1e^0x5D='C'`...).

## Commands
```bash
# region map (find live regions)
python3 -c "d=open('extracted/memory.raw','rb').read();
[print(hex(o),sum(1 for b in d[o:o+0x10000] if b)) for o in range(0,len(d),0x10000) if sum(1 for b in d[o:o+0x10000] if b)>64]"

# hidden process vs. fake audit list
grep -aoE '[A-Za-z0-9_]+\.exe' extracted/memory.raw | sort -u   # winxnet.exe stands out

# decode ROOT9 record (key 0x5D stored at header offset 9)
python3 -c "
d=open('extracted/memory.raw','rb').read(); i=d.find(b'ROOT9')
ct=d[i+16:i+16+51]
print(bytes(b^0x5D for b in ct).decode())"
# -> hiCTF{dk0m_unl1nk_3pr0c3ss_l1st_cr0ss_ch3ck_7c3a9f}
```

## Flag
`hiCTF{dk0m_unl1nk_3pr0c3ss_l1st_cr0ss_ch3ck_7c3a9f}`

Decoy (do not use): `hiCTF{th1s_1s_4_f4k3_d3c0y_fl4g_f0r_n00bs_883a1c}`
