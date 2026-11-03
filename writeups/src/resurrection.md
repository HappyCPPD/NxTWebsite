# RESURRECTION (Operation Eclipse Void)

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{p3_0v3rl4y_71m3d473574mp_k3y_n7f5_runl157_cl5_g30m37ry_7r4ns4c710n_n4n0_f1l371m3_3v7x_b1n4ry_xml_70k3n5_b17m4p_orph4n_v01d_r35urr3c710n}`

---

**Category:** forensics · 1 GiB NTFS image (scorched geometry)
**Flag:**

    hiCTF{p3_0v3rl4y_71m3d473574mp_k3y_n7f5_runl157_cl5_g30m37ry_7r4ns4c710n_n4n0_f1l371m3_3v7x_b1n4ry_xml_70k3n5_b17m4p_orph4n_v01d_r35urr3c710n}

Length 142, one `{` / one `}` - a clean, self-consistent flag.

---

## The one insight that solves it

Every recovered segment has the shape **`<ordinal-tag>--<leet-technique>_`**, e.g.
`53c0nd--n7f5_runl157_cl5_g30m37ry_`. The challenge note says *"Each recovered phase
reveals an ordinal identifier tag. Concatenate all five payload segments in order."*

The **ordinal tag is an ordering label, NOT flag bytes.** It is stripped before
concatenation - exactly the convention the author uses in the sibling challenge
**TESSERA** (its labels `1ist-----`, `--s32nd--`, `iiiiiiiiiii-3hird---` are
discarded, and its part-1 literal begins with the flag's own `hiCTF{`).

That explains the parts that look like anomalies:
* part-1's decoded overlay contains a literal `hiCTF{` → it is simply the **flag
  opener**, sitting right after the `f!r5t--` label (author's house style).
* part-5's payload ends in `}` → it is the **flag closer**.
* part-3 decodes as `th1jd…` (`j` where the ordinal wants `r`) - **irrelevant**, the
  whole `th1jd--` token is the label and is thrown away.

So: `flag = hiCTF{ p1 p2 p3 p4 p5 }`, where `pi` = segment `i` with its `<ord>--`
label removed.

The three challenge "silent spaces" map onto the five channels: **Shattered-Geometry**
= PE-overlay (1) + NTFS runlist (2); **Chrono-Echoes** = TxR filetime (3) + evtx (4);
**Unmapped-Voids** = $Bitmap orphans (5).

## The five channels (one per phase)

| # | ordinal label (strip) | channel (inode) | encoding | payload kept |
|---|---|---|---|---|
| 1 | `f!r5t` | `Windows/System32/kbdusx.dll` (179) - PE32+ stub, 42-byte overlay | `overlay[i] XOR TimeDateStamp_LE[i%4]` (`0x65ec8580` → `80 85 ec 65`) | `hiCTF{p3_0v3rl4y_71m3d473574mp_k3y_` |
| 2 | `53c0nd` | `Confidential_Q3` dir (111) - bogus 11 MB `$DATA` | each run-list **run-length byte** = one ASCII char | `n7f5_runl157_cl5_g30m37ry_` |
| 3 | `th1jd` | `Windows/System32/config/TxR/tx_journal.log` (181) | 34 `tx_NN.db` entries; planted FILETIME at name+52; `char[0]=(ft[0]%1e7)-0x2700`, `char[i]=(ft[i]-ft[i-1])-0x2700` | `7r4ns4c710n_n4n0_f1l371m3_` |
| 4 | `f01_1rth` | `Windows/System32/winevt/Logs/Security_Audit.evtx` (193) | ASCII in byte[1] of each little-endian dword (`00 XX 00 00`), stride 4 | `3v7x_b1n4ry_xml_70k3n5_` |
| 5 | `51f7h` | `$Bitmap` (6) | length of each contiguous **free** cluster run, **+1**, as ASCII | `b17m4p_orph4n_v01d_r35urr3c710n}` |

## Image quick facts
MBR + primary GPT + primary NTFS boot sector zeroed ("scorched"); the **backup** VBR
(`0x3FDFFE00`) and backup GPT (`0x3FFFFE00`) survive. NTFS starts at `0x1000000`.
Work on `work/fixed.raw` (primary VBR restored from the backup) with `fls/icat -o 32768`.
Only three non-zero regions: metadata/file area ~16 - 26 MB, `$LogFile` @`0x15A88000`,
`$MFT` @`0x15F55000`, plus backup VBR/GPT. Many "files" (hives, kernel32/ntdll/svchost.dll,
prefetch, audit_*.xlsx) are high-entropy **decoys** with fake magic.

## Repro
```bash
cd work
# part1 — ino 179 (kbdusx.dll) PE overlay XOR TimeDateStamp
python3 - <<'E'
import struct,subprocess
d=subprocess.run(['icat','-o','32768','fixed.raw','179'],capture_output=True).stdout
e=struct.unpack('<I',d[0x3c:0x40])[0]; key=struct.pack('<I',struct.unpack('<I',d[e+12:e+16])[0])
ov=d[0x400:0x42a]
print(bytes(ov[i]^key[i%4] for i in range(42)).decode())
E
python3 runlen_all.py | grep 111      # part2  -> 53c0nd--... (run lengths)
# part3 — ino 181 (TxR journal) FILETIME deltas -0x2700
python3 - <<'E'
import subprocess,re,struct
d=subprocess.run(['icat','-o','32768','fixed.raw','181'],capture_output=True).stdout
pos=[m.start() for m in re.finditer(b't\x00x\x00_\x00',d)]
fts=[struct.unpack('<Q',d[p+52:p+60])[0] for p in pos][:33]
o=[(fts[0]%10_000_000-0x2700)&0xff]+[((fts[i]-fts[i-1])-0x2700)&0xff for i in range(1,len(fts))]
print(bytes(o).decode('latin1'))
E
# part4 — ino 193 (Security_Audit.evtx): byte[1] of each LE dword, stride 4
icat -o 32768 fixed.raw 193 | python3 -c "import sys;d=sys.stdin.buffer.read();s=bytes(d[i] for i in range(1,len(d),4));i=s.find(b'f01_1rth');print(s[i:i+34].split(b'\0')[0].decode())"
python3 bitrun.py                     # part5 -> 51f7h--... (free runs +1)
```

## Assembly
```
ordinals : f!r5t  53c0nd  th1jd  f01_1rth  51f7h      (ordering tags -> discard)
payloads : hiCTF{p3_0v3rl4y_71m3d473574mp_k3y_   (channel 1, opener)
           n7f5_runl157_cl5_g30m37ry_
           7r4ns4c710n_n4n0_f1l371m3_
           3v7x_b1n4ry_xml_70k3n5_
           b17m4p_orph4n_v01d_r35urr3c710n}       (channel 5, closer)
flag     : hiCTF{ <payload1..5 concatenated> }
```
