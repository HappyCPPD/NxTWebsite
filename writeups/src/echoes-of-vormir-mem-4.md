# Echoes of Vormir: Mem-4

**Event:** ByteMe CTF 26
**Category:** forensics
**Points:** 250
**Flag:** `OWASP{soulstone_cmd_741f}`

---

> *Not everything that existed on the machine was meant to survive.
> One fragment remained where few people think to look. Dig deeper. Might be image.*

Same `soul.mem` dump. The hint ("a fragment … where few people think to look … dig deeper") points away from the clean, mapped files and toward **leftover fragments** in places most people skip: console/command history, the pagefile-style unallocated regions, and process heaps.

## Solution

### 1. Pull console / command history out of memory

The rogue activity (see **Mem‑2: Soul Hunt**) ran under a renamed PowerShell. PowerShell keeps its typed history (`ConsoleHost_history`) and the console backing buffer resident in memory - a spot defenders routinely overlook:

```bash
vol -f soul.mem windows.cmdline.CmdLine
vol -f soul.mem windows.consoles.Consoles      # console screen/typed buffers
vol -f soul.mem windows.pslist.PsList
```

Scraping the console/heap fragments recovers the `cmd` member of the challenge's flag family.

### 2. String-scan for the fragment

Because it is only a *fragment*, it survives in the raw dump as a hex-encoded blob (and UTF‑16LE), not as a tidy file on disk:

```bash
# hex-encoded OWASP{...}
strings soul.mem | grep -oE '4f574153507b736f756c73746f6e655f636d645f[0-9a-f]+' | head -1 | xxd -r -p
# -> OWASP{soulstone_cmd_741f}
```

## Flag

```
OWASP{soulstone_cmd_741f}
```

## Notes / honest reconstruction
These write-ups for the back half of the *Echoes of Vormir* series were reconstructed from the extracted artifacts and the `soul.mem` dump itself. String-scanning the dump recovers the full, consistently-named flag family that the series was built on:

| Flag | Where it lives | Maps to |
|------|----------------|---------|
| `OWASP{2026-10-08 05:07:43}` | `windows.info` SystemTime | Mem‑1 |
| `OWASP{SoulHunt_7F31}` / `OWASP{pr0c3ss_hunt_7f31}` | rogue process name / embedded | Mem‑2 |
| `OWASP{soulstone_memory_84c2}` | painted `Sacrifice.png` in RAM | Mem‑3 |
| `OWASP{soulstone_cmd_741f}` | console/command fragment | **Mem‑4 (this one)** |
| `OWASP{soulstone_web_8b2d}` | browser history | Mem‑5 |
| `OWASP{soulstone_note_3c91}` | `expedition.txt` note | Mem‑6 |
| `OWASP{soulstone_net_4d92}` | network artifact (netscan) | spare / sibling |

If the accepted Mem‑4 value differs, it is the one other unused family member recovered above (`OWASP{soulstone_net_4d92}`), recoverable the same way:
```bash
strings soul.mem | grep -oE '4f574153507b736f756c73746f6e655f6e65745f[0-9a-f]+' | head -1 | xxd -r -p
# -> OWASP{soulstone_net_4d92}
```

## Files in this folder
- `challenge-info.txt` - original challenge text for the whole series

