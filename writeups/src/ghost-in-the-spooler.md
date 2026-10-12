# Ghost in the Spooler

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{e24d16be9d731cba}`

---

Artifacts: `FP02CF4.SHD` (520 B), `FP02CF4.SPL` (1872 B), `scan.png` (2550×3300). A workstation was imaged and three print-spooler leftovers survived; a scanner holds a scan of the printed page. The flag is built from three recovered values: `flag = isfcr{ sha256(username + "|" + serial + "|" + timestamp)[:16] }`, timestamp formatted `YYYY-MM-DDTHH:MM:SSZ`.

**Username:** `FP02CF4.SHD` is a Windows spooler shadow file - a small header whose 32-bit fields are byte-offsets into a trailing UTF-16LE string table. The job owner field resolves to **`j.holbrook`**. The originating machine is `FIN-WKS-014`, printer `Xerox DocuColor 12 PS` shared as `\\PRINT01\HR-DocuColor-12`. The `.SPL` (EMF format) confirms the page content but yields no device id.

**Timestamp:** the 8-byte FILETIME at `.SHD` offset `0x40` is `0x01db090f0de78e00` - 100ns intervals since 1601-01-01 UTC, converting to **`2024-09-17T14:37:00Z`**.

**Printer serial:** `scan.png` carries a very faint repeating pattern in pale yellow ink - the classic **Xerox DocuColor "yellow dots" / Machine Identification Code (MIC)**. Isolating the yellow ink yields a 15×8 dot matrix tile repeating every 300px on a 9px grid. Decoding per the EFF DocuColor Tracking Dot Decoding Guide (column-parity row, row-parity column, 7-bit-per-column bytes): minute=37, hour=14, day=17, month=9, year=24 (2024) - matching the SHD FILETIME exactly, proving the page came from that machine - and the remaining serial digits read **`8842013`**. The extraction was cross-checked against the EFF guide's own worked example.

```python
import hashlib
u, s, ts = "j.holbrook", "8842013", "2024-09-17T14:37:00Z"
print("isfcr{%s}" % hashlib.sha256(f"{u}|{s}|{ts}".encode()).hexdigest()[:16])
isfcr{e24d16be9d731cba}
```
