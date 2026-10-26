# ShellBreach

**Event:** SolarCTF
**Category:** forensics
**Flag:** `SOLARCTF{sh3llb4g_m4nual_pars1ng_is_th3_w4y}`

---

**Flag:** `SOLARCTF{sh3llb4g_m4nual_pars1ng_is_th3_w4y}`

## TL;DR

`solar_forensic.zip` → `disk.vhd` (dynamic VHD) → NTFS volume `EVIDENCE`.
Everything visible is decoy except **one NTFS alternate data stream**:
`Documents/SolarGrid/Reports/report_q3.xlsx:metadata` (44 bytes, resident in
MFT record 64). It is XOR-encrypted with the repeating 6-byte key
`aa bb cc 11 22 33` - which is the *unique half of the drop_link.lnk
TrackerDataBlock Droid/ObjectID* (the "unique bytes" that differ between the
synthetic LNKs). XOR → flag.

## Walkthrough

1. **Unpack the VHD.** `unzip solar_forensic.zip` → `disk.vhd`. It is a
   *dynamic* Microsoft VHD (`conectix` footer, dynamic header cookie
   `cxsparse` at offset 512, `dataOffset=0xFFFFFFFFFFFFFFFF` = dynamic,
   64 MiB virtual, 2 MiB block size). Convert with
   `qemu-img convert -f vpc -O raw disk.vhd disk.raw`.

2. **Parse the partition manually** (this is why "the IT tools were failing" -
   nothing is corrupt, it just needs a raw read):
   - MBR at 0, partition 1 starts at sector 128 (`offset=65536`), type 0x07,
     128 896 sectors (~62.9 MiB).
   - `dd if=disk.raw of=part.ntfs bs=512 skip=128 count=128896`.
   - NTFS boot sector at `part.ntfs+0x0`: 512 B/sector, 8 sectors/cluster
     (4 KiB), MFT at LCN 5370, volume label **EVIDENCE**.

3. **Filesystem contents** (`ntfsls`/`tsk_recover` on `part.ntfs`):
   ```
   /Documents/Desktop/notes.txt              "Backup password: s0lar_backup!!"
   /Documents/Desktop/shortcuts/{jira,vpn}.lnk
   /Documents/Personal/todo.txt              "Export archive password: dr0pp3d_th3_k3y"
   /Documents/Personal/vacation_2024.jpg     1x1 JPEG, decoy
   /Documents/SolarGrid/Designs/{panel_v2_draft,panel_v3_final}.pdf  decoy
   /Documents/SolarGrid/Designs/specs_2024.xlsx                      decoy
   /Documents/SolarGrid/Export/{backup_config,drop_link,old_server,shared_drive}.lnk
   /Documents/SolarGrid/Meetings/{notes_{jan,feb},standup_template}.docx  decoy
   /Documents/SolarGrid/Reports/report_q{1,2,3,4}*.{xlsx,docx}   q3 carries the ADS
   /ProgramData/Microsoft/Diagnosis/diag_perfmon.edb   SRUM DB (see below)
   /Users/d.korshunov/NTUSER.DAT                       fake hive = "dr0pp3d_th3_k3y" filler
   ```

4. **The decoys** (they exist to burn time):
   - `NTUSER.DAT` is *not* a registry hive (no `regf` magic): 12 288 bytes of
     `dr0pp3d_th3_k3y` repeated with ~28 % random byte substitutions plus a
     noisy 120-byte head. It just screams the todo.txt password at you.
   - `diag_perfmon.edb` is a real ESE database - an **SRUM**
     (`SruDbIdMapTable`, `{DD6636C4-...}` network-usage table with
     `BytesSent`/`BytesRecvd`). Its app-path table ends with two interesting
     entries:
     `C:\Users\d.korshunov\AppData\Local\Temp\AU3_setup.exe` and
     `C:\Users\d.korshunov\AppData\Local\Temp\solarsync.exe` - the exfil tool
     that did the network I/O. Story, not flag.
   - LNK files are syntactically valid and reveal the leak destinations:
     `\\192.168.50.10\drop\solar_docs` (drop_link), `\\10.0.0.5\backups\config`,
     `\\172.16.0.1\legacy\archive`, `\\fileserver\shared`.
   - `$Extend/$Deleted` (a non-standard directory the author added) has a
     64 KiB index allocation (LCN 38 - 53) that is fully zeroed, and MFT records
     16 - 23 / 73 - 255 are zeroed - the deleted folders/recycle-bin traces are
     genuinely wiped.

5. **ADS sweep** (the actual hiding place). Enumerate every named attribute in
   the MFT: only one exists -
   ```
   rec 64  report_q3.xlsx : $DATA "metadata"  resident, 44 bytes
   ```
   Dump it: `icat part.ntfs 64-128-4 > ads.bin`
   ```
   f9f480507070fefdb7624a00c6d7ae25456cc78fa264435ff5cbad635102c4dc9378516cded3ff4e5507d3c6
   ```

6. **Find the key.** The LNK `TrackerDataBlock`s (signature 0xA0000003) carry
   the standard MachineID + Droid/DroidBirth GUIDs. The 6-byte tail of each
   file's Droid ObjectID is a fabricated "unique" value:
   ```
   jira.lnk          000000000002
   vpn.lnk           000000000001
   backup_config.lnk deadbeef0001
   drop_link.lnk     aabbcc112233   <-- key
   old_server.lnk    525400123456
   shared_drive.lnk  001a2b3c4d5e
   ```
   (they look like MAC addresses / magic constants - a giveaway that they are
   deliberate).

7. **XOR** the 44 ADS bytes with `aa bb cc 11 22 33` repeated:
   ```python
   blob = bytes.fromhex("f9f4...d3c6")
   key  = bytes.fromhex("aabbcc112233")
   print(bytes(b ^ key[i % 6] for i, b in enumerate(blob)).decode())
   ```
   ```
   SOLARCTF{sh3llb4g_m4nual_pars1ng_is_th3_w4y}
   ```

## Notes / gotchas

- `qemu-img` handles the dynamic VHD fine; no need to reassemble blocks by hand.
  The 5 allocated 2 MiB blocks (0, 2, 9, 10, 31) map exactly onto QEMU's raw
  output - nothing is hidden in unallocated/phantom VHD blocks, and the 1 MiB
  tail after the NTFS partition is zero.
- NTFS volume spans clusters 0 - 16110; $Bitmap (LCN 5368) shows every non-zero
  cluster is owned by a live file, i.e. **no free-space carving candidates**;
  the deleted files were small (resident) and their records were zeroed.
- `ntfs-3g`/`ntfsls` on the *whole* `disk.raw` fails ("NTFS signature missing")
  because the FS starts at offset 65536 - always `dd` the partition first or use
  the sleuthkit (`fls`, `icat`) which read raw offsets.
- Only one name offset convention matters for the ADS: sleuthkit addresses it as
  `64-128-4` (inode-attrtype-attrindex).
