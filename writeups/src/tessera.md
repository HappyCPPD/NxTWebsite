# TESSERA

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{alpc_p0rt_c0lloquy_s35s10n_z3r0_syst3npr0f1l3_r3p4r53_buff3r_vort3x}`

---

**Flag:** `hiCTF{alpc_p0rt_c0lloquy_s35s10n_z3r0_syst3npr0f1l3_r3p4r53_buff3r_vort3x}`

Artifact: `evidence/` - an **extracted Windows file tree** (not a raw image), with the
materialised NTFS metadata as plain files under `[SYSTEM]/` (`$MFT` 306 MB,
`$LogFile` 64 MB, `$Bitmap` 2.5 MB). No TSK/volume offset needed.

Riddle mapping (as resolved):
- *"Sub-rosa whispers transversed the local interstice through an unmapped portico"* → **ALPC port** colloquy (`alpc_p0rt_c0lloquy`).
- *"ephemeral colloquy where disparate entities conjoined in silence"* → **Session 0 / SYSTEM** profile (`s35s10n_z3r0_syst3npr0f1l3`).
- *"prime fracture unbinds the isolated, sightless sanctum, whose lingering phantom subsequently redirects reality itself"* → a **$REPARSE_POINT** buffer injected into a phantom directory (`r3p4r53_buff3r_vort3x`).

The three parts were **self-describing** - each carries a leet ordinal label
(`1ist` / `s32nd` / `3hird`) that is an ordering tag, **not** flag bytes.

---

## Channel 1+2: PowerShell ScriptBlock logging (the whole attacker script)

`Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx`

The evtx stores the full attacker script as **UTF-16** XML text, so `grep -rlia hiCTF`
and every ASCII scan miss it (`h\0i\0C\0T\0F\0{`). The file also mixes UTF-16LE and
UTF-16BE chunks, so a plain `decode('utf-16le')` misses half. Endianness-agnostic
recovery:

```python
d = open(evtx,'rb').read()
s = d.replace(b'\x00', b'').decode('latin-1')   # strips NULs -> ASCII of BOTH endiannesses
```

Extracted script literals (exact, from the artifact bytes):

```
FlagPart1    = "1ist-----hiCTF{alpc_p0rt_c0lloquy_"
FlagPart2    = "--s32nd--s35s10n_z3r0_syst3npr0f1l3_"
Flag3_Raw    = "iiiiiiiiiii-3hird---r3p4r53_buff3r_vort3x}"
SecretKey    = "T3ss3r4_K3y_8819472MasterSecret!"
IV_HEX       = "101112131415161718191a1b1c1d1e1f"
TargetDir    = "C:\ProgramData\Microsoft\Diagnosis\ETLLocalStore"
Schema       = "NTFS_REPARSE_STREAM_LOCATOR"
EntropyStr   = "TesseraEntropy_99"
```

Intermediate token values after stripping the ordinal labels:

| part | label (discard) | payload kept |
|------|-----------------|--------------|
| 1 | `1ist-----` | `hiCTF{alpc_p0rt_c0lloquy_` |
| 2 | `--s32nd--` | `s35s10n_z3r0_syst3npr0f1l3_` |
| 3 | `iiiiiiiiiii-3hird---` | `r3p4r53_buff3r_vort3x}` |

Concatenation: `hiCTF{alpc_p0rt_c0lloquy_` + `s35s10n_z3r0_syst3npr0f1l3_` + `r3p4r53_buff3r_vort3x}`.

---

## Channel 1 (independent corroboration): XOR 0x5A ETL payload

`Windows/System32/LogFiles/WMI/AuditDiagTrace.etl` (16384 bytes) stores a `HEX=<...>`
string (UTF-16). Decode hex and XOR each byte with `0x5A`:

```
HEX= 6B33292E77777777773233190E1C213B362A39052A6A282E05396A...  ^0x5A
 ->  1ist-----hiCTF{alpc_p0rt_c0lloquy_||TargetService:DiagTrackSvcAux
```

Independent confirmation of part 1 (the log literal is authoritative).

## Channel 2 (corroboration): registry-configured service

`config/SYSTEM` → `\ControlSet001\Services\DiagTrackSvcAux\Parameters`:
`ServiceVault` → `…\systemprofile\…\Caches\cpinforev.dat`, `EntropyToken` =
base64 of `TesseraEntropy_99`. The vault is a DPAPI (LocalMachine) blob whose
plaintext is a decoy (the script stringifies a Hashtable).

## Channel 3 (independent verification): custom $REPARSE_POINT via raw $MFT

Parsing `[SYSTEM]/$MFT` (1024-byte records, attr walk from `+0x14`) found exactly
**one** record with a non-stock reparse tag:

- **MFT record 101281**, attr type `0xC0`, tag `0xA0000028`, dataLen `0x30` (48)
- Reparse buffer: `280000a0 30000000` (8-byte header `[tag][dataLen][reserved]`) + 48-byte AES-CBC ciphertext
- Ciphertext: `f4efda2cbfa8208e5b387ec8d2870200c8a8acd0feb6dd72c4e250bbd653b323e5c391e6e0b6983a4935c3b319267c14`

`AES-256-CBC(key = "T3ss3r4_K3y_8819472MasterSecret!", IV = 10..1f).decrypt(ct)`
yields `…d---r3p4r53_bu583r_vort3x}` + PKCS7 padding `06 06 06 06 06 06` - the first
16-byte block is **tampered** (CT bytes 14 - 15 differ).

Tamper resolution: re-encrypting the log literal
`iiiiiiiiiii-3hird---r3p4r53_buff3r_vort3x}` (42 bytes + 6 PKCS7 = 48) matches the
stored ciphertext in **46/48** bytes (diff only at CT 14,15), while the "tampered"
`bu583r` variant differs in 34 bytes. ⇒ authored plaintext is `…r3p4r53_buff3r_vort3x}`;
the `5`/`8` seen in raw decryption are the tampered-block artifact.

---

## Negative channels (checked, not the payload)

- MFT runlist lengths / LCNs / LCN-deltas across all in-use records - nothing (this is the extracted-tree variant; the runlist-length channel is empty).
- `$Bitmap` free/used run-lengths, value ±1 - nothing in this variant.
- All 420 reparse attrs are stock MS FT tags except record 101281 (the payload).
- `$Extend/$Deleted` entries (`00030000000183DD36C63374`, `000500000001827466C51742`, `0003000000000E7B64B4269A`) are real delete-pending NTFS metadata (`prefix + hex(FRN)`), not planted.

## Deliverables

- `FLAG.txt` - the final flag.
- `WRITEUP.md` - this file.
