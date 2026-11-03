# The Miner That Mined The Victim

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{c4r3ful_4b0ut_cr4ck3d_t001s_69246bf057}`

---

**Flag:** `hiCTF{c4r3ful_4b0ut_cr4ck3d_t001s_69246bf057}`

## Answers (14 questions)

1. **OS Version:** Microsoft Windows NT 10.0.26200.0
2. **Timezone:** UTC-7, 420
3. **Download URL:** https://limewire.com/d/Ak55K#Yrx3FgK3du
4. **Download ID:** 42d377fe-8948-4a32-809f-69a51e6dbcfa
5. **Miner execution time:** 2026-05-13 14:25:36 UTC
6. **First encrypted file & PID:** 2026-05-13 14:26:55 UTC, 1
7. **Crypto DLL + timestamp:** C:\Program Files\dotnet\shared\Microsoft.NETCore.App\9.0.16\System.Security.Cryptography.dll, 2026-05-13 14:26:58 UTC
8. **Defender disable registry:** HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware
9. **MITRE ATT&CK technique:** T1685 (ATT&CK v19 renaming of T1562.001)
10. **Important text:** hiCTF{finally_u_proved_ur_worthiness} (hidden in MFT resident data in C:\Sysmon)
11. **Deleted folder:** C:\Users\milon1\Downloads\miner, 2026-05-13 14:27:47 UTC (from Recycle Bin $I file)
12. **Byte size:** 179623 (from $I file metadata)
13. **bar.txt plaintext:** I will always be there for you bro! (hidden in MFT resident data)
14. **Shred pattern:** help (0x706c6568 little-endian from Sysmon Event ID 23)
