# Echoes of Vormir: Mem-2

**Event:** ByteMe CTF 26
**Category:** forensics
**Points:** 200
**Flag:** `OWASP{SoulHunt_7F31}`

---

From the Echoes of Vormir memory forensics series. The artifact is `soul.zip`, containing `soul.mem`, a 2.6 GB Windows memory dump captured with FTK Imager, reused across all five sub-challenges.

> *Among everything running on the machine, something doesn't belong. Find
> it.*

We're given `soul.mem`, a Windows memory dump captured with FTK Imager.

## Solution

### 1. List running processes

Using Volatility 3 to enumerate all processes:

```bash
vol -f soul.mem windows.pslist.PsList
```

Most of the output is standard Windows processes - `svchost.exe`,
`csrss.exe`, `explorer.exe`, `msedge.exe`, etc. But one entry stands out:

```
PID   PPID  ImageFileName       CreateTime
2580  6960  SoulHunt_7F31.      2026-10-08 04:48:01 UTC
```

A process named `SoulHunt_7F31` spawned by `powershell.exe` (PID 6960) - clearly not a legitimate Windows process.

### 2. Inspect the command line

```bash
vol -f soul.mem windows.cmdline.CmdLine --pid 2580
"C:\Users\nightwatch\Desktop\SoulHunt_7F31.exe" -NoLogo -NoProfile -NoExit -Command Start-Sleep -Seconds 7200
```

The executable sits on the user `nightwatch`'s Desktop and was invoked with
PowerShell-style flags to stay alive silently for 2 hours.

### 3. Confirm it's masquerading

Dumping the executable from memory and checking its strings:

```bash
vol -f soul.mem windows.dumpfiles.DumpFiles --virtaddr 0xdb0f7765f7e0
strings SoulHunt_7F31.exe.img | grep -i powershell
powershell.pdb
<description>PowerShell</description>
```

`SoulHunt_7F31.exe` is a **renamed copy of PowerShell** - a classic evasion
technique to disguise malicious activity under an innocuous-looking process
name.
