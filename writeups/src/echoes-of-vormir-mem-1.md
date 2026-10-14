# Echoes of Vormir: Mem-1

**Event:** ByteMe CTF 26
**Category:** forensics
**Points:** 100
**Flag:** `OWASP{2026-10-08 05:07:43}`

---

## Overview

We're given a memory dump (`soul.mem`) from a Windows machine. The challenge series has five artifacts to find. The memory image is reused across all sub-challenges.

**File:** `soul.zip` -> `soul.mem` (2.6 GB Windows memory dump)

---

## Mem-1: When It Happened (100 pts - Easy)

> *Before following the trail, determine when the machine gave up its secrets.*
> *Find the time recorded in the memory image.*
> *Flag format: OWASP{YYYY-MM-DD HH:MM:SS}*

### Approach

This is a straightforward memory forensics warm-up. The challenge asks for the timestamp embedded in the memory image -- i.e., the `SystemTime` recorded when the dump was captured.

### Solution

**Step 1: Extract the memory dump**

```bash
unzip soul.zip
```

This produces `soul.mem`, a ~2.6 GB raw memory image.

**Step 2: Identify the image and extract metadata with Volatility 3**

```bash
vol -f soul.mem windows.info
```

Key output:

| Variable           | Value                      |
|--------------------|----------------------------|
| Is64Bit            | True                       |
| KeNumberProcessors | 6                          |
| **SystemTime**     | **2026-10-08 05:07:43+00:00** |
| NtSystemRoot       | C:\Windows                 |
| NtProductType      | NtProductWinNt             |

The `SystemTime` field in the `_KUSER_SHARED_DATA` structure records the system clock at the time the memory was captured.

### Flag

```
OWASP{2026-10-08 05:07:43}
```

