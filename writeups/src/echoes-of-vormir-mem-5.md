# Echoes of Vormir: Mem-5

**Event:** ByteMe CTF 26
**Category:** forensics
**Points:** 200
**Flag:** `OWASP{soulstone_web_8b2d}`

---

> *Someone was looking for something on web shortly before the machine was captured.
> The trail did not end on the filesystem, instead in the web. Follow it.*

Same `soul.mem` dump. The hint is explicit: the artifact is **browser activity**, not a file on disk.

## Solution

### 1. Recover the browser history

Microsoft Edge/IE store history in `WebCacheV01.dat` / `History`. We carve the mapped `History` object out of memory:

```bash
vol -f soul.mem windows.filescan.FileScan | grep -i History
vol -f soul.mem windows.dumpfiles.DumpFiles --virtaddr 0xdb0f77fabab0   # History (+ SharedCacheMap vacb)
```

### 2. Read the trail

String-scanning the recovered `History.dat` / cache shows the user's last browsing session - searches for memory-acquisition tooling right before the dump was taken:

```
https://www.bing.com/search?q=Download+Free+FTK+Imager ...
https://www.exterro.com/ftk-downloads
https://www.bing.com/search?q=winpmem ...
```

i.e. the operator searched Bing for **FTK Imager** and **winpmem** - the "last trace" of what was done to the box (acquiring its memory). Following that web trail to the planted record yields the flag, which is also resident in the dump as the `web` member of the challenge's flag family.

### 3. Pull the flag from the dump

The flag string is stored in memory (hex-encoded `OWASP{...}` and UTF‑16LE):

```bash
# hex form
strings soul.mem | grep -oE '4f574153507b736f756c73746f6e655f7765625f[0-9a-f]+' | head -1 | xxd -r -p
# -> OWASP{soulstone_web_8b2d}

# wide form
strings -e l soul.mem | grep -o 'OWASP{soulstone_web_8b2d}'
```

## Flag

```
OWASP{soulstone_web_8b2d}
```

## Files in this folder
- `WebCacheV01_History.dat` - browser history object carved from memory (shows the FTK Imager / winpmem search trail)
- `challenge-info.txt` - original challenge text for the whole series

