# Omnitrix

**Event:** TISC 2026
**Category:** pwn
**Artifact:** `/congratulationsyougottheflag` (mode `0111`, 682696 B, static stripped ET_EXEC)
**Flag:** `TISC{6r33n_n33dl3_0r_br41n5t0rm??}`

---

## Overview

A stripped Rust/tokio TCP service ("Omnitrix") running in a `scratch`
container. The intended path is a logic/`dlopen` pwn: escalate a runtime
policy mask, then get the server to `dlopen` an attacker-supplied shared
object. The interesting part of this challenge isn't the exploit chain
itself, it's that the recon instrument lied for twelve sessions and
manufactured a false negative.

## 1. What we're given

The Dockerfile is the map. The builder stage compiles the flag *binary*:

```dockerfile
RUN printf ... > /flag.c \
 && gcc -O2 -static -s -DFLAG="$FLAG" /flag.c -o /flag.bin \
 && chmod 0111 /flag.bin && rm -f /flag.c
```

The program prints `token: <16 hex>`, reads 16 bytes, and prints the flag
only if you echo the token back within 30 seconds. `chmod 0111` means it's
**execute-only** - you cannot read it.

```dockerfile
FROM scratch
ARG FLAG_FILEPATH
ENV OMNITRIX_BIND=0.0.0.0:7878
COPY --from=builder /lib64/ld-linux-x86-64.so.2 /lib64/
COPY --from=builder /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libm.so.6 /lib/x86_64-linux-gnu/
COPY --from=builder /omnitrix.bin /omnitrix
COPY --from=builder /flag.bin $FLAG_FILEPATH
USER 10001:10001
```

Two deductions shape everything from here:

1. The flag must be **executed**, not read.
2. `FLAG_FILEPATH` is a build **ARG** used as a `COPY` destination - it is
   **not exported as ENV**. Confirmed live: the container's `ENVIRON` is
   `PATH=... | HOSTNAME=pwn-omnitrix | OMNITRIX_BIND=0.0.0.0:7878 |
   KUBERNETES_* | HOME=/` - no `FLAG*` variable anywhere. The flag's location
   is not discoverable from the environment; the filesystem has to be
   enumerated.

## 2. The service

A 16-byte header, strings length-prefixed big-endian:

```text
"OMNI" | version=1 | kind | opcode(u16 BE) | id(u32) | body_len(u32 BE) | body
```

Auth is op `0x0010` with hardcoded credentials: `ben.tennyson` /
`its-hero-time`. A full u16 scan confirms exactly eight opcodes exist:

| op | meaning |
|---|---|
| `0x10` | login |
| `0x20` | issue lease (`str(cap)+u64 duration`) |
| `0x21` | recall/commit lease |
| `0x41` | worker dispatch, runs the transform dispatcher |
| `0x50` | runtime mode change (needs a `matrix.configure` lease) |
| `0x51` | diag, no auth - pure decoy |
| `0x52` | "master-control voucher" |
| `0x53` | privileged playback / codon recall |

Leasable capabilities: `omnitrix.scan`, `dna.shift`, `matrix.configure`.

## 3. The escalation geometry (looks provably closed)

Everything gates on one global runtime policy mask:

- `codon.stream.inject` (the `dlopen` path): permitted iff `mask & 0x150 == 0x150` at mode 2
- op `0x53` recall: `not ebp; test ebp,0x150; jne error` - needs all of `0x150`
- `omnitrix.master_control.prepare`: permitted iff `mask == 0xffffffff`

The only code that produces a `0x150`-bearing mask is the op-`0x50` apply:

```text
base        = table[0x1e014][mode]            # mode 0/1/2 -> 0x0 / 0x4 / 0x2a4
flags       = entry_flags | 0x4(epoch advanced) | 0x8(resolve ok)
merged_mask = (mode==2 && (flags & 0xf)==0xf) ? (base | 0x150) : base   # 0x2a4|0x150 = 0x3f4
```

Quiescently `entry_flags == 0x2001`, so the nibble is `1`, `flags` maxes out
at `0xd` (1|4|8), and the gate never fires. The alternative route, op `0x52`
installing an attacker-chosen mask, needs a registered voucher, which is only
created by `prepare`, which needs `mask == 0xffffffff`. A closed triangle -
every static and black-box avenue is mapped and shut.

## 4. The bug: a data race in capability-cache reconcile

The triangle has a concurrency crack. Under load, the mode-change apply
sometimes reads `entry_flags` with bit 1 already set (`0x2003`), a genuine
race on the cache entry's flags dword, sometimes torn. Then nibble `= 0xf`,
`flags = 0xf`, and `merged_mask = 0x2a4 | 0x150 = 0x3f4` gets written to the
global, shared mask.

Reproduced two independent ways:

- **Black-box:** op `0x53` with an `omnitrix.scan` lease discriminates the
  gate by its error string. In 25 s: control = 1656 closed / 0 open; under
  load = 1280 closed / 357 open.
- **Trace (`RUST_LOG`):** the reconcile line over 25 s of load shows
  `flags=15` and `merged_mask=0x000003f4` thousands of times; neither ever
  occurs quiescently.

::: pitfall
The trace output is ANSI-coloured, so `grep 'flags=15'` finds nothing - strip
`\x1b\[[0-9;]*m` before parsing.
:::

So: churn enough mode-changes and the shared mask flips `0x2a4 <-> 0x3f4`
many times per second, and `inject` plus `recall` open with it.

## 5. From mask to code execution

**`inject`** writes a file into the codon vault
(`/tmp/omnitrix/codon/<name>`). The name may contain `/` but not `..`, so
`name="replay/w.so"` lands exactly where recall reads.

**`content_filter`** vets the blob: rejects embedded ELF magic in non-ELF
blobs, denies a list of libc imports (`execve`, `system`, `fork`,
`posix_spawn`, `dlopen`, `socket`, `connect`, ...), denies denylisted ASCII
anywhere in the file, and requires a well-formed `ET_DYN` with `DT_NEEDED
libc`, non-stripped section headers, and no RWX `PT_LOAD`. A hand-written
`.so` that performs every action with **inline `syscall` instructions** and
imports essentially nothing sails straight through.

**`recall`** reads `/tmp/omnitrix/codon/replay/<action>`, validates an
"OREP" container:

```text
"OREP" | u16 BE version=1 | str form | str template | u16 BE count | count * (str key, str val)
```

For `form="scan"` with `band="engage"`, it takes `map["payload"]` as a module
path, joins it to the vault, and `dlopen`s it, `dlsym`s `omnitrix_probe`, and
calls it - in-process, as uid 10001.

Kill chain:

1. `0x10` login.
2. Race the mask open (40 churn threads driving `0x50` mode-2 + `0x21`).
3. During a window, inject the weaponized `.so` as `replay/w.so`.
4. Inject the container as `replay/go` with `band=engage`, `payload=replay/w.so`.
5. Recall `go` -> `dlopen` -> `omnitrix_probe` -> flag.

## 6. Making it reliable: detect, freeze, exploit

The window is short and rare, and a 20 KB `.so` loses the race against the
worker's processing of the task. The fix exploits a property of the mask: it
is only rewritten by a mode-change apply.

1. Churn hard until a tiny-inject detector (a 1-byte payload) sees `imported
   ...` - the gate is open.
2. **Stop all churn.** If the last apply landed mid-window, the mask is now
   stuck at `0x3f4`.
3. Confirm with a few more tiny injects (`sticky=True`).
4. Now inject the big `.so` and the container leisurely, and hammer `recall`.

The weaponized `omnitrix_probe`: inline syscalls only; `getenv` retained
purely to keep `DT_NEEDED libc.so.6`. It forks
`/congratulationsyougottheflag` over two pipes, echoes the 16-hex token back,
and relays the captured output to every connected socket
(`getpeername() == 0`), so the flag arrives on whichever recall connection
triggered the load.

## 7. The actual hard part: the instrument was lying

The chain above worked locally, repeatedly, on the unpatched binary. Live, it
produced nothing, and the in-container recon reported: *"the flag artifact is
very likely a shared object to dlopen... no top-level file name contains
'flag'... `/` entries observed: `lib64` and little else."*

::: insight
All of that was false, for three mundane reasons - three bugs in the
enumeration probe:

1. **`list_dir()` used a `static` `getdents64` buffer while recursing.** The
   recursive call clobbered the parent's buffer mid-iteration, producing
   truncated, garbled listings. This is the true origin of "`/` has lib64 and
   little else".
2. **`wait4` was called through a 3-argument syscall helper.** `wait4(pid,
   status, options, rusage)` needs `r10` set; it held garbage, so the kernel
   wrote a 144-byte `rusage` struct through a garbage pointer - memory
   corruption that turned the relayed output into binary garbage.
3. **Deliberate blind spots.** The walk skipped `/lib`, `/lib64`, `/usr/lib`,
   `/proc`, `/sys`, `/dev`, skipped any `*.so*` name, and recursed exactly
   one level deep - three more ways to lose a `FLAG_FILEPATH`.
:::

The probe's own `has_flag_word()` would have matched the flag's filename all
along; the flag was reachable from session one, the tool reporting on the
world was broken.

The fixed probe uses a per-invocation `getdents` buffer, a correct 4-arg
syscall wrapper for `wait4`, `lstat` so symlinks aren't followed, and a full
depth-4 walk with no path or name skips, printing every entry it finds and
testing every exec-bit regular file. The exhaustive walk finally returned:

```text
E /congratulationsyougottheflag m111 s682696 d8
```

Execute it, echo the token, read the flag.

```text
TISC{6r33n_n33dl3_0r_br41n5t0rm??}
```

Captured on two separate live instances, identical both times.

## Lessons

- **Verify the enumerator.** When a long investigation concludes "I
  enumerated X and saw nothing", the tool is as much a suspect as the
  target. Two independent implementation bugs in a recon helper produced a
  false negative that survived twelve sessions and one confident, wrong
  root-cause hypothesis.
- **"Provably closed" must account for concurrency.** The gate arithmetic was
  verified byte-for-byte and dynamically; it was still wrong, because a
  quiescent aligned read of a raced dword is not the only read that happens.
- **Execute-only files are still files.** `chmod 0111` forces execute, not
  read, and a token-echo dance is a perfectly good exfiltration channel once
  there's code running in the process.
