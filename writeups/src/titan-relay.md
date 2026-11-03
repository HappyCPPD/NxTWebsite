# Titan Relay

**Event:** HICyberCon CTF 2026
**Category:** pwn
**Flag:** `hiCTF{ru5t_vm_g4te_and_h4ndler_ch41n_152bad75bf}`

---

**Flag: `hiCTF{ru5t_vm_g4te_and_h4ndler_ch41n_152bad75bf}`**

Recovered from the **live** service (the server itself printed it):
```
$ python3 exploit.py --remote --host titan-relay-2409d376ae08.chall.hiddeninvestigations.net
[*] trying path b'Z:/flag.txt.'  capsule 392 bytes
=== TITAN RELAY :: route consensus vm ===
[+] capsule accepted
hiCTF{ru5t_vm_g4te_and_h4ndler_ch41n_152bad75bf}
```

## Artifact
`titan_relay.exe` - PE32+ x86-64 **Rust** console app, 286208 B. Served under **Wine** inside
ubuntu:24.04 via `socat -T 60 TCP-LISTEN:7260,reuseaddr,fork EXEC:"./run_titan.sh work",su=ctf`
(the platform proxies it to :1337 over TLS). The real flag lives at `/flag.txt` (mode 444);
the `flag.txt` shipped in the zip is a placeholder.

## Console / surface
```
=== TITAN RELAY :: route consensus vm ===
1) load capsule
2) quit
Option > Capsule length > Capsule hex >
```
You upload a hex byte-string ("capsule") which the app treats as bytecode for a small VM.

## Why a raw capsule never runs (the first trap)
The loader **decrypts** the uploaded capsule before executing it:
```
plain[i] = cipher[i] ^ ((0x71 + 0x3d * i) & 0xff)
```
(SIMD at `0x1400031bc–0x140003301`; scalar tail at `0x1400032ec` computes `key = 0x71 + 0x3d*i`.)
So a "valid" opcode like `0x51` sends `0x51 ^ 0x71` and the VM runs off the end →
silent `[!] route fault contained`. Capsules must be encrypted with that keystream.

## VM layout
- Dispatch loop inlined in `main` at **`0x1400035a7–0x140003c6c`**; two decode tables:
  `T1 @0x14003c164` (0x71 - 0xB1), `T2 @0x14003c0a0` (0x21 - 0x51).
- 8 registers at `state+0x18`; memory `mem[0..15]` at `state+0x58`;
  a **`relay` array at `state+0xd8`** whose first 3 entries leak `lo32(canary)`, `hi32(canary)`,
  `hi32^valid` - so the canary is obtainable *from inside the VM*.

## The primitive: SUBMIT → host `CreateFileW` (arbitrary file read)
`SUBMIT` = opcode **`0x51`**, handler `0x140003b26–0x140003b4e`, which requires:
- `state+0x08 == state+0x00` (canary echoed)
- `state+0x10 == 0x1400018c0` (the validator's PIE-relative address)
- `reg6 != 0`

then `call 0x1400018c0` at `0x140003c62`. The host validator expects the 0x20-byte struct at `reg6`:

| off | value |
|---|---|
| +0x00 | canary |
| +0x08 | pointer to the filename buffer |
| +0x10 | `lo32(can) ^ hi32(can)` |
| +0x14 | `0x0b` (11 - the filename length) |
| +0x18 | `+lo32(can)` |

The buffer is de-obfuscated as `buf[i] ^ canary_byte(map(i))` with `map = 0..7,0..2` and the
constraint `buf[11] == canary_byte(3)`; the resulting 11-byte NUL-free UTF-8 string is passed to
`File::open` and the contents are printed. Failure prints `[!] order rejected`.

## Exploit
`exploit.py` builds a capsule that (1) reads the canary via `RELAY`, (2) derives the validator
address and all gate values, (3) sets up the 0x20-byte validator struct with the target filename,
and (4) issues `SUBMIT`; the whole capsule is XOR-encrypted with the loader keystream.
The target path used is the 11-byte `Z:/flag.txt.` (Wine maps `Z:` → `/`, so this opens
`/flag.txt`; the trailing byte satisfies the 11-byte length/NUL-free constraint).

```bash
python3 exploit.py --local          # proves the primitive against the shipped binary
python3 exploit.py --remote --host <instance>   # pulls the real flag
```

## Verification
The flag came out of the **live** server process - the reliable oracle for a pwn service
(the local run can only prove the file-read primitive, since the shipped `flag.txt` is
`hiCTF{fake_flag_for_local_testing}`).
