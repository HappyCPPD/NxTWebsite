# biblocker

**Event:** Kaspersky CTF 2026
**Category:** reverse engineering
**Points:** 50
**Flag:** `kaspersky{s1gn4l5_pr0v1d3d_tPm_k1nd4_sus}` (submitted, platform status `Correct`)

---

> You're asking why BitbLocker uses TPM? Well, you only need to understand the power contained in those three letters:
> T - Trusted / P - Potato / M - Module

The whole challenge is the hint: the "TPM" is a **SIGSEGV handler** that provides the key material out of band.

---

## 1. Recon

```bash
file files/biblocker_5d741069dd2afdda
# ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
md5sum files/biblocker_5d741069dd2afdda
# 96d209649384dc92fdfc095adb6aa6c4
```

Not stripped, so `nm` gives a very informative symbol table:

```
AES_CBC_decrypt_buffer   derive_decrypt_key      segsegv_handler
AES_init_ctx_iv          validate_key            resolve_sigaction
sha256_*                 fs_img_begin/fs_img_end target_key
mount_squashfs_blob      create_memfd            check_tracer
sm_crc32_1/2/3           confuse_path            get_tracer_pid
```

Interesting strings: `squashfs`, `/mnt/biblocker`, `/dev/loop-control`, `blablablablablab`,
`invalid password!`, `corrupted image!`, `memfd_create`.

So: password → key → AES-CBC decrypt an embedded squashfs image → write to a memfd → loop-mount it.

## 2. Decompilation (IDA Pro 9.1 headless)

`ida-pro-mcp` was not wired up in this session, so IDA was driven headless with an IDAPython script:

`decomp.py`
```python
import idautils, idc, ida_hexrays, ida_auto, ida_pro

ida_auto.auto_wait()
out = open("decomp.c", "w")
ida_hexrays.init_hexrays_plugin()
for ea in idautils.Functions():
    out.write("//==== %s @ 0x%X ====\n" % (idc.get_func_name(ea), ea))
    try:
        out.write(str(ida_hexrays.decompile(ea)) + "\n\n")
    except Exception as e:
        out.write("// decompile failed: %s\n\n" % e)
out.close()
ida_pro.qexit(0)
```

```bash
cp files/biblocker_5d741069dd2afdda ./biblocker.elf
TVHEADLESS=1 idat -A -S"decomp.py" biblocker.elf     # -> decomp.c (2270 lines)
```

## 3. Program logic

### `main` @ `0x56D0`

```c
derive_decrypt_key(argv[1], key);                       // key = 16 bytes
v7 = MEMORY[0xA524F867B50] ^ key[0..15];                // <-- faulting load
if (v7 != target_key) { puts("invalid password!"); return 1; }

prepare_mount_path("/mnt/biblocker");
memfd = create_memfd();                                  // memfd_create("biblocker", 1)
aes_cbc_decrypt_to_fd(fs_img_begin, fs_img_end - fs_img_begin, key, memfd);
mount_squashfs_blob(memfd, "/mnt/biblocker");
```

### `derive_decrypt_key` @ `0x41C0`

```c
sha256(password) -> h[32]
for (i = 0; i < 16; i++) key[i] = h[i] ^ h[i+16];
```

Plain SHA-256 folded in half → **AES-128 key**. Not invertible, and brute-forcing the password is
explicitly out of scope - but we don't need the password at all.

### `aes_cbc_decrypt_to_fd` @ `0x5E50`

```c
AES_init_ctx_iv(ctx, key, "blablablablablab");   // IV is a hardcoded ASCII string
AES_CBC_decrypt_buffer_to_fd(ctx, blob, len, fd);
// then reads the last block back and validates PKCS#7 padding
```

### `validate_key` @ `0x4240` - the key equation

```asm
4240: movups xmm0,[rdi]                  ; derived key
4243: movaps [rsp-0x18],xmm0
424d: movabs rsi,0xa524f867b50           ; <-- absolute, UNMAPPED address
4257: mov    rax,QWORD PTR [rsi]         ; 48 8b 06        (3 bytes) -> SIGSEGV
425a: xor    QWORD PTR [rcx],rax
425d: mov    rax,QWORD PTR [rsi+0x8]     ; 48 8b 46 08     (4 bytes) -> SIGSEGV
4261: xor    QWORD PTR [rcx+0x8],rax
...   cmp against target_key
```

So the check is simply:

```
derived_key XOR mask == target_key      =>      AES_key = target_key XOR mask
```

`target_key` @ `0x8670` in `.data`:

```
8670  d6b9ac3e 973f597a b291bd21 cb0db68a
```

`mask` is *never stored anywhere*. It is produced by the SIGSEGV handler - the "Trusted Potato Module".

## 4. The "TPM": `segsegv_handler` @ `0x4FF0`

The third handler argument is a `ucontext_t *`. On x86-64 glibc, `uc_mcontext.gregs[]` starts at
`ucontext + 40`, i.e. `a3[5]` in qword indices, so `a3[i] == gregs[i-5]`:

| decompiler | greg index | register |
|---|---|---|
| `a3[15]` | 10 | `RBP` |
| `a3[18]` | 13 | `RAX` |
| `a3[20]` | 15 | `RSP` |
| `a3[21]` | 16 | `RIP` |
| `a3[23]` | 18 | `CSGSFS` |
| `a3[27]` | 22 | **`CR2` (fault address)** |

Handler behaviour:

```c
v6 = sm_crc32_3(&gregs[CR2], 8);            // CRC32 of the 8-byte fault address
v5 = (*(u8*)(RIP + 2) & 0xF) - 5;           // opcode-shape check on the faulting insn

key[0..1] = 0xB7DA05A379A0A4 * CR2;         // XTEA key, derived from the fault address
key[2..3] = 0xB015462CBD5972 * CR2;

if (v5 == 1 && v6 ==   569722185) { ct = 0xB08863AE1CF8A11D; RIP += 3; }
else if (v5 == 1 && v6 == -1471963024) { ct = 0x09692350899D4F57; RIP += 4; }
else { /* fake epilogue: emulate leave/ret to confuse tracing */ }

// 32-round XTEA decryption, delta = -1207154922, sum = 25748160
for (i = 0; i < 32; i++) {
    hi -= (key[3] + (lo >> 5)) ^ (sum + lo) ^ (key[2] + 16*lo);
    lo -= (key[1] + (hi >> 5)) ^ (sum + hi) ^ (key[0] + 16*hi);
    sum -= delta;
}
gregs[RAX] = (hi << 32) | lo;               // hand the mask qword back to the code
```

The two branches map exactly onto the two faulting instructions:

* `mov rax,[rsi]`     = `48 8b 06`    → byte at `RIP+2` is `0x06`, low nibble `6`, `6-5 = 1` ✓, length **3**
* `mov rax,[rsi+0x8]` = `48 8b 46 08` → byte at `RIP+2` is `0x46`, low nibble `6`, `6-5 = 1` ✓, length **4**

and are disambiguated by `sm_crc32_3` (a custom reflected CRC32, poly `0xF6ABF146`,
init `~0x3DD8B0B8`) over `CR2 = 0xa524f867b50` and `0xa524f867b58`.

## 5. Static emulation

`solve.py` reimplements the CRC and the XTEA round exactly, with no execution of the binary
(no root, no loop devices, no mounting, and it also sidesteps the `check_tracer`/`get_tracer_pid`
anti-debug and the `text_crc` self-integrity checks).

```bash
python3 solve.py
```

```
CR2=0xa524f867b50 crc32_3=569722185    -> mask qword 0x7b596340958bc1bc
CR2=0xa524f867b58 crc32_3=-1471963024  -> mask qword 0x05d4168edd6f1910
mask        : bcc18b954063597b10196fdd8e16d405
target_key  : d6b9ac3e973f597ab291bd21cb0db68a
AES-128 key : 6a7827abd75c0001a288d2fc451b628f
decrypted 4096 bytes, magic: b'hsqs'
```

Both computed CRCs matched the hardcoded constants exactly - strong confirmation the register
mapping and the fault addresses were read correctly.

Note on extraction of the ciphertext: `fs_img_begin`/`fs_img_end` are vaddrs `0x3138`/`0x4148`,
and the executable `LOAD` segment maps file offset `0x1d90` → vaddr `0x2d90`, so
`file_offset = vaddr - 0x1000`. Blob length `0x1010` = 4112 bytes (16-aligned, as
`aes_cbc_decrypt_to_fd` requires).

## 6. Flag

```bash
file fs.squashfs
# Squashfs filesystem, little endian, version 4.0, zlib compressed, 2 inodes
unsquashfs -q fs.squashfs
cat squashfs-root/flag.txt
```

```
kaspersky{s1gn4l5_pr0v1d3d_tPm_k1nd4_sus}
```

Submission:

```bash
/Users/dan/ctf/kaspersky/kasperskyflag 20 'kaspersky{s1gn4l5_pr0v1d3d_tPm_k1nd4_sus}'
# {"status": "Correct"}
```

---

## Files in this directory

| File | Purpose |
|---|---|
| `files/biblocker_5d741069dd2afdda` | original attachment (untouched) |
| `biblocker.elf` | working copy fed to IDA |
| `decomp.py` | IDAPython headless decompilation driver |
| `decomp.c` | full Hex-Rays output |
| `solve.py` | TPM/XTEA emulation + AES-CBC decryption |
| `fs.squashfs` | recovered squashfs image |
| `squashfs-root/flag.txt` | the flag |

## Anti-analysis features noted (all bypassed by pure static solving)

* `check_tracer` / `get_tracer_pid`, parses `/proc/self/status` `TracerPid`, so a debugger changes behaviour.
* `text_crc` + `g_text_addr`/`g_text_end` + `sm_crc32_1/2/3`, self-integrity checks over `.text`.
* Manual ELF symbol resolution (`elf_hash`, `elf_gnu_hash`, `resolve_elf_sym_hash`,
  `resolve_elf_sym_gnu_hash`, `resolve_sigaction`) - `sigaction` is resolved by hand rather than via the PLT.
* `confuse_path`, `sm_crc32_confuse`, `jmp_table`, `skip`/`skip_1`/`return_slide`/`zero_stub`, CFG obfuscation.
* The `else` branch of the SIGSEGV handler forges a `leave; ret` in the trap frame, so an unexpected
  fault silently unwinds instead of crashing - designed to punish patching or single-stepping.

## Remaining unknowns

The original password is not recovered: `derive_decrypt_key` is a one-way SHA-256 fold, and the
challenge only ever compares the folded output. Brute force was deliberately not attempted; it is
unnecessary because the AES key itself is fully determined by `target_key XOR mask`.
