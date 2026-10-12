# slab

**Event:** CryoVault CTF 2026
**Category:** pwn
**Flag:** `isfcr{cust0m_sl4b_n0_gl1bc_r3c1p3_s4v3s_y0u}`

---

`nc 0.cloud.chals.io 20535`, no artifact shipped - recovered entirely over the wire. A "note store": `alloc | free <i> | edit <i> <hex> | read <i> | report | quit`, 16 slots, 96 bytes per note.

**Bug #1 - index-parsing mismatch:** the bounds check uses `atoi` (stops at first non-digit) while the array access uses `strtol(...,0)` (honours `0x`/sign). So `read 0x10`, `edit 0x10 ...` pass the bounds check but index outside the table - found to be a dead end (adjacent memory was zeros).

**Bug #2 - the real primitive, XOR-encoded free-list + note aliasing:** 16 note data pointers live in a `slots[]` table; `free(i)` doesn't wipe the note, it XOR-encodes the free-list link into the note's first 8 bytes with a per-process random key, and `alloc()` decodes the head with the same key to get the next note's data pointer. Because we control the bytes of a freed note, we control the decoded pointer - a freed note can be made to point anywhere, including at the `slots[]` table itself:

```
alloc x4 ; free 1 ; free 0
edit 0 <p64(0x4b6b00 ^ KEY)>     # encode SLOTS so alloc decodes to &slots[0]
alloc ; alloc                    # note1 now ALIASES the slot-pointer table
```

Writing note 1 now rewrites the entire pointer table - the store becomes a fully arbitrary 96-byte read/write primitive at any address. The per-process XOR key is trivially recovered live: `alloc; free 0; read 0` returns `0 ^ KEY = KEY`.

**Recovering the program:** with arbitrary read, dumped the ELF header, program headers, and `.rodata` strings, finding `flag.txt` referenced by a `load_flag()` function that opens the file, reads it into a stack buffer, and `write()`s it to a global fd - which is set to **the current connection's socket fd** by the per-connection handler.

**The dispatch hijack:** the `report` command handler dispatches through a writable function pointer currently pointing at a stub that just logs "nothing to report." With the arbitrary write, overwrite that pointer to `load_flag`:

```
1. setup the alias             -> note1->data = 0x4b6b00 (the pointer table)
2. arbitrary write: *0x4b50d0 = 0x4022e6  (load_flag)
3. send: report
   -> handler calls load_flag() -> opens flag.txt, writes it to our socket
--- report output ---
b'isfcr{cust0m_sl4b_n0_gl1bc_r3c1p3_s4v3s_y0u}\n> '
```

"Convince it to hand you something that was never filed": the flag was never filed into the note store - the free-list XOR encoding (a custom "slab" allocator, no glibc recipe to lean on) is the vulnerability, giving an aliased note and thus arbitrary read/write, turning an inert `report` function pointer into a flag-exfiltration gadget.
