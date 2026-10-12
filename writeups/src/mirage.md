# mirage

**Event:** CryoVault CTF 2026
**Category:** pwn
**Flag:** `isfcr{bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry}`

---

`nc 0.cloud.chals.io 23023`, no binary shipped. The description - "an echo that repeats back a little more than you said" - is a textbook printf format-string leak description, and the flag text (`bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry`) confirms the intent to solve entirely blind.

**First contact:** `%p`/`%x`/`%s` confirm the bug immediately; feeding `AAAA%p%p%p%p%p%p%p%p` leaks `0x7025702541414141` - our own input buffer, little-endian, living on the stack, at argument index 6 (8-byte words). An 8-byte-aligned sweep maps the stack layout and finds several **fixed, non-randomised** low addresses (`0x40xxxx`/`0x48xxxx`/`0x4bxxxx`), proving the binary is **static, non-PIE** - fixed global addresses are readable without any ASLR leak.

**Arbitrary read:** naively placing the target address first fails because `printf` treats the buffer as a C string and stops at the first `0x00` byte inside the packed address. Fix: place the address **after** the format specifiers, computing the correct argument index from the buffer offset (`IDX = 6 + OFF//8`). Verified against known strings (`"quit"`, a known banner string).

Two interaction quirks: the service drops the **leading character** of every line (so avoid relying on it), and it processes **exactly one line per TCP segment** (extra pipelined lines in one `send()` are discarded) - requests must be sent one line at a time.

**Speeding up:** printf accepts many positional specifiers in one format string, so one request reads ~30 addresses via `%38$s|%39$s|...`, giving ~15 ms per address and letting whole memory regions be swept in seconds.

**Locating the flag:** `flag.txt`'s name sits in `.rodata`; the file is read into a fixed `.bss` buffer at startup. Sweeping `.bss` with stride 8 finds the flag string directly, confirmed by reading neighbouring (empty/NUL) addresses to pin the exact start:

```
4b6ac0  isfcr{bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry}
isfcr{bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry}
```

No write primitives (`%n`) were ever needed - the flag is simply leaked out of a global via the arbitrary read. Lessons: blind format-string work proceeds via `%p` stack mapping then identifying non-randomised addresses to prove static/non-PIE; NUL bytes kill a format string unless the pointer comes *after* the specifiers; multi-specifier reads turn a 1-read-per-RTT oracle into a ~30-read-per-RTT scanner.
