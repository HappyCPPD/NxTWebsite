# Soul's Whisper

**Event:** ByteMe CTF 26
**Category:** rev
**Points:** 100
**Flag:** `OWASP{th3_s0ul_st0n3_wh1sp3r}`

---

**1. First look**

The handout is a single 16 KB file:

```
soul_whisper: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
              interpreter /lib64/ld-linux-x86-64.so.2, not stripped
```

Not stripped - so symbols are intact and there is no need to fight the
disassembler. `nm` names two interesting functions immediately:

```
000000000000129a T main
00000000000011c9 T soul_stone
```

Running it shows a themed prompt:

```
====================================
        SOUL STONE VAULT
====================================

The Soul Stone remembers everything...

Enter the secret phrase:
```

## 2. Leaking fragments with strings

`strings` coughs up four suspicious 8-byte fragments, each ending in a stray
`H`:

```
OWASP{thH
3_s0ul_sH
l_st0n3_H
wh1sp3r}H
```

Stripping the trailing `H` (which is really the first byte of the *next*
instruction's opcode being mistaken for text) leaves:

```
OWASP{th  3_s0ul_s  l_st0n3_  wh1sp3r}
```

Concatenating gives `OWASP{th3_s0ul_sl_st0n3_wh1sp3r}` - visibly *almost*
right but with a duplicated `sl`. That seam is the tell: the pieces are
overlapping, and reading them naively is a trap. Time to read the actual
code.

## 3. main() - the gate

```asm
call   __isoc99_scanf                      ; "%63s" into buf @ rbp-0x50
mov    DWORD PTR [rbp-0x55], 0x6c756f73    ; 73 6f 75 6c = "soul"
mov    BYTE  PTR [rbp-0x51], 0x00          ; NUL terminate
lea    rdx, [rbp-0x55]
lea    rax, [rbp-0x50]
call   strcmp                              ; strcmp(input, "soul")
test   eax, eax
jne    reject
call   soul_stone                          ; match -> print the flag
```

`0x6c756f73` is little-endian `73 6f 75 6c` = **`soul`**. The compared
constant is built on the stack, not stored as a plain string in `.rodata`,
which is why it doesn't appear as its own entry in `strings`.

So the "secret phrase" the vault is guarding is literally `soul`. A match
falls through to `soul_stone()`.

## 4. soul_stone() - where the flag actually lives

`soul_stone()` assembles the flag from four 64-bit `movabs` immediates
written to overlapping `rbp`-relative slots, copies 29 bytes (`0x00..0x1C`)
into a local buffer, NUL-terminates it, then `printf("Flag: %s")`:

```asm
movabs rax, 0x68747b505341574f   ; "OWASP{th"
movabs rdx, 0x735f6c7530735f33   ; "3_s0ul_s"
mov    [rbp-0x70], rax
mov    [rbp-0x68], rdx

movabs rax, 0x5f336e3074735f6c   ; "l_st0n3_"
movabs rdx, 0x7d72337073316877   ; "wh1sp3r}"
mov    [rbp-0x63], rax           ; <-- note: -0x63, NOT -0x60
mov    [rbp-0x5b], rdx
```

Laying the writes out by `rbp` offset:

| immediates (hex)         | little-endian ASCII | written at  |
|--------------------------|---------------------|-------------|
| `0x68747b505341574f`     | `OWASP{th`          | `rbp-0x70`  |
| `0x735f6c7530735f33`     | `3_s0ul_s`          | `rbp-0x68`  |
| `0x5f336e3074735f6c`     | `l_st0n3_`          | `rbp-0x63`  |
| `0x7d72337073316877`     | `wh1sp3r}`          | `rbp-0x5b`  |

The third write sits at `-0x63`, three bytes **into** the second write's
slot. It re-lands `l`, `_`, `s` over the exact same `l`, `_`, `s` that
`3_s0ul_s` already ends with - a deliberate overlap that reproduces the seam
we saw in `strings`. Same values, so nothing is corrupted; it just exists to
make linear/naive reconstruction produce the wrong `...sl...` result.
Reading from `-0x70` upward with later writes winning:

```
O W A S P { t h 3 _ s 0 u l _ s t 0 n 3 _ w h 1 s p 3 r }
```

→ `OWASP{th3_s0ul_st0n3_wh1sp3r}`

## 5. Solve

Fastest path - the binary prints the flag once you know the gate word:

```bash
echo 'soul' | ./soul_whisper
[+] The stone recognizes your soul.
[+] Access granted.

Flag: OWASP{th3_s0ul_st0n3_wh1sp3r}
```

Static path, no execution - decode the immediates directly:

```bash
python3 solve.py     # OWASP{th3_s0ul_st0n3_wh1sp3r}
```

## 6. Takeaways

- "Not stripped" is a gift: `nm` handed over `main` and `soul_stone`.
- A stack-built `strcmp` constant is a cheap way to hide a password from
  `strings`; recognize the `mov DWORD PTR [...], imm` + `strcmp` idiom.
- Overlapping `movabs` immediates are a classic obfuscation: the fragments
  in `strings` *look* almost right but duplicate a seam character. Trust the
  disassembly's memory layout, not the string dump.
- Two independent methods (live run, static decode) agree - high
  confidence.
