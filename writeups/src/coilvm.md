# CoilVM

**Event:** September 2026 SkillBit Flash CTF
**Category:** rev
**Flag:** `SkillBit{n4nom1tes_eat_y0ur_symb0lic_execut0r}`

---

## Overview

> Something inside the coil watches every choice you feed it, tightening or
> slackening in response before it lets the next test through. Rush it and it
> forgets nothing kindly. Wind it just right, all the way to the end, and it
> finally lets go of what it's been holding.

A single stripped x86-64 ELF, `coilvm`. It reads 36 bytes from stdin and
prints either `nope` or a flag.

```text
$ file coilvm
coilvm: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, stripped

$ strings coilvm | grep -i c01l
C01L_VM_d3c0y_d0_n0t_b3l13v3_th15_str1ng

$ echo test | ./coilvm
nope
```

The decoy string names itself as a decoy, which is its own small joke. The
real check lives somewhere strings can't reach.

## Architecture: a VM built out of faults

The binary implements a custom VM using SIGTRAP as its instruction dispatch.
The "coil" is a chain of 36 `int3` (`0xCC`) bytes interleaved with
self-modifying XOR blocks. Each `int3` traps into a SIGSEGV/SIGTRAP handler
that processes exactly one input byte before returning control to the next
link in the chain.

`main` (`0x401631`) does four things:

1. **`mprotect`s its own code RWX** so the coil can rewrite itself later.
2. **Init phase** — runs the int3 chain once, doing nothing but recording all
   36 fault addresses into an array. This is how the handler later knows
   *which* step it's on without any explicit state passed in.
3. **Reads 36 bytes** of input into a fixed buffer.
4. **Verify phase** — seeds an FNV-1a hash at `0x811c9dc5`, clears a fail
   flag, and runs the chain again, this time for real.

If every step passed and the fail flag never got set, it decrypts and prints
the flag. Otherwise, `nope`.

## The trap handler

The handler (`0x401196`) pulls the faulting RIP out of the `ucontext_t` and
branches on which phase it's in.

**Init mode** just stores the RIP into the 36-entry step table.

**Verify mode** is where the checking happens:

::: pitfall
An `rdtsc` delta since the last trap over `0x4000000` (~67M cycles) —
i.e. someone single-stepping in a debugger — silently XORs the running hash
with `0xa5a5a5a5` before continuing. Nothing crashes, nothing prints early.
The check just becomes impossible to pass, and you'd only notice because the
math stops adding up. This is the "rush it and it forgets nothing kindly"
line from the prompt.
:::

Past the anti-debug gate, for step `i` with current hash `h`:

```text
expected = (h & 0xFF) ^ verify_table[i]
check:    rol8((h & 0xFF) ^ input[i], (h >> 5) & 7) == expected
```

A failed check sets the fail flag but does **not** stop execution — every
byte is still processed regardless, so timing and control flow give away
nothing about which byte was wrong. The hash then updates with plain
FNV-1a: `h = (h ^ input[i]) * 0x1000193`, and a derived byte
`(h & 0x7F) ^ 0x90` gets written back into the XOR blocks between traps,
mutating the coil's own bytes for the next run. That self-modification
doesn't affect verification at all — it exists purely to make a static
disassembly stale the moment the program runs.

## Decryption

Once all 36 bytes pass, the final hash seeds a 47-byte output loop
(`0x401797`). For output position `d`:

```text
idx1 = d % 36
h    = (h ^ input[idx1]) * FNV_PRIME          # FNV-1a continues

idx2 = (1 + 5*d) % 36                          # stride-5 permutation
rot  = rol8(input[idx2], (h >> 7) & 7)

out[d] = ((h >> 11) & 0xFF) ^ decrypt_table[d] ^ (d & 0xFF) ^ rot
```

The output is longer than the input because the 36 input bytes get reused
cyclically, the FNV state keeps accumulating fresh entropy each step, and the
stride-5 index scrambles which byte feeds the rotation at each position.

## Solving it forward

The hash is deterministic and each byte is checked in order, so there's no
need to search anything: at step `i` the hash going in is already fixed by
the previous 0..i-1 bytes, so the verification equation inverts cleanly for
`input[i]`.

```python
def ror8(val, n):
    n &= 7
    return ((val >> n) | (val << (8 - n))) & 0xff

verify_table = bytes([
    0x2f, 0x3b, 0xb3, 0x3a, 0xb6, 0x86, 0x9a, 0xd7,
    0xbf, 0xa0, 0x74, 0x61, 0x1b, 0x0f, 0xa2, 0x06,
    0xec, 0xe4, 0xc3, 0x8f, 0x79, 0x38, 0x40, 0xcf,
    0x9c, 0x0f, 0xb7, 0x14, 0x95, 0xb4, 0x65, 0xee,
    0x9e, 0x74, 0x0c, 0x35,
])

hash_val = 0x811c9dc5
input_bytes = []

for step in range(36):
    h_lo = hash_val & 0xff
    rot = (hash_val >> 5) & 7
    expected = h_lo ^ verify_table[step]
    input_byte = h_lo ^ ror8(expected, rot)
    input_bytes.append(input_byte)
    hash_val = ((hash_val ^ input_byte) * 0x1000193) & 0xFFFFFFFF
```

```session
$ printf 'n4nom1tes_eat_y0ur_symb0lic_execut0r' | ./coilvm
SkillBit{n4nom1tes_eat_y0ur_symb0lic_execut0r}
```

## Flag

```text
SkillBit{n4nom1tes_eat_y0ur_symb0lic_execut0r}
```
