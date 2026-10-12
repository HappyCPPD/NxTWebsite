# Palimpest

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{p4p3r_r3m3mb3rs_wh4t_1nk_f0rg3ts}`

---

A statically linked, stripped Zig-built ELF. The catalogue (`?`) shows two decoy flags for JOB 00/02 plus a reversed hint "Restoration starts at the last impression." The input check requires `isfcr{` + 32 `[a-z0-9_]` chars + `}`, and the 32 inner chars are copied verbatim into eight 32-bit registers - no hashing of the input.

**The virtual machine:** 320 iterations consume 8 bytecode bytes each, decoding an opcode and operands via a rolling hash keyed by an accumulator `r9`, built from `rol5`/xor mixing with the golden-ratio constant. Range checks on decoded operands are hard rejects. Nine ops shuffle the eight registers: ADD imm, XOR imm, ROL reg, MUL imm, ADD ROL, XOR ROL, S-box substitute, SWAP, MOVE pointer. A 3-bit pointer `P` only moves on the MOVE op. After the op, the *new* register state feeds the next round's key - self-referential, hence *Palimpest* / "a mirror on the workbench". The final gate requires `P==1`, a running sum check, and the eight registers to equal two hard-coded 128-bit constants.

**Solving:** rather than hand-invert the data-dependent control flow, the whole loop was reimplemented and symbolised with 8 symbolic 32-bit registers, asserting at every step: range checks, selector validity, guard conditions, plus the final equality/`P==1`/sum constraints and "body is printable ASCII". A concrete Python twin was first validated against the binary under gdb (step-0 decode and re-keyed `r9` both matched). This is QF_BV; **bitwuzla** solved it in seconds (a z3 port also worked but was slower/memory-hungry).

```
$ python3 bw_solve.py print
RESULT: sat
FLAG: isfcr{p4p3r_r3m3mb3rs_wh4t_1nk_f0rg3ts}

$ printf 'isfcr{p4p3r_r3m3mb3rs_wh4t_1nk_f0rg3ts}\n' | ./palimpsest
> Seal accepted. Job 04 restored.
```

Two bugs cost time: z3's `>>` is arithmetic (sign-extending) - needed `z3.LShR` for the rotate helper; and the epilogue adds byte `b7`, not the loop counter (the assembly clobbers the counter register first).
