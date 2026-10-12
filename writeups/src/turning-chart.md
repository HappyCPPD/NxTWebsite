# Turning Chart

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{3v3ry_r0ut3_r3m3mb3rs_1ts_0r1g1n}`

---

A statically-linked, stripped ELF64. The prompt's `?` is a decoy printing a retired dial and exiting (the blurb says "kept for the museum, not for navigation" - a tell to ignore it). Input must be exactly 39 bytes: `isfcr{` + 32 `[a-z0-9_]` chars + `}`, copied **verbatim** into a 32-byte state array with no hashing at all.

A fixed 320-round "needle" state machine then runs. Crucially every round's parameters (op, indices, operands) come only from a fixed xorshift PRNG seeded at `0x73b59a26` and rolling accumulators - **nothing depends on the input state**. So the whole program is a fixed, invertible sequence of 320 byte-ops. Nine op types observed: rotate 8-byte window, rotate 4-byte strided window, swap, add-with-key, XOR-rotate, S-box substitute (runtime 256-byte table), a combine op, reverse a 4-byte window, no-op. The final state is compared against 32 hard-coded bytes XOR-masked by a second xorshift stream.

**Method:** gdb-logged the full 320-round op sequence and the runtime 256-byte permutation and final PRNG value. Reimplemented the 9 ops in Python; a forward pass with all-`'a'` input reproduced the binary's final state exactly, confirming the model. Recovered the required pre-XOR final state from the hard-coded target and the final xorshift stream, then applied each op's inverse over `reversed(ops)`.

```
num ops 320 rounds 0 319
forward match: True
mid bytes: b'3v3ry_r0ut3_r3m3mb3rs_1ts_0r1g1n'
re-fwd match: True
$ printf 'isfcr{3v3ry_r0ut3_r3m3mb3rs_1ts_0r1g1n}\n' | ./turning_chart
Course: Chart opened. Course restored.
exit=0
```

"Every route remembers its origin": the transform is a fixed, data-independent op program, so it is trivially invertible. The decoy dial and the missing input dependency are the two traps - the machine is a bijection, not a one-way function.
