# The-Loom

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{2nd_0rd3r_r3v_c3ll_aut0m8}`

---

A stripped 64-bit ELF reads 32 bytes and checks them. The flag is the input itself. The binary expands the 32 input bytes into a 256-bit array (bit `i` of state = bit `i%8` of byte `i/8`), then runs ~1,000,003 outer iterations of a nonlinear update over three rotating 256-byte buffers `(A,B,C)`:

```
g = (t&p) ^ (q^r) ^ (q&r) ^ (t&s) ^ (p&s)
C[j] = (g & 1) ^ A[j]
```

then rotates `(A,B,C) -> (B,C,A)`. Tracking the middle buffer's contents gives `P[n+1] = g(P[n]) ^ P[n-1]` - a second-order nonlinear recurrence ("second-order cellular automaton" - the flag name is the tell). After 1,000,002 rotations (`≡ 0 mod 3`), the final state leaves `P[1000003]` and `P[1000002]` exposed, compared against two hard-coded 32-byte constants via a `pack` inverse-expand.

**The trick:** the recurrence `P[n+1] = g(P[n]) ^ P[n-1]` is its own inverse: `P[n-1] = g(P[n]) ^ P[n+1]`. Given the two consecutive published states, walk backward one step at a time - 1,000,002 cheap O(256) steps - all the way to `P[0]`, the bit-expansion of the input.

```c
expand(C1, nxt);   // P[1000003]
expand(C2, cur);   // P[1000002]
for (k = 0; k < 1000002; k++) {
    gfun(cur, prev);
    for (j = 0; j < 256; j++) prev[j] ^= nxt[j];
    nxt = cur; cur = prev;
}
pack(cur, input);
isfcr{2nd_0rd3r_r3v_c3ll_aut0m8}
```

Verified against the original binary: `./solve | head -c 32 | ./chall` → `CORRECT`. A nonlinear, high-iteration map is not automatically hard - state the update order. Order-2 maps falling out of a shift-register/XOR-with-previous-state construction are reversible given two consecutive states, exactly as the challenge name (*The Loom*) and flag (*2nd order*) signpost.
