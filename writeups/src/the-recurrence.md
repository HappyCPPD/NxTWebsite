# The-Recurrence

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{p0hlig_h3llman_sm00th}`

---

A stripped 64-bit ELF reads exactly 28 bytes and prints `CORRECT` or `nope.`. The flag **is** the 28-byte input. The 28 bytes pack into a 224-bit little-endian scalar `k`. A loop runs bit 255 down to bit 0 of `k`, updating two 256-bit values `A`, `B` initialised to `A=2`, `B=P` (a constant), using modular add/sub/mul helpers mod `M`.

**The recurrence:** bit clear → `A' = A*A-2, B' = A*B-P`; bit set → `A' = A*B-P, B' = B*B-2`. This is exactly the **double-and-add ladder of a Lucas V-sequence** `V_n(P, Q=1)`: `V_0=2, V_1=P, V_2n=V_n^2-2, V_2n+1=V_n*V_n+1-P`. With `(A,B)=(V_n,V_n+1)`, bit clear → `n:=2n`, bit set → `n:=2n+1`. After consuming `k`, the state is `(V_k, V_k+1)`.

**The check:** only `A` is verified against a constant `T`, so `V_k(P,1) ≡ T (mod M)`.

**Inverting it:** since `Q=1`, the characteristic roots `α, β = α^-1` give `V_n = α^n + α^-n`. `V_k = T` becomes a quadratic in `α^k`: `(α^k)² − T·α^k + 1 = 0`, solved via Tonelli-Shanks since `T²−4` is a QR. Recovering `k` is now a discrete log of `α^k` base `α` in `F_M*`. Factoring `M-1` shows it is squarefree and **fully smooth** (largest factor 59051), and `α` is a primitive root - Pohlig-Hellman splits the 247-bit dlog into dlogs per ~16-bit prime, CRT'd together in milliseconds. Two candidate roots give two candidate `k` values (±k); exactly one lies in `[0, 2^224)` and yields printable ASCII.

```
k = 13207006284361456903106593959418730498679199957338452512214440375145
k.to_bytes(28, 'little') = b'isfcr{p0hlig_h3llman_sm00th}'
```

Verified: `printf '%s' 'isfcr{p0hlig_h3llman_sm00th}' | ./chall` → `CORRECT`. The author conveniently chose a prime `M` with a fully smooth `M-1` (the flag name gives it away).
