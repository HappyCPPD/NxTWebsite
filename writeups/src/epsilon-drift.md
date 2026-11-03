# Epsilon Drift

**Event:** HICyberCon CTF 2026
**Category:** rev
**Flag:** `hiCTF{1eee754_s1gn3d_z3r0_1u1p_dr1ft_eps!}`

---

**Flag:** `hiCTF{1eee754_s1gn3d_z3r0_1u1p_dr1ft_eps!}`

## Binary
- `extracted/epsilon-drift` - ELF x86-64, statically linked, stripped (1.2 MB).
- Uses the gfortran runtime (Fortran 2003). `main` = `0x401d30`; the real body is `0x401f10`.

## Input handling (`0x401f10`)
1. `command_argument_count` is checked; one argument required.
2. `get_command_argument` reads argv[1] into a 256-byte buffer.
3. Its length must be exactly `0x40` (64 chars) → a **32-byte** vector, i.e. **4 IEEE-754 doubles** `v0..v3` (little-endian).
4. A hex decoder (`0x401fad`..`0x40201e`) turns the 64 hex chars into 32 raw bytes and copies them into a malloc'd buffer.

## Acceptance check (`0x402020`..`0x4022a1`)
The four doubles are split into bit fields:
- `v3` (`rsp+0x18`) must satisfy `ucomisd 0.0` (equal, not NaN).
- `v0` bits in `rax`, `v1` bits in `rdi`.
- Mantissas are sliced into four 13-bit groups `a`(bits0-12), `b`(bits13-25), `c`(bits26-38), `d`(bits39-51); exponents are bits52-62; sign is bit63.
- Every branch ends in `sete`/`and`, so **all** of these must hold (mod 8192 / 2048):

```
(1) (a0+a1)  = 0x1334     (2) (a0+2a1) = 0xcce
(3) (b0+b1)  = 0x1998     (4) (b0+2b1) = 0x664
(5) (c0+c1)  = 0xccc      (6) (c0+2c1) = 0x1332
(7) (d0+d1)  = 0x666      (8) (d0+2d1) = 0x999
(9) (e0+e1)  = 0x7ff      (10)(e0+2e1)= 0x3ff
(11) sign(v0)=0, sign(v1)=0
(12) bits(v0+v1) == bits(v2)        ; v2 = v0 + v1  (double add)
```
Subtracting each pair gives a unique solution:
`a0=a1=0x199A`, `b0=b1=0xCCC`, `c0=c1=0x666`, `d0=d1=0x333`, `e0=1023`, `e1=1024`.

That is `v0 = 1.1`, `v1 = 2.2`, `v2 = 3.3000000000000003`, matching the hint's `residual 3.300000000000000e+00`.

### The "rounding" / signed-zero trick
The success branch (`0x402291`) does `movq %xmm1,%rax; test %rax,%rax; mov $1,%eax; cmovs %eax,%esi` and then jumps to the printing routine `0x402a70`, which chooses **accept when `esi != 0`**.
`esi` only becomes 1 when the sign flag is set, i.e. when `v3`'s top bit is 1 - while the earlier `ucomisd` only demands `v3 == 0.0`.
The only value equal to zero with the sign bit set is **negative zero**: `v3 = -0.0 = 0x8000000000000000`.
That is the `epsilon`/`rounding` drift: `+0.0` is rejected as "off-spec", `-0.0` is accepted.

## Flag generation (`0x402a70` accept path)
On accept it computes `SHA-256(vector)`, runs an iterative SHA-256 keystream (counter `be32(round)` appended), XORs it with a table at `0x4e34ff`, and after 42 bytes verifies `SHA-256(config) == {0x7ee08052b24c8222,0xf7722162aec0b1f9,0x24225a48a6865e8b,0x62cbba471e1887c5}`; on match it `fwrite`s the 42-byte config to stdout. No need to reimplement it - feeding the correct vector does it.

## Vector (64 hex chars)
```
9a9999999999f13f9a999999999901406766666666660a400000000000000080
```
- `v0 = 1.1`  → `9a9999999999f13f`
- `v1 = 2.2`  → `9a99999999990140`
- `v2 = 3.3000000000000003` → `6766666666660a40`
- `v3 = -0.0` → `0000000000000080`

## Reproduce
```
./extracted/epsilon-drift 9a9999999999f13f9a999999999901406766666666660a400000000000000080
# hiCTF{1eee754_s1gn3d_z3r0_1u1p_dr1ft_eps!}
```
