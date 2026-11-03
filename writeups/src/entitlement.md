# Entitlement

**Event:** HICyberCon CTF 2026
**Category:** rev
**Flag:** `hiCTF{>o<_C0ngrats_Her3_1s_Y0ur_HI4_Subscript1on_^_^}`

---

**Flag:** `hiCTF{>o<_C0ngrats_Her3_1s_Y0ur_HI4_Subscript1on_^_^}`

Verified: the string the binary emits is the 64-byte buffer the program itself builds, and its
byte-sum equals the program's own acceptance constant `0x133d` (sum = 4925 = 0x133d).

Reproduction (the program deliberately burns ~500 million modular-square iterations before
printing, so it takes ~15 - 20 minutes on one core):

```bash
printf '8f7db18bd70e193b\n2977e17b118de75b3b4e921a4\n' | ./Entitlement
# Serial > ... Activation code > ... Correct! The flag is hiCTF{...}
```

Two inputs are required:

| stage | input | value |
|-------|-------|-------|
| 1 | Serial (16 hex chars) | `8f7db18bd70e193b` |
| 2 | Activation code (25 hex chars) | `2977e17b118de75b3b4e921a4` |

## Binary structure

`Entitlement` is a 15048-byte ELF64 with **no section headers**. It is a self-loader: the entry
stub (`0x40abd8`) decrypts a live image into `0x400000–0x408000` (via a `memfd`), sets
`PR_SET_DUMPABLE=0` and reads `/proc/self/status:TracerPid` as anti-debug. The cleared live image
was recovered to `work/live.bin`; every real function lives in `0x401000–0x405000`.

### Stage 1 - Serial (bit-serial VM)

`main` @ `0x401110` reads `%63s`, requires length 16, hex-decodes it to 64-bit `r8`, then runs a
private bytecode VM.

* `0x404330` first **decrypts the VM program in place** at `0x407080` (0x18c bytes). The key stream
  is a KDF (`0x4042c0`) seeded by a 64-bit hash of the VM handler code bytes `0x404560–0x404702`.
  Anti-debug (`0x403830`) XOR-corrupts that seed if a tracer is present - this is why "the key
  doesn't work" under gdb: the bytecode is never correctly decrypted. It also sets the guard byte
  at `0x40721c`, which makes repeat calls skip re-decryption.
* VM (`0x404560`): dispatch table @ `0x405060`, 8 registers, 4-byte instructions
  `[opcode, dst, src1, src2]`, opcodes 0 - 16 (LOAD_CONST/LOAD_INPUT/COPY/XOR/NOT/ROL/ROR/SHL/SHR/
  ADD/SUB/BRANCH_NZ/JMP/LOOKUP/RET), constant table @ `0x405240`.
* The decrypted program computes, over **GF(2^64)** with reduction polynomial
  `P = 0x2b395c2099596d9f`:

  ```
  out = (serial XOR 0xd1705c3b2e33689b)^13  XOR  0xba6b1f3cb925c25a
  ```

  and `main` requires `out == 0x30cefbec2e4bc466`.

* Since `gcd(13, 2^64-1) = 1`, the map is a bijection. With `d = 13^-1 mod (2^64-1)`:

  `serial = ((0x30cefbec2e4bc466 XOR 0xba6b1f3cb925c25a)^d XOR 0xd1705c3b2e33689b) = 0x8f7db18bd70e193b`

### Stage 2 - Activation code (anomalous-curve ECDLP)

The 25 hex characters are read as a **100-bit integer `k`**, then the program performs a
double-and-add scalar multiplication of a base point by `k` on an elliptic curve over
`F_M`, `M = 0x8c817b4a4c0f170cd5aab18cf` (prime, 100 bits). String `Serial > ` etc. live at
`0x4050xx`; the group operation is `0x403ad0` which uses the modular inverse routine `0x403900`
(exponent `M-2`, i.e. Fermat). The base point constants are @ `0x405670` / `0x405680`.

Empirically (emulating `main` under Unicorn and reading the accumulator for `k = 1,2,3,4`) the
result is `k*P` with

```
P = (0xc217d88d4bf005f2022d4e0f, 0x30999f70fb48e2b703431f4d0)
E: y^2 = x^3 + a*x + b  mod M
a = 0x65561c079c3bb669feb4d54d9
b = 0x3905920c79c2f7ace28164fb6
```

The required result is

```
Q = (0x622d01f78ebad9c83dd402304, 0x387932a13c1ef33f165880b6)
```

`#E(F_M) = 695750960437370813140792187087 = M`, i.e. **trace 1 → the curve is anomalous**, so
Smart's attack (p-adic elliptic logarithm) solves the discrete log in milliseconds:

```
k = 205340998046118030005408178596 = 0x2977e17b118de75b3b4e921a4
```

### Flag derivation (with the intentional work factor)

After both checks pass, the flag buffer is `table64[i] XOR buf2[i]` where `table64` is the 64-byte
constant @ `0x405200` and `buf2` is a SHA-256-based expansion of the activation data. Before that,
`0x4037b0` runs a **deliberate 0xc350 × 0x2710 = 500,000,000-iteration** big-integer
square/reduce loop (a proof-of-work / anti-reversing delay). The loop genuinely feeds the digest,
so it must actually run; it is why the program "hangs" for ~15 - 20 min before printing. The final
check is that the byte-sum of the produced 64-byte buffer equals `0x133d`, and on success it prints
`Correct! The flag is %s\n`.

## Verification

* Stage-1 serial: `(serial^C11)^13 ^ C13 == 0x30cefbec2e4bc466` ✔
* Stage-2: `k*P == Q` on E/F_M ✔ (Smart's attack)
* End-to-end: `./Entitlement` prints the flag, and its byte-sum equals the program's own `0x133d`
  gate ✔
