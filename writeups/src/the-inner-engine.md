# The Inner Engine

**Event:** HICyberCon CTF 2026
**Category:** rev
**Flag:** `hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}`

---

**Flag:** `hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}`
**Valid activation key:** `L1c#N0d3_7mQ9f3a2b8c6d1e` (exactly 24 bytes)

Verify:

```
$ ./inner-engine 'L1c#N0d3_7mQ9f3a2b8c6d1e'
hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}
```

Any other input (including no argument) prints `license sealed`.

---

## 1. Triage

```
$ file inner-engine
ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
```

* Compiled by **Nim** (`syncio.nim`, `raiseEIO`, `readFile`, `IndexDefect`, Nim signals/exception strings in `.rodata`).
* Strings are **XOR-obfuscated with 0x3c**. The literal `"license sealed\n"` does not appear in the file; it is decoded at runtime.
  * `.rodata` @ `0x406298` holds the 15-byte blob `50 55 5f 59 52 4f 59 1c 4f 59 5d 50 59 58 36`; XOR 0x3c ⇒ `"license sealed\n"`.
* Anti-debug present: developer reads `/proc/self/status` and looks for `TracerPid:`.
* All imports are the Nim runtime; the real logic lives in a bespoke **bytecode VM**.

## 2. Finding the check

`write(2)` tracing showed the sealed message is emitted via stdio at exit and the string is built at `0x4046be` (XOR 0x3c loop). Backtracing the print showed the dispatch chain
`main(0x400530) → 0x4048eb → 0x404871 → 0x4047ad`.

`0x4047ad` is the front door:

```
call 403b75           ; Nim paramStr/paramCount
cmp  $0x1,%rax        ; exactly one CLI argument?
jne  .sealed
cmpq $0x18,0x8(%rdx)  ; argument length == 24  (0x18)
jne  .sealed
... copy 24 bytes of argv[1] into the string @0x40aa70 ...
call 404709           ; <-- run the VM
cmpl 0,0x40aa40       ; success flag set by VM?
je   .sealed
```

So the key must be **exactly 24 bytes**, otherwise it is rejected before the VM even starts.

## 3. The bytecode VM

VM interpreter @ `0x404709`:

* Program counter `ip` @ `0x40aa58`, current operand `imm` @ `0x40aa50`, halt-state `0x40aa48`, success flag `0x40aa40`.
* Data-stack helpers: gen-`seq[int]` @ `0x40aa80` (len @ `0x40aa80`, data @ `0x40aa88`).
* Register/indexed memory: `uint32 mem[]` @ `0x40aa60`.
* Input string descriptor @ `0x40aa70` (`{len, ptr}`); characters start at `ptr+8`.
* Program: **1126 bytes @ `0x405e00`** (`.rodata`), decoded as fixed **5-byte instructions** `opcode, u32 imm` (little-endian), `ip += 5`.
* Dispatch table is built at startup into `0x40a240` (256 entries) - dump it from a live process.

Dumped runtime dispatch table + handler disassembly give the full ISA:

| op | handler | meaning |
|----|---------|---------|
| `0xf2` | 0x403fe3 | push anti-debug result (1 if clean) |
| `0x49` | 0x403db7 | JZ imm - pop; if 0 → jump (used to jump to the fail block) |
| `0x0b` | 0x404416 | decrypt + validate + print the activation record |
| `0xe5` | 0x403bf0 | state=1 (success) |
| `0x5a` | 0x403bfc | state=2 (fail) |
| `0x17` | 0x403c14 | push imm |
| `0x4c` | 0x403c1c | push zero-extended input[imm] |
| `0x95` | 0x403c30 | push mem[imm] |
| `0x38` | 0x403c9c | mem[imm] = pop() |
| `0x2b` | 0x403c9a | pop/drop |
| `0xa3` | 0x403c64 | dup |
| `0x6e` | 0x403c78 | swap |
| `0x7d`/`0xc1` | | add / sub |
| `0x52`/`0x8a` | | xor / mul |
| `0x33`/`0xbf` | | and / or |
| `0x1e` | 0x403d51 | eq (push 1/0) |
| `0x64`/`0xcc` | | rol imm / shl imm |
| `0x71`/`0xae` | | neg / not |
| `0xd7` | 0x403be2 | jmp imm |

### Program flow

1. `ip=0`: anti-debug (`0xf2`); if traced, `0x49 → 0x6e` jumps to `0x5a` (halt/fail). A *clean* run pushes 1, so it passes.
2. `mem[0..3]` are computed from input bytes `k0..k3` (the ROL-8/ROL-24 pair is a no-op, so `mem[i]=k[i]`).
3. A linear chain of `compute → 0x49 0x6e (JZ fail)` checks.
4. On success `0x40483e` reaches `op 0x0b` @ ip 1165, which XOR-decrypts the 40-byte blob at `0x4062e0` with key material derived from the input, validates it against a 32-byte digest @ `0x4062c0` (SHA-256), and prints the plaintext - the flag. Then `op 0xe5` sets success.

## 4. Solving the key

The 23 non-trivial checks (after symbolic execution) are, with `k[i] = key byte i` and all arithmetic mod 256:

```
k5^k6=84   k9+k10=164  k10+k11=190  k12+k13=159 k13+k14=153
k14+k15=148 k16+k17=148 k17+k18=154 k18+k19=155 k19+k20=153
k20+k21=154 k22+k23=150 k23+k0=177
k3*k15=67  k7*k21=236  k11*k19=83
k0^k8^k16=33   k4^k12^k20=65  k2^k10^k18=54
k1^k5^k9^k13^k17^k21=86
k3^k6^k11^k14^k19^k22=119
k0+k4+k8+k12+k16+k20=154   k2+k7+k10+k15+k18+k23=1
```

`vm.py` reimplements the ISA and symbolically executes it with z3 (`BitVec(32)`), asserting every `JZ` operand is non-zero (i.e. every check passes). Enumerating solutions restricted to printable ASCII yields exactly two:

```
FS##F*~}]OUi9f3a:Z@[>\+k
L1c#N0d3_7mQ9f3a2b8c6d1e
```

The residual 1 DOF is pinned by the record's SHA-256 check inside `op 0x0b`. Feeding both to the untraced binary selects the second one.

## 5. Result

```
$ ./inner-engine 'L1c#N0d3_7mQ9f3a2b8c6d1e'
hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}
```

* Key: `L1c#N0d3_7mQ9f3a2b8c6d1e`
* Flag: `hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}`

## Reproduction

```
python3 vm.py concrete ABCDEFGHIJKLMNOPQRSTUVWX   # show check structure
python3 vm.py solve                                # z3-solve the key
./inner-engine 'L1c#N0d3_7mQ9f3a2b8c6d1e'
```

(Set an `ip` breakpoint trick to bypass the anti-debug when inspecting under gdb; the final run must be un-traced.)
