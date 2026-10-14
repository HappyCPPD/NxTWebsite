# Palimpest

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{p4p3r_r3m3mb3rs_wh4t_1nk_f0rg3ts}`

---

> Flag: **`isfcr{p4p3r_r3m3mb3rs_wh4t_1nk_f0rg3ts}`**
> Confirmed live: `Seal accepted. Job 04 restored.`

## 0. The prompt
"The night shift at Bellwether Printworks left job 04 unfinished. The press still
recognizes the operator's seal, but the original has vanished beneath layers of
calibration ink. Restore the job and recover the accepted seal." The service card
adds: display-case labels came from earlier shifts; the paper moves as part of the
mechanism; the night engineer left a mirror on the workbench.

We get a single 4200-byte `palimpsest` ELF. Running it:

```
$ echo '?' | ./palimpsest
PALIMPSEST / Restoration Press 04
Supply the restoration seal, or ? for the archive catalogue.
> 
PALIMPSEST / surviving job cards
--------------------------------
JOB 00  SELFTEST ONLY; commissioning print, no live seal.
        isfcr{th3_pr3ss_p4ss3d_1ts_s3lf_t3st_0}
JOB 02  SUPERSEDED; cancelled before the final impression.
        isfcr{0ld_1nk_n3v3r_t3lls_n3w_t4l3s_v2}
JOB 04  ACTIVE; eight registers, one sheet, many impressions.
        The press remembers the paper's position.
VERSO   .noisserpmi tsal eht ta strats noitarotseR
```

The two catalogue flags are the "display-case labels from earlier shifts" - decoys.
`VERSO` is a reversed string: "Restoration starts at the last impression."

## 1. Recon
```
$ file palimpsest
ELF 64-bit LSB executable, x86-64, statically linked, stripped
```
Built with Zig (Linker: LLD / zig-bootstrap). Only ~1.4 KB of `.text` (0x10018d0,
size 0x5ca) and a 0x7b0 `.rodata`. Everything is raw syscalls. `strings` shows the
banner, the two verdicts, the catalogue, and one long random-looking blob - the
0x500-byte **bytecode** at file 0x3d0.

Program headers give the trivial mapping `file_offset = vaddr - 0x1000000`, so
`.rodata` at 0x1000120 = file 0x120, and the bytecode at 0x10003d0 = file 0x3d0.

## 2. The input check
`objdump -d -M intel` shows the entry reads bytes one at a time with `read(0,buf,1)`
into `rbp-0x50`, appends non-newline bytes to a buffer at `rbp-0x90`, and then:

```
cmp r8d,0x27                        ; length must be 39
cmp DWORD PTR [rbp-0x8f],0x72636673 ; bytes[1..4] == "sfcr"
cmp al,0x69                         ; bytes[0] == 'i'
cmp BYTE PTR [rbp-0x8b],0x7b        ; bytes[5] == '{'
cmp BYTE PTR [rbp-0x6a],0x7d        ; bytes[38] == '}'
```
So the input is `isfcr{` + 32 bytes + `}`. Those 32 bytes are then copied into two
16-byte SSE registers:

```
movups xmm0,[rbp-0x8a]   ; bytes[6..21]  -> [rbp-0x50]  (regs 0..3)
movdqu xmm1,[rbp-0x7a]   ; bytes[22..37] -> [rbp-0x40]  (regs 4..7)
```

**The 32-byte body *is* the eight 32-bit registers** ("eight registers, one sheet").
Everything else is a bytecode machine that shuffles these eight dwords.

## 3. The virtual machine
The main loop runs 160 iterations. Each iteration consumes 8 bytecode bytes at
`rdx = 0, 8, …, 0x4f8` and does two things:

**(a) Decode.** A rolling hash keyed by `r9` turns the 8 bytes into an opcode and
operands:
```
h0 = rol5(r9 + b0 + rdx + 0x9e3779b9) ^ 0xa5a5f00d
lim1 = (h0>>24) ^ b1      ; must be <= 7   (used as a register index)
h1 = rol5(h0 + b1 + rdx + 0x9e3779ba) ^ 0xa5a5f00d
lim2 = (h1>>24) ^ b2      ; must be <= 7   (register index)
h2 = rol5(h1 + b2 + rdx + 0x9e3779bb) ^ 0xa5a5f00d
lim3 = (h2>>24) ^ b3      ; must be 1..31  (rotate amount)
... h3..h6 ...
sel  = (r9>>24) ^ b0      ; must be one of the 8 opcodes
```
Each of these range checks is a hard reject - a wrong state yields garbage and the
program bails to `Seal rejected.` So the *register values act as the key that
decrypts the bytecode*: "the paper moves as part of the mechanism."

**(b) Dispatch.** `dst = (lim1+P)&7`, `src = (lim2+P)&7` where `P` (`r15`) is a
3-bit pointer (starts at 3). The selector picks one of eight ops:

| sel | op | semantics |
|-----|----|-----------|
| 0x27 | ADD imm | `reg[dst] += ebx` |
| 0x13 | XOR imm | `reg[dst] ^= ebx` |
| 0x39 | ROL reg | `reg[dst] = rol(reg[dst], lim3)` |
| 0x4d | MUL imm | `reg[dst] *= ebx` (needs `ebx` bit0 = 1) |
| 0x62 | ADD ROL | `reg[dst] += rol(reg[src], lim3)` |
| 0x78 | XOR ROL | `reg[dst] ^= rol(reg[src], lim3)` |
| 0x8b | SWAP | `swap(reg[dst], reg[src])` |
| 0xa6 | MOVE P | `P = (P + r11) & 7` |

where `ebx`/`r11` are further hash limbs built from the same bytes (still keyed by
`r9`). The dispatch splits at `sel > 0x61` into two code paths, but both restore
`r15 = P` - the pointer only moves on `0xa6`.

**(c) Epilogue / re-key.** After the op, the *new* register state feeds the next
key:
```
r9_next = esi
        + rol7( rol5(rdx + (h6 + b7) + 0x9e3779c0)
                ^ regs[(P+esi)&7]
                ^ rol11(regs[(P+esi+3)&7])
                ^ 0xa5a5f00d )
        + 0x7f4a7c15
```
That `^ regs[...] ^ rol(regs[...])` term is why the opcode stream is data
dependent: "the night engineer left a mirror" - the machine only "sees" itself.

**(d) Final gate.**
```
cmp r15d,1                    ; P must be 1
add ecx,esi ; cmp ecx,0xf7f77ddb
pcmpeqd regs0..3, [0x1000130] ; == 0xe74d487f 0x3d01bcd0 0xcd6b620a 0xd803ecbd
pcmpeqd regs4..7, [0x1000120] ; == 0xe8ee0984 0x00c1e0d9 0xcee2bffa 0xcda90206
```
All four lanes of both halves must match → only one 32-byte body satisfies it.

## 4. Solving
The run is fully deterministic given the initial 8 registers, but the control flow
is data-dependent, so I turned the whole thing into a bitvector formula and let an
SMT solver find the unique body.

I re-implemented the loop exactly (a concrete Python twin, `conc.py`, was first
validated against the binary under gdb: for `isfcr{AAAA…}` both agree - step 0
decodes `sel=0x4d dst=2 lim1=7 lim2=3 lim3=30`, and the re-keyed `r9` after step 0
is `0x34ce5ef1` in both). Then I symbolised the 8 registers and asserted, for every
step: the range checks, the selector in the valid set, the `dst!=src` guards for
`0x62/0x78/0x8b`, the `ebx&1` guard for `0x4d`; plus the final register equality,
`P==1`, and the `ecx+160` check. Add "body is printable ASCII" and solve.

Registers are indexed by *symbolic* values, so reads use an 8-way `ITE` chain and
each op's write is `ITE(sel==op ∧ dst==k, …, old)`. This is QF_BV; **bitwuzla**
(`bw_solve.py`) cracks it in seconds. A z3 port (`solve_print.py`) works too but is
slower and memory-hungry.

```
$ python3 bw_solve.py print
RESULT: sat
FLAG: isfcr{p4p3r_r3m3mb3rs_wh4t_1nk_f0rg3ts}

$ printf 'isfcr{p4p3r_r3m3mb3rs_wh4t_1nk_f0rg3ts}\n' | ./palimpsest
> Seal accepted. Job 04 restored.
```

## 5. Bugs that cost time
1. **z3 `>>` is an arithmetic (sign-extending) shift.** My rotate helper
   `(x<<n)|(x>>(32-n))` was correct in Python (ints) but wrong in z3 once the
   operand became symbolic and the top bit was set → the model went UNSAT at step 3
   and stayed UNSAT. Switching to `z3.LShR` fixed it (`N=3` became SAT).
2. **The epilogue adds `b7`, not the loop counter.** The assembly does
   `movzx esi,[rdx+7]` then `mov r14d,esi`, clobbering the counter before
   `add edi,r14d`. Using the counter produced wrong re-keys.
3. The two decoy flags are *not* accepted by the live job - only the catalogue
   prints them, so `?` output must not be trusted as the answer.

## 6. Hint mapping
- "eight registers, one sheet, many impressions" → 8-register VM over the one 32-byte body.
- "the press remembers the paper's position" → the pointer `P`/`r15` and the rolling `r9` key.
- "the paper moves as part of the mechanism" → the key depends on the (moving) register state.
- "mirror on the workbench" → the self-referential `regs[...] ^ rol(regs[...])` re-key.
- "display-case labels came from earlier shifts" → the JOB 00 / JOB 02 decoys.
- "VERSO / Restoration starts at the last impression" → reason from the final compare
  (the last impression) backwards - which is exactly what the SMT model encodes.

