# VaultKeeper

**Event:** HICyberCon CTF 2026
**Category:** rev
**Flag:** `hiCTF{!!I_10v3_4ndr0!d_m4n_m4k!ng_th3m_f331_g0Od!!}`

---

**Flag:** `hiCTF{!!I_10v3_4ndr0!d_m4n_m4k!ng_th3m_f331_g0Od!!}`

## Artifact

`extracted/VaultKeeper.apk` (SHA-256 `7c0ccbd2…d7aa10`), package `com.hictf.vaultkeeper`,
versionName `2026.1`. Contains `classes.dex`, `resources.arsc`, `assets/vault.bin`
(8192 B, high-entropy random - pure seed material, not a payload), and two JNI libs:
`lib/x86_64/libvaultnative.so` and `lib/arm64-v8a/libvaultnative.so` (stripped, NDK r27).

## Triage - the decoys

The challenge is *dense* with planted decoys. Confirmed dead ends:

| Where | Value | Verdict |
|---|---|---|
| `resources.arsc` | `hiCTF{y0u_f0und_th3_0bv10us_0n3}`, `hiCTF{th1s_0n3_1s_w4y_t00_l0ng…}`, `hiCTF{n0t r3al w1th sp4ces}`, `hiCTF{m1ss1ng_br4ce`, `h1CTF{n34rly_th3r3}` | decoys (strings, obviously fake) |
| `Diagnostics.emitTrace()` (dex) | `hiCTF{l0gc4t_1s_n0t_4_fl4g_s0urc3}` | decoy (self-labelled) |
| `getFlag()` in libvaultnative (exported, **never called**) | `hiCTF{str1ngs_4nd_x0r_w0nt_s4v3_y0u}` | decoy (honeypot; "strings and xor won't save you") |
| `FlagRepository` A..F XOR + `spread()` (no-op) | "master key" | decoy |
| `GestureArmer` (3 taps + long-press), `EnvAudit` (ptrace/frida/root/sig checks) | gates | decoy flavour - the flag is *not* gated behind UI/env |

The real flag is computed inside `nv_final()` - a 51-byte string that is then **memzeroed**,
so it never leaks through `strings`.

## Native flow (from `NativeBridge`)

```
nvSeed(vault, token)          -> cells[128]      (hash-expanded from vault.bin + token)
CellMixer.k1(cells)           -> mixed cells
nvUnseal(cells, token)        -> prog[2048]      (byte stream derived from cells)
CellMixer.k2(prog, cells)     -> prog'
nvExec(prog', cells, token)   -> VM output (64 B into globals 0x8cb0..0x8cef)
nvFinal(token)                -> builds 51/29-byte flag, validates, then memzero
```

`nv_final` builds a 51-byte buffer as
`const1(0x1770) ^ const2(0x17b0) ^ vm_output(0x8cb0) ^ hash_ctx_state`, then checks
`H("VK-TAG-2026" || buf)` (custom hash @ `0x6050/0x6080/0x6320`) against the 16 bytes at `0x17f0`.

* **Match** → the 51-byte string is the real flag.
* **Mismatch** (anti-debug routines @ `0x4f80` dispatched at the start of every `nv_*`
  perturbed state - debugger/`TracerPid` detected) → a taunt flag
  `hiCTF{4nt1_d3bug_f4ncy_p4nts}`.

## Reproducing it on the host (no emulator)

The lib ships an **x86_64 slice**, so it runs on glibc. Steps (all in `/tmp/vk`):

1. **Neutralise bionic versioning** - rewrite the `PT_DYNAMIC` tags `DT_VERNEED`
   (`0x6ffffffe`), `DT_VERNEEDNUM` (`0x6fffffff`) and `DT_VERSYM` (`0x6ffffff0`) to
   `DT_DEBUG` (21). Supply a stub `liblog.so`, symlinks `libc.so`/`libm.so`/`libdl.so`,
   and an `LD_PRELOAD` shim for bionic's `__strrchr_chk` (glibc lacks it).
   `__open_2`/`__cxa_*`/`__register_atfork` exist in glibc already.
2. **Disable the anti-debug dispatcher** `0x4f80` (`31 c0 c3` = `xor eax,eax; ret`) so a
   clean-environment run is simulated (and so gdb can be used).
3. **Drive the pipeline** with a small harness calling the internal functions
   (base = `getFlag - 0x5e00`):
   `nv_seed(vault, 8192, token, cells)`, re-implement `CellMixer.k1`/`k2` in C,
   `nv_unseal(cells, token, prog, 2048)`, `nv_exec(prog, 2048, cells, token)`, `nv_final(token)`.
4. **Capture the flag before it is wiped** - patch `0x66c0` (`memzero`) to jump to a
   `vk_mz(rdi,rsi)` handler (harness built `-no-pie` so its address is fixed) and log the
   64-byte buffers; the `len==64` one holds the 51-byte flag.
   (gdb breakpoint at `base+0x66c0` gives the same result.)

Result (identical across different random `armToken`s → the flag is token-independent):

```
[MZ64] hiCTF{!!I_10v3_4ndr0!d_m4n_m4k!ng_th3m_f331_g0Od!!}
```

5. **Positive control** - call the lib's own hash (`0x6050`/`0x6080`/`0x6320`) as
   `H("VK-TAG-2026" || flag)` and compare to the embedded digest at `0x17f0`:

```
got : 62672db15a0b6a4793b351292f29a0b3
want: 62672db15a0b6a4793b351292f29a0b3   MATCH=1
```

The lib's own verification accepts exactly this string - cryptographically confirming it is
the intended flag (the anti-debug taunt's hash does not match).

## Flag

```
hiCTF{!!I_10v3_4ndr0!d_m4n_m4k!ng_th3m_f331_g0Od!!}
```
