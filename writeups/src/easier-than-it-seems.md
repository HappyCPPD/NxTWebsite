# Easier Than It Seems

**Event:** SolarCTF
**Category:** forensics
**Flag:** `SOLARCTF{NGC_n3v3r_sl33ps_0nl1n3}`

---

Flag: `SOLARCTF{NGC_n3v3r_sl33ps_0nl1n3}`

## Recon

The task gives you a UAC archive (uac-webtestinc-linux-20261014085246.tar.gz) from a compromised
web testing box. Description says the attackers got in, the system was never rebooted, find the
malware and pull the flag out of it. The "never rebooted" part is the hint that matters, it means
runtime artifacts are still there.

After unpacking, the process listing has two things that jump out:

- PID 18400 running `/usr/sbin/sshd` with the binary marked **(deleted)** in maps, started at 08:41,
  not a child of systemd (the real sshd listener is PID 1397)
- two kernel threads named `[psimon]` (774 and 17715), which is not a kernel thread name any
  distro ships, so probably some rootkit module, but that turned out to be flavor text

The fake sshd is listening on port 41095. Classic deleted-but-running backdoor, and exactly why
you don't reboot a compromised box before triage.

UAC saved us one step: because the process was still alive, it copied `/proc/18400/exe` for us as
`recovered_exe`. That is the malware sample, 3.8 MB, stripped PIE.

## First pass on the sample

Dynamically linked Rust binary, statically obvious nothing. Strings are all crate noise
(hyper, reqwest, rustls, tokio...) until you grep for registry paths and see this:

```
/home/user/.cargo/registry/src/index.crates.io-.../aegis_vm-0.2.52/src/state.rs
```

`aegis_vm` is a real obfuscation crate ("RustAegis", VM virtualization framework, on crates.io).
So the sensitive logic is compiled into custom bytecode that runs on an embedded interpreter.
That explains the heavy obfuscation.

Dumping the process memory (UAC already had heap snapshots in `sections/`) and unswapping them
gave two useful strings the binary does not contain in plaintext:

- the full analysis tool blacklist (`ida;ghidra;radare2;strace;gdb;wireshark;frida;...`)
- the C2 URL `https://httpbin.org/get`

Both are decoded at runtime, so plain strings on the file finds nothing.

## Getting the thing to run

Everything after this was done in a throwaway docker container with no internet, binary mounted
read only.

Running it gives:

```
[signal] art not found

> ACCESS:
[!] access denied -> fallback
```

so there is a password prompt. Under strace (renamed, since it scans process names) it reads
`/proc/self/status`, sees a tracer, and exits silently. Under plain LD_PRELOAD hooks it works
fine, so detection is tracer based, not preload based.

qemu-user with the gdb stub turned out to be the clean way to debug it. The guest reads qemu's
own /proc/self/status, TracerPid stays 0, and gdb talks to the stub where the malware can never
see it. Two gotchas worth writing down:

- the malware scans /proc for blacklisted *substrings* in cmdlines, and `qemu-x86_64 -strace`
  contains "strace". Use the QEMU_STRACE env var instead, the cmdline stays clean
- it forks, and which side does the prompt vs the decoy output confused my breakpoints for a
  while. The "[signal] art not found" line comes from one side, the ACCESS flow from the other

## The aegis_vm layer

Since the crate is public I pulled aegis_vm 0.2.52 source from crates.io. Relevant pieces:

- the build seed (32 bytes) is reconstructed at runtime as `ENTROPY_POOL[idx] ^ SEED_DELTAS[i]`
  against a 1024 byte pool in .rodata. In the binary this compiles down to a chain of
  `movzx eax, byte [rax+r14]; xor al, imm8` blocks
- VM bytecode blobs sit right after the pool, AES-GCM encrypted with whitebox derived keys
- opcodes are shuffled per build, table generated from HMAC-SHA256(seed, "opcode-shuffle-v1")
  and a Fisher-Yates with the crate's BuildRng
- there is also a separate config-string obfuscation: plain XOR against per-build tables

Breaking at the four call sites that pass blobs to the interpreter (0x1b085d / 0x1b0f4d /
0x1b15cd / 0x1b1c4d) and dumping [rsp+8] gave the runtime-reconstructed 32 byte seed:

```
1aa9d331d0715aed3aa1f42a8c5c8966780bc62ca493bde9039dd13f5bea0854
```

With that seed I recomputed the opcode shuffle offline in python (BuildRng + Fisher-Yates from
build.rs, the ordering of BASE_OPCODES matters), and dumped the four decrypted VM programs out of
the interpreter's memory (145, 140, 340 and 340 bytes).

Then I wrote a small Unicorn harness that loads the PIE, applies relocations, stubs malloc/free
in the GOT, and calls the interpreter entry directly. It reproduces the malware's outputs exactly
(which I verified against live runs). The four programs turn out to be:

- P1: linear, out = param*9063 + 13
- P2: affine 64 bit hash, invertible
- P3: real hash with rotations
- P4: byte transformer table

Nice, except none of them is the password check. Feeding input and watching the decrypt calls
showed they never receive anything derived from stdin. Rabbit hole, mostly. The useful leftovers
from this stage were the integrity hashes (custom FNV with basis 0xcfd1aab5a0dd1a35 and prime
0x37ab00000001b3), which confirm which buffers are live, and the config decoder.

## The config strings

One helper at 0x17b6d0 decodes embedded blobs with a formula visible right in the loop body:

```
out[i] = (13*i) ^ blob[len-1-i] ^ tbl[i & 7] ^ 0x2d
```

with tbl at 0x38908. Decoding every blob referenced by callers gives the malware's config:
the C2 url, `0.0.0.0:0`, `/dev/null`, `src`, and `ACII.txt`. That last one explains
`[signal] art not found`, it tries to load an ASCII art banner file. If you create ACII.txt it
gets echoed back at you. Cute, still not the flag.

## Where the check actually is

The ACCESS flow is a Rust async state machine, which is why nothing obvious ever gets called.
Digging through the poll function (dispatch table at 0x3113c) the states are:

0. print prompt, init
1. read a file / build the expected value
2. read stdin lines into an accumulator, UTF-8 check
3. success path
4. print "[!] access denied -> fallback"

and the decision is a single call at 0x19f24f:

```
call 1a4380          ; (input_ptr, input_len, expected_ptr, expected_len)
test al, al
je denied
```

So all I needed was the second argument pair at that call. Debugger breakpoints on it kept
missing because of the fork mess and qemu slowness, so I stopped being polite and did this
instead:

1. an LD_PRELOAD shim that intercepts openat/read and rewrites `TracerPid:\t<pid>` to
   `TracerPid:\t0` in /proc/*/status reads. Unlike redirecting the file (which its statx checks
   catch) the fd stays real procfs, so the scrub is invisible
2. in the same shim's constructor, find the binary base from /proc/self/maps, mprotect the text
   page, and overwrite the 5 byte `call rel32` at base+0x19f24f with a jump to my logger
   (through a small springboard parked in an int3 cave inside .text, since a direct rel32 to a
   shared lib overflows)

The logger prints both argument buffers and returns "not equal". Result:

```
IN : password123
EXP: ergePAsdf^#$&!SSUAH*S
```

(arg order is input first, expected second, I had them backwards initially.)

## Flag

Feeding the exact bytes `ergePAsdf^#$&!SSUAH*S` at the prompt (careful with shell escaping, the
`$&` will eat your lunch) and the backdoor answers:

```
SOLARCTF{NGC_n3v3r_sl33ps_0nl1n3}
```

There is also a 60 second countdown on stderr after the prompt that eventually drops to the
background listener, which explains the "transitioning to background" string.

## Thoughts

Title is honest in a twisted way. The scary part (the VM) is mostly there to waste your time,
the actual check is one memcmp-ish call you can trap in twenty lines of C once you can see it.
The chain that actually mattered was: know that /proc/pid/exe survives deletion, recognize
aegis_vm as a public crate and read its source, defeat TracerPid anti debug in a way that
survives its statx cross-check, and instrument the compare call directly instead of reversing
the state machine around it.
