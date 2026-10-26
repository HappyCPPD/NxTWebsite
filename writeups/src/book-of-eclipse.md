# Book of Eclipse

**Event:** HITCON CTF 2026
**Category:** pwn
**Flag:** `hitcon{Card_Effect:Flip_any_one_bit_in_IA32_FMASK!At_the_end_of_this_turn_you_will_gain_a_root_shell!!!}`

---

The final exploit works both on a host with FSRM and on one without it, which is what the remote runs.

```
hitcon{Card_Effect:Flip_any_one_bit_in_IA32_FMASK!At_the_end_of_this_turn_you_will_gain_a_root_shell!!!}
```

## 1. The bug

`book_of_eclipse_ioctl` (cmd `0x41004500`) copies a 0x100-byte user buffer,
reads `buf[0]` as a bit index (< 0x20), and **toggles that bit in
`IA32_FMASK`** (`0xc0000084`), then latches `effect_activated = 1` (one-shot).

`IA32_FMASK` is the mask of RFLAGS bits the CPU *clears* on `SYSCALL`. Default
`0x257fd5` contains bit 10 (DF). Clearing bit 10 **unmasks DF**: userland DF now
survives into the kernel, so `rep movsb` inside `copy_from_user`/`copy_to_user`
runs backwards.

## 2. KASLR leak

`uname` `copy_to_user`s a stack `new_utsname`. With DF=1 it walks backwards and
leaks the kernel stack below that buffer into `[dst-~0x30, dst)`. One of the
leaked qwords is a return address into `__do_sys_newuname+0x8e`
(static `0xffffffff810a900e`); matching it modulo 0x200000 yields the slide.

## 3. Stack return-address overwrite

`msgctl(IPC_SET)` → `ksys_msgctl.constprop.0` calls the **frame-less** helper
`copy_msqid_from_user.constprop.0`:

```
mov edx,0x78
call _copy_from_user          ; dst = rsp+0x20 = B
mov rdx,-14; test rax,rax; cmovne rax,rdx; jmp __x86_return_thunk
```

Frame-less helper ⇒ the hijackable slot (`_copy_from_user`'s `ret`) is
`B-0x30`. With DF=1 and `src = P+0x78`: `mem[B-k] = P[0x78-k]` - the whole
region `[B-0x77, B]` is attacker-controlled.

Two practical notes (both measured):
- glibc's `syscall()` clears DF, so any copy that must run *forward* has to use
  raw inline-asm `syscall` (and `cld`/`std` explicitly).
- A DF=0 `msgctl(IPC_SET)` on the same frame copies `[B, B+0x77]` **forward**
  (a "groom") - useful for filling the slots above `B` - but `msgctl_down`
  rewrites the buffer when the msqid is valid, so the groom must use an invalid
  msqid. **Any deep syscall in between destroys the groom** (a `printf`→`write`
  eats ~0x300 of stack): groom and hijack must be adjacent, with no syscall
  between.

## 4. Escalation

```
[B-0x30] pop rdi ; ret
[B-0x28] &init_cred
[B-0x20] commit_creds
[B-0x18] 0xffffffff82001637        ; full KPTI trampoline
[B-0x10] ...
```

`commit_creds(&init_cred)` works - the oops report shows `UID: 0`. `init_cred`
is used rather than a fake cred on purpose: a fake cred lives on the kernel
stack and is destroyed by the syscall-exit path before userland ever runs.

## 5. Returning to userland with PTI on

The short trampoline `0xffffffff8200160a` (`swapgs; …; iretq`, **no CR3
switch**) reaches userland with the *kernel* CR3, where user text is NX:

```
segfault at 401c10 ip 0000000000401c10 sp 00000000004ba9b0 error 15
```

`error 15` = instruction-fetch protection fault. The correct primitive is the
full KPTI user-return trampoline, **entered at `0xffffffff82001637`**
(`mov %rsp,%rdi; mov %gs:sp0,%rsp; push frame; SWITCH_TO_USER_CR3; pop; swapgs;
iretq`). Entering just past `POP_REGS` means the iret frame is read from
`[rdi+0x10 .. rdi+0x30]` = `[B .. B+0x20]` when the chain leaves `rsp = B-0x10`
entirely inside the forward-groom window. **No stack leak and no `pop rsp`
pivot are needed.**

## 6. The subtle one: FSRM changes the copy dispatch

Everything above works locally, but the remote panicked with `RIP: 0x0`. The
remote host lacks `fsrm` (qemu: `host doesn't support requested feature:
CPUID.07H:EDX.fsrm`). Dumping the runtime bytes showed `_copy_from_user` is
**byte-identical** in both configs - yet the behaviour differs. The difference
is in how the copy is *dispatched*:

- **FSRM present**: the copy is inline (`mov %rcx,%rdx; rep movsb`); the
  hijackable slot is `_copy_from_user`'s own ret at `B-0x30` → gadget `P[0x48]`.
- **FSRM absent**: the site is patched into a **`call` to an out-of-line helper
  (`0xffffffff81f5b8a0`)**. The `call` pushes a return address at `B-0x40`, and
  the DF=1 backward copy walks over it, so the helper's `ret` pops the attacker
  value at `B-0x40` → gadget `P[0x38]`.

A clean 0x10 shift of the entry point. Proven by putting a self-loop gadget at
`P[0x48]` (returns to `P[0x38]`) and at `P[0x38]` (hangs), deterministically.

**Fix - a unified payload** that duplicates the first two cells so both entries
converge before `commit_creds`:

```
P[0x38] = pop rdi ; ret      ; [B-0x40]  no-FSRM entry
P[0x40] = &init_cred
P[0x48] = pop rdi ; ret      ; [B-0x30]  FSRM entry
P[0x50] = &init_cred
P[0x58] = commit_creds       ; [B-0x20]
P[0x60] = 0xffffffff82001637 ; [B-0x18]
```

Both paths reach `commit_creds` with `rsp = B-0x18`, return into the trampoline
with `rsp = B-0x10`, and read the same `[B .. B+0x20]` frame. The frame is
placed in **both** the backward (P) and forward (G) windows, so it is right
whether the copy lands 1 byte or 8 bytes at `[B]`.

## 7. Remote harness

`nc bookofeclipse.chal.hitconctf.com 13370` → SHA256 PoW (6 zeros) →
`NEED_UPLOAD_EXPLOIT (y/n)` → `y` → `Input your exploit url :` (serve the raw
ELF from a public URL) → the service boots the VM; type `/tmp/e` at the `~ $`
prompt (it does not auto-run).
