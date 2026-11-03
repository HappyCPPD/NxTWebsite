# Forgotten Secrets

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{m3m0ry_dump_d1g_d33p}`

---

**Flag:** `hiCTF{m3m0ry_dump_d1g_d33p}`

## Files
- `forgotten-secrets.zip` → `forgotten_secrets.bin` (262144 bytes, "ELF 64-bit LSB *unknown arch 0xffffc4aa*")

## Analysis
The `.bin` is a 256 KiB memory dump. Despite the ELF magic at offset 0, the rest is
uniformly high-entropy (≈7.99 bits/byte across the whole file), i.e. random-looking
noise. `strings` surfaced many decoys:

- `This is not the flag you are looking for`
- `flag_not_here_keep_looking`
- `base64_encoded_nothing_useful_here`
- `AES-256-CBC encrypted block follows`
- `CAFEBABE` / `DEADBEEF` / `TryHarder!`
- fake creds (`password123!@#`, `hunter2`, `root:x:0:0`, ssh key headers, JWT, etc.)

None is the flag - the description warned it would not show up in a simple string search.

## Solve
The data is XOR-obfuscated with a single repeating byte. Brute-forcing all 256 single-byte
XOR keys and grepping for `hiCTF` / `CTF{` immediately revealed the flag with key
`0x42` (`'B'`):

```python
data = open('forgotten_secrets.bin','rb').read()
x = bytes(b ^ 0x42 for b in data)
i = x.find(b'hiCTF{')
print(x[i:x.find(b'}', i)+1].decode())
# hiCTF{m3m0ry_dump_d1g_d33p}
```

`hiCTF{m3m0ry_dump_d1g_d33p}`
