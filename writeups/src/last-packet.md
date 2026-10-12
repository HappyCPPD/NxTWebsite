# last packet

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{l33t_c0d3_tw0_sum_f0und}`

---

Given `challenge2.pcap` (13 KB, 112 packets): DNS lookups, benign HTTP browsing, and two internal microservices. The interesting conversation is a developer hitting an internal `twosum-api.internal.corp:9090` service's `/api/v1/twosum/solve` endpoint with `X-Debug-Mode: enabled` and `X-Developer: raj.kumar` headers set.

The response came back `X-Debug-Level: VERBOSE` with a JSON body containing far more than the algorithm's answer - a `debug` object with `internal_key` (hex string) and `enc: "xor"`, plus assorted build/perf metadata. The `enc: "xor"` field is practically a how-to.

**Decoding:** hex-decode `internal_key` → ASCII base64 string → base64-decode → raw bytes. Since the flag format `isfcr{` is known, the single-byte XOR key is derived from the first bytes: every byte of `(decoded[i] ^ expected_char[i])` comes out to the same value, `0x42`, confirming a single-byte key.

```python
import base64
key_hex = "4b7a456b495441354c6e467..."
data = base64.b64decode(bytes.fromhex(key_hex) + b"=")
flag = bytes(b ^ 0x42 for b in data).decode()
isfcr{l33t_c0d3_tw0_sum_f0und}
```

The vulnerability: a debug endpoint accessible on an internal network returned sensitive cryptographic material in its verbose response, "encrypted" with a trivially reversible single-byte XOR. A textbook case for stripping debug fields behind a build flag rather than a request header a developer can toggle at will.
