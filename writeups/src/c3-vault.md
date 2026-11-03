# C3 Vault

**Event:** HICyberCon CTF 2026
**Category:** misc
**Flag:** `hiCTF{efus3_cl34r_jt4g_0p3n_nv5_017026ab04}`

---

**Category:** hardware / reverse · **Endpoint:** `c3-vault-*.chall.hiddeninvestigations.net:1337`
(TLS, banner `C3VAULT/2`, commands `help status auth <64 hex> quit`).

> Retired ESP32-C3 gateway with access to a remote vault. Recover its enrollment
> credentials and convince the live service that you are the gateway. Flag `hiCTF{}`.

**RESULT:** `hiCTF{efus3_cl34r_jt4g_0p3n_nv5_017026ab04}` (live auth, `VAULT OPENED`).

## 1. Flash decryption
4 MiB `extracted/flash_image.bin` is AES-128-XTS flash-encrypted with the key from eFuse
BLOCK4 (`extracted/efuse_read.bin[0x70:0x90]`, also shipped as `key.bin`). Decrypt with the
canonical tool (a hand-rolled XTS fails because the C3 tweak is `(addr & ~0x7F)` LE over
128-byte blocks, not `addr/16`):
```
espsecure.py decrypt-flash-data -k key.bin -o flash_plain.bin -a 0 -x extracted/flash_image.bin
```
Partition table at 0x8000: `nvs` @0x9000 (0x6000), `nvs_keys` @0xF000 (0x1000), `factory` @0x10000.

## 2. NVS decryption
NVS is NVS-XTS encrypted (page headers plaintext, 32-byte entries XTS'd). Key set =
`nvs_keys[0xF000:0xF040]` (`eky||tky`, AES-256-XTS); tweak = 16 bytes whose first 4 are the
entry's partition-relative byte offset (LE); scheme per ESP-IDF v5.3.1
`components/nvs_flash/src/nvs_encrypted_partition.cpp`. Recovered entries:

| ns | key | value |
|---|---|---|
| `gateway` | `device_id` | `ee0315f3953aad298d7f3f43973ad618` (16 B) |
| `gateway` | `generation` | `7` (u32) |
| `vault_v2` | `seed` | `826e4e9e65c0ce89f413b7c291bb7e84185c64d4ec8769805227253b985083c5` (32 B) |
| `vault_v1` | `seed` | `d857200f87a1728b5220a4d77c31d7d9ee9bf8992ad16dbb398d05844676aa4f` (stale/decoy) |

`device_id` matches the live service's `DEVICE` banner exactly - NVS decryption confirmed.

## 3. Protocol (from the decrypted firmware, project `c3_vault_device`, IDF v5.3.1)
The device console reads a 64-hex challenge and prints `RESPONSE <hex>`; the host verifier
accepts the same value. Message/label layout recovered from `vault.c` (`app_build_response`
@ `0x42004888`, `derive_device_key` @ `~0x42004a84`):

```
key  = HMAC_SHA256(seed_v2, "c3-vault/device-key/v2\0" || device_id || generation_LE4)   # 43-byte info
resp = HMAC_SHA256(key,     "C3VAULT-AUTH-V2\0"        || challenge  || device_id)       # 64-byte msg
```

### KDF identification (correction of the earlier "non-standard KDF" claim)
The KDF wrapper `0x4200c0c4` is textbook mbedtls HMAC: `md_setup(ctx,info,hmac=1)` →
`mbedtls_md_hmac_starts(ctx, key, keylen)` → `mbedtls_md_update(ctx, data, datalen)` →
`mbedtls_md_finish(ctx, out)`; i.e. `F(key, data) = HMAC_hash(key, data)`. The `info` (type 9)
struct is at `0x3c02818c`: `digest_size=0x20` (32), `block_size=0x40` (64) → **SHA-256**
(the banner also says SHA-256). A hand-rolled XTS/emulation was unnecessary.

> A previous session concluded "F is not plain HMAC" and tried to run the firmware's own code
> under Unicorn. That conclusion was an artifact: the emulator produced values matching *no*
> standard construction for any test vector, because mbedtls on the C3 dispatches into ROM SHA
> routines that the emulator had stubbed to NOPs. Do not trust `c3_solve.py`'s output.

## 4. Solver
`c3_solve.py` (plain-Python HMAC; no emulation, no `segs.json` needed) connects, parses the
fresh `CHALLENGE`, computes `key` then `resp` with `hmac`/`hashlib`, sends `auth <resp>`, and
prints the verifier reply.

`./c3_solve.py <host> [port]`
