# Tasmota Vault

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{b3rry_r0t4t10n_c94934d76344ab1151e03afd}`

---

## Summary
An ESP32 Tasmota32 v15.6.0 flash image contains a custom Berry agent plus a
LittleFS partition holding a vault (device id, per-epoch keyring, sealed
record). A short MQTT capture delivers the `VaultRotate` request (epoch +
nonce) the gateway authenticated. Reconstructing the agent's `unseal()`
routine from the Berry bytecode and replaying the KDF/AEAD offline recovers
the sealed record.

**Flag: `hiCTF{b3rry_r0t4t10n_c94934d76344ab1151e03afd}`**

## Files
- `flash.bin` - 4 MiB ESP32 flash, physical offsets preserved.
- `mqtt.pcap` - MQTT 3.1.1 lab traffic (historical state + a TCP retransmit).
- `upstream/Tasmota-v15.6.0.tar.gz` - pinned source (Berry + `berry_port`).

## 1. Partition table
ESP32 partition table at offset `0x8000`:

| label    | type/subtype | offset   | size     |
|----------|--------------|----------|----------|
| nvs      | 1/2          | 0x9000   | 0x5000   |
| otadata  | 1/0          | 0xe000   | 0x2000   |
| safeboot | 0/0          | 0x10000  | 0xd0000  |
| app0     | 0/0x10       | 0xe0000  | 0x2d0000 |
| spiffs   | 1/0x82       | **0x3b0000** | **0x50000** |

The partition labelled `spiffs` actually holds LittleFS (disk format 2.0,
erase block 4096) per `recovery.txt`.

## 2. Carve and read LittleFS
```bash
dd if=flash.bin of=/tmp/lfs.img bs=1 skip=$((0x3b0000)) count=$((0x50000))
```
Read with `littlefs-python` (mount via `LittleFS(block_size=4096, block_count=128)`,
`fs.context.buffer = image`, `fs.mount()`). Extracted:

- `/autoexec.be` - `load("vault.bec")`
- `/vault.bec` - 1464 bytes, Berry bytecode v4 (32-bit int/float)
- `/vault/device.id` - 16 bytes  `f5ed39bba88daddd7159956e7ee8254b`
- `/vault/keyring.bin` - 108 bytes = 3 × (4-byte LE epoch || 32-byte key)
- `/vault/sealed.bin` - 74 bytes  = 12-byte IV || 46-byte ciphertext || 16-byte tag

keyring entries: epoch 6, 7, 8 with 32-byte keys each.

## 3. MQTT traffic
```bash
tshark -r mqtt.pcap -Y mqtt -T fields -e mqtt.topic -e mqtt.msg
```
Publishes on `farm/gw-01/cmnd/VaultRotate` (JSON, hex payloads):

- epoch 7: `{"device":"f5ed…254b","epoch":7,"nonce":"9bb1…65f0"}`
- epoch 8: `{"device":"f5ed…254b","epoch":8,"nonce":"1a3d…2606"}`

(`nonce` is a 32-byte hex value; the epoch-8 publish is a TCP
retransmission/duplicate of the same rotation.)

## 4. Decode the Berry agent
Use the pure-Python Berry port from the pinned source:
```python
import sys; sys.path.insert(0,'.../lib/libesp32/berry')
from berry_port import be_vm, be_bytecode, be_debug
vm = be_vm.be_vm_new()
cl = be_bytecode.be_bytecode_load(vm, 'vault.bec')
be_debug.be_dumpclosure(cl)   # + walk proto.ptab for sub-protos
```
The port's defaults (`BE_INTGER_TYPE=0`, `BE_USE_SINGLE_FLOAT=1`) already match
the bytecode header (`BE CD FE 04 00 …`).

`unseal(request)` reconstructed:

1. `req = json.load(request)`; verify `bytes(req.device) == read_blob("vault/device.id")`.
2. `epoch` must be `int` and `>= 1`; `nonce` must be 32 bytes.
3. Look up the 32-byte key for `epoch` in `vault/keyring.bin`
   (entries of `4 + 32` bytes); missing epoch → error `epoch`, more than one
   → `duplicate epoch`.
4. `info = bytes().fromstring("tasmota-vault/unwrap/v2") + bytes("00")`
   → `b"tasmota-vault/unwrap/v2\x00"`.
5. `derived = HMAC_SHA256(key, info + device.id + epoch_le4 + nonce)`.
6. `gcm = crypto.AES_GCM(derived, sealed[0:12])`
   `plaintext = gcm.decrypt(sealed[12:58])`; `gcm.tag() == sealed[58:74]`.

Note the vm uses inclusive ranges for slices, so the split is IV `[0:12)`,
ciphertext `[12:58)`, tag `[58:74)`.

## 5. Recover the record
```python
import hmac, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key  = bytes.fromhex("770a76ce441e8722482aa05dcc8f06424a4ade0c3cf0f0e01676a9d0ac69ef66")  # epoch 8
dev  = bytes.fromhex("f5ed39bba88daddd7159956e7ee8254b")
non  = bytes.fromhex("1a3dfb1382455e073f25450c8c8cee24ba89b0a924f86b7103a732ab902a2606")
msg  = b"tasmota-vault/unwrap/v2\x00" + dev + (8).to_bytes(4,"little") + non
dk   = hmac.new(key, msg, hashlib.sha256).digest()
iv, ct, tag = sealed[:12], sealed[12:58], sealed[58:]
pt   = AESGCM(dk).decrypt(iv, ct + tag, None)
```
Only the epoch-8 request (with a NUL separator) yields a valid GCM tag
(the epoch-7 historical request does not authenticate).

Result: `hiCTF{b3rry_r0t4t10n_c94934d76344ab1151e03afd}`

## Flag
```
hiCTF{b3rry_r0t4t10n_c94934d76344ab1151e03afd}
```
