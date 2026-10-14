# signed, but which original?

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{29336738f5f44f4d2d1e3ac2}`

---

## 0. Handout
`handout.zip` → `case.json` + `entries.bin`.
`case.json` is a "case spec" the target derivative must satisfy:

```
capture_principals     : ["capture-north"]
final_action           : "redact"
intermediate_actions   : ["crop", "resize"]
max_chain              : 4
parent_logged_before_child : true
log_scope              : "largest_valid_checkpoint"
manifest_encoding      : "RFC8785"
target_incident_id     : "incident-d7be9442cb"
root_key               : 304bff5d…b70b03
checkpoints            : 5 signed tree heads (tree_size 55/33/46/50/52)
```

The deliverable is a 6-field evidence list, hashed into a scrypt key that
decrypts an AES-GCM blob. Because GCM is authenticated, **the tag itself is the
oracle** - only the exactly-correct evidence decrypts.

## 1. Reversing `entries.bin`
Magic `ISFCRLOG`, then `[u32 len][record]*`. `record[0]` is a type byte and the
rest is TLV (`tag u8, len u16, value`):

| type | meaning | fields |
|------|---------|--------|
| 0x01 | key registry | 0x01 key_id, 0x02 principal, 0x04 ed25519 pubkey(32), 0x05 epoch, 0x7e "root", 0x7f sig |
| 0x03 | manifest | 0x08 raw-JSON manifest, 0x7e signer key_id, 0x7f ed25519 sig |
| 0x04 | incident link | 0x09 incident_id, 0x0a asset_sha256 |
| 0x02/0x05 | tree-head stubs | key_id + tree_size + sig |

The manifest JSON is `{action, asset_sha256, manifest_id, parent_asset_sha256}`.
`parent_asset_sha256` links a DAG: capture → {crop,resize,recolor,redact,…}.

**Signature scheme:** the 64-byte sigs verify as plain ed25519 **over the raw
JSON bytes** with the pubkey registered under the manifest's signer key_id.
(Also tried sha256(canonical) - wrong.) This immediately exposed forgeries.

## 2. Checkpoint validity
Two independent conditions must hold for a signed tree head:

1. **Signature** verifies with the checkpoint key's own pubkey over
   `JCS({"key_id","root_hash","tree_size"})` (sorted keys, `,`/`:` separators).
2. **Root** equals the RFC6962 Merkle root over the first `tree_size` log
   records, leaf hash = `SHA256(0x00 || record_bytes)`.

Plus the signer must be an **authorized log key** - i.e. the log's own primary
signer `log-primary`, not the secondary.

| tree_size | sig | root | authorized | verdict |
|-----------|-----|------|-----------|---------|
| 55 | ✗ | ✓ | ✓ | invalid (bad sig) |
| 33 | ✓ | ✓ | ✓ | valid |
| 46 | ✓ | ✓ | ✓ | **valid (largest)** |
| 50 | ✓ | ✗ | ✓ | invalid (root ≠ log) |
| 52 | ✓ | ✓ | ✗ (log-secondary) | invalid (rogue signer) |

`log_scope: largest_valid_checkpoint` ⇒ **scope = records 0..45**.

The two "big" decoys are deliberately tempting: 55 has a *correct* Merkle root
but a forged signature; 50 has a *valid* signature but a root that doesn't match
the log; 52 is perfect in every way except it's signed by the secondary key.

## 3. Finding the derivative
`capture_principals = ["capture-north"]` ⇒ capture must be signed by
`k-378c6e054e`. Three captures qualify, but only one has a
`crop → resize → redact` continuation:

```
capture 5fe33137 (idx 6, capture-north)
 └─ crop   9293fe40 (idx 12)
     └─ resize 39b82b8f (idx 17)
         └─ redact … (idx 19,24,33,34,38,41,48)
```

Every redact candidate must then pass: raw-sig valid **and** RFC8785-canonical
**and** inside scope **and** parent logged before child:

- idx19 duplicate `"action"` key → not canonical.
- idx24 `"action":"\u0072edact"` → not canonical.
- idx34 spaces after colons → not canonical.
- idx33 signature invalid (forged).
- idx38 parent `39B82B8F…` uppercase → not the same asset as `39b82b8f…`.
- idx48 valid but **index 48 > scope 45** → outside the relied-upon checkpoint.
- **idx41 `mf-ee2392778137` - the only survivor.**

So the derivative is `mf-ee2392778137` (asset `c40ac4a3268f…`), and its ancestry
from capture to derivative is
`mf-326c47df321e > mf-95efb978da36 > mf-57d2452e846e > mf-ee2392778137`.

The title is literal: several redacts are *signed*; the puzzle is deciding
*which original* (which capture/chain/checkpoint) the answer hangs from - and
only one survives every constraint simultaneously.

## 4. Flag derivation
```python
evidence = [derivative_asset, derivative_manifest_id, ancestry_joined,
            capture_asset, target_incident_id, str(tree_size)]
E   = json.dumps(evidence, ensure_ascii=True, separators=(",", ":")).encode("ascii")
key = scrypt(b"isfcr-forensics\x00"+E, salt=df2fd39a…, n=131072,r=8,p=1,dklen=32)
flag = AESGCM(key).decrypt(nonce, ct, b"signed-but-which-original")
```
Evidence:
```
["c40ac4a3268f0b30aac5a1e344e1e4016b82fbfb1171e86330a64c69e73d6cff",
 "mf-ee2392778137",
 "mf-326c47df321e>mf-95efb978da36>mf-57d2452e846e>mf-ee2392778137",
 "5fe33137c48b34086ca6c2c19723b4916fb13732e465759be10b96dcef825bcf",
 "incident-d7be9442cb",
 "46"]
```
⇒ `isfcr{29336738f5f44f4d2d1e3ac2}`

## 5. Traps summary
- "signed" ≠ "valid": valid signatures over non-canonical JSON, uppercase hex
  links, and out-of-scope entries all fail the case spec.
- Merkle-root correctness alone (55) or signature correctness alone (50) is not
  enough; the largest checkpoint is disqualified on purpose.
- `root_key` in `case.json` is a decoy - the checkpoints verify with the log
  key's own registered pubkey, not the root key.

