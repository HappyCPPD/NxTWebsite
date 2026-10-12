# signed, but which original?

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{29336738f5f44f4d2d1e3ac2}`

---

`handout.zip` → `case.json` (a case spec the target derivative must satisfy: capture principal, final action `redact`, intermediate actions `crop`/`resize`, max chain 4, parent-before-child, `log_scope: largest_valid_checkpoint`, RFC8785 canonical encoding, target incident id, root key, 5 signed tree heads) + `entries.bin` (magic `ISFCRLOG`, TLV records: key registry, manifest, incident link, tree-head stubs).

Manifests are ed25519-signed over the raw JSON bytes (not over a canonical form - confirmed by local verification). `parent_asset_sha256` links a DAG from capture through derivatives.

**Checkpoint validity** requires both a valid signature over the canonical `{key_id, root_hash, tree_size}` AND a correct RFC6962 Merkle root over the log records, AND an authorized signer. Of the 5 checkpoints: `tree_size=55` has a correct root but forged signature; `tree_size=50` has a valid signature but a root mismatch; `tree_size=52` is signed by the rogue secondary key; only `tree_size=33` and **46** (the largest valid) pass everything - so `log_scope` = records 0..45.

**Finding the derivative:** only one capture (`capture-north`-signed) has a `crop → resize → redact` continuation. Among the redact candidates, each must pass raw-sig validity, RFC8785 canonical JSON, in-scope index, and parent-logged-before-child - eliminating candidates with duplicate JSON keys, unicode-escaped keys, extra spaces, forged signatures, case-mismatched hex links, and out-of-scope indices (idx48 > scope 45). **`mf-ee2392778137`** is the only survivor.

```python
evidence = [derivative_asset, derivative_manifest_id, ancestry_joined,
            capture_asset, target_incident_id, str(tree_size)]
E = json.dumps(evidence, ensure_ascii=True, separators=(",", ":")).encode("ascii")
key = scrypt(b"isfcr-forensics\x00"+E, salt=..., n=131072, r=8, p=1, dklen=32)
flag = AESGCM(key).decrypt(nonce, ct, b"signed-but-which-original")
isfcr{29336738f5f44f4d2d1e3ac2}
```

"signed" ≠ "valid": several redacts carry valid signatures over non-canonical JSON, uppercase hex links, or out-of-scope entries. Merkle-root correctness alone or signature correctness alone is not enough - the largest checkpoint is disqualified on purpose, and `root_key` in `case.json` is a decoy (checkpoints verify against the log key's own registered pubkey).
