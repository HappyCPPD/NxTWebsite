# Dormant Signer

**Event:** HICyberCon CTF 2026
**Category:** misc
**Flag:** `hiCTF{layout_undead_borrowed_betrays}`

---

**Category:** Blockchain (Vyper / EVM) · launched as `dormant-signer.zip`
(sha256 `9397090f…`)

## Artifact
- `chain/` - `genesis.json`, `transactions.jsonl` (the whole custody-desk history), `replay.sh`, `HEAD`
- `contracts/` - `Authorizer.vy`, `VoucherDesk.vy`, `Notary.vy`

`Authorizer.vy` pays withdrawals against a co-signature from an off-chain
"automated signer". When the desk winds an authorizer down it **files a recovery
escrow** and self-destructs:

```
filed = escrow ^ escrow_mask(liveness signature) ^ running_digest
```

where
- `running_digest = keccak256(concat(prev, keccak256(abi_encode(authorizer, request_id, amount, recipient))))`
  folded over every settled request - recomputable by replaying the chain;
- `escrow_mask(v,r,s) = keccak256(ESCROW_DOMAIN ++ r ++ s ++ v)` over the signer's
  **liveness** signature - `ecrecover(LIVENESS_DIGEST, v, r, s)`, i.e. only the
  signer can produce it.

## Method
1. **Recover the signer private key - ECDSA nonce reuse.** The `authorize`
   co-signatures on the two authorizers leak the same `r` for two different
   messages (the RFC6979 nonce collided across deployments):

   ```
   k = (z1 - z2) * (s1 - s2)^-1 mod n
   d = (s1 * k - z1) * r^-1      mod n
   ```
   `recover.py` → recovered signer keys, e.g. authorizer A
   `c0ecef7be0815db43cf992c33dce2b92739576089c31e30ce0c30ac2e2919e52`.

2. **Recompute the liveness signature** deterministically (RFC6979, low-s,
   `v ∈ {27,28}`, raw `LIVENESS_DIGEST`, no message prefix) and derive
   `mask = keccak(ESCROW_DOMAIN || r || s || v)`.

3. **Replay the chain** into a local anvil, read `storage[14] = masked_secret`
   on the sealed authorizer `0x5ebb…`, and strip the mask:

   ```
   escrow = masked_secret ^ mask        (running_digest already folded into the
                                        filed blob ⇒ it cancels)
   ```

## Repro
```bash
cd chain && DETACH=1 bash replay.sh      # local anvil + replay of transactions.jsonl
python3 ds_open.py                       # recovers key, reads storage[14], unmasks
```
`ds_open.py` prints the escrow plaintext:

```
hiCTF{layout_undead_borrowed_betrays}
```

## Verification
- Key recovery is confirmed by **`ecrecover` over every `authorize`
  co-signature on the destroyed authorizer returning the recovered address**
  (100% match - see `final.py`).
- The unmasked escrow is ASCII and a well-formed `hiCTF{…}` token.

## Tooling notes
- Authorizer filed `masked_secret` at storage slot 14; `running_digest` and
  `settled` follow it - read them with `eth_getStorageAt`.
- Deterministic nonces (RFC6979) meant the "unrecoverable" key was actually
  leaked by a single `r` collision between the two authorizers.
