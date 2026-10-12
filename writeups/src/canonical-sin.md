# Canonical Sin

**Event:** CryoVault CTF 2026
**Category:** web
**Flag:** `isfcr{c4n0n1c4l_d1ff3r3nt14l_t4g_55799_1s_th3_s3lf_d3scr1b3_tr4p_2ec4}`

---

A "capability broker" issues COSE-Sign1-style CBOR tokens (`header.payload.signature`, Ed25519) after `/auth/login`. The signature is a genuine COSE `Signature1` over the raw protected-header and payload bytes - verified locally, no canonicalization bypass available there; tampering with any byte breaks verification.

`/vault/secret/flag` requires `role == "admin"`. The real attack surface is `POST /auth/mint`, an undocumented method-specific route that merges attacker-supplied `extra_claims` into a freshly re-signed token, subject to three filters: (A) a raw-byte blocklist for literal strings like `admin`; (B) a decoded-value blocklist (case-insensitive scan of decoded string values); (C) a semantic check that a text-string `role` must equal `"user"` (non-string "structured claim objects" are allowed through).

## Exploit - two CBOR canonicalization tricks combined

1. **Indefinite-length string to beat filter A:** encode `"admin"` as an indefinite-length CBOR text string split into chunks (`7f 63 "adm" 62 "in" ff`) - the raw bytes never contain the contiguous ASCII `admin`, so the byte-level blocklist misses it.
2. **CBOR tag 55799 (self-describe) to beat filters B and C:** wrapping the value in tag `55799` makes the mint filter treat the claim as a structured object (skipping the string-role check and the value-literal scan), while the final CBOR decoder that builds the real token payload transparently **unwraps** the tag back to the bare string `'admin'`.

```
map(2):
  "role" -> tag55799( indef("adm"+"in") )     # decodes to "admin", raw bytes clean
  "caps" -> ["read:vault"]
```

The broker re-signs this, producing a token that decodes to `{'role':'admin', 'caps':['read:vault'], ...}`.

```
GET /vault/secret/flag -> 200
isfcr{c4n0n1c4l_d1ff3r3nt14l_t4g_55799_1s_th3_s3lf_d3scr1b3_tr4p_2ec4}
```

Root cause: `/auth/mint` performs validate-then-reserialize with a filter/decoder pair that disagrees on non-canonical CBOR - the filters assume canonical encoding (contiguous string bytes, bare values) while the serializer's full decoder normalizes tags and indefinite-length items. The fix is to canonicalize once (RFC 8949 §3.9/§4.2), validate the canonical form, and sign exactly that - rejecting tags and indefinite-length items in security-sensitive tokens.
