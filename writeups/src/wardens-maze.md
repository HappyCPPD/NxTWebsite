# Warden's Maze

**Event:** HICyberCon CTF 2026
**Category:** rev
**Flag:** `hiCTF{maze-warden-vault-seed-2026_65d2638530}`

---

**Category:** rev / pwn-lite · **Artifacts:** `extracted/maze` (x86-64 Linux **static-PIE**, stripped, Rust), `extracted/README.txt`

> Note: the accepted token is **per-instance** (minted only on a genuine win, see
> "Live service" below). The default-seed value `hiCTF{warden_vault_cleared_845f9b65}`
> recovered from the packaged binary is local-only and is **not** the submittable flag.


## The intended path (engine bug)
Per the challenge text: the vault in the maze centre is sealed on all sides; the way in is a
*genuine mistake in the engine*, specifically a hand-rolled index in the **visibility/render**
code that can be made to land outside the intended cell (a wall becomes floor). The game server
is a line-oriented TCP service (`GAME_PORT`, default 7700, `w/a/s/d` + Enter):

```
./maze            # or: GAME_PORT=7700 ./maze
nc 127.0.0.1 7700
```

## The shortcut I used (the token is seed-derived, not random)
`strings` on the binary reveals the whole prize mechanism:

```
[maze] prize token loaded (value hidden)
hiCTF{warden_vault_cleared_%s}     <- template at .rodata 0x5c5ef
maze-default-seed   FLAG_SEED   RCTF_FLAG   flag.txt   GAME_PORT
```

The startup routine (around file offset .text 0x75d6-0x77f6) resolves the prize token from, in order:
`RCTF_FLAG` env, `FLAG_SEED` env (default **`maze-default-seed`**), else `flag.txt`; it then runs an
HMAC-style construction (the disassembly shows the classic `xor 0x36` / `xor 0x5c` ipad/opad over a
64-byte key, then a SHA-512-family hash at 0x10818) and formats the result into the template with
`hiCTF{warden_vault_cleared_<8 hex chars>}`.

So the token is a deterministic function of the seed - no need to beat the warden, and no need to
reach the live service. Read it straight out of a locally started server's memory
(reading `/proc/<pid>/mem` of a child process is permitted without root):

```bash
python3 - <<'EOF'
import subprocess, time, re
p = subprocess.Popen(['./maze'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
time.sleep(1.2)
regions = [l.split()[0] for l in open(f'/proc/{p.pid}/maps') if 'rw' in l.split()[1]]
for r in regions:
    a, b = r.split('-'); start, end = int(a,16), int(b,16)
    if end - start > 64*1024*1024: continue
    try:
        data = open(f'/proc/{p.pid}/mem','rb',buffering=0).read()  # seek first in real code
    except Exception:
        continue
    m = re.search(rb'hiCTF\{[ -~]{1,80}\}', data)
    if m: print(m.group().decode()); break
p.kill()
EOF
```

Result is stable across runs: `hiCTF{warden_vault_cleared_845f9b65}`.
Sanity check that it really is seed-derived: re-running with `FLAG_SEED=mytest` gives
`hiCTF{warden_vault_cleared_f08ec824}`.

## Live service (the real exploit - this is where the submittable token comes from)
The hosted instance terminates TLS in front of the line-oriented service and routes by SNI,
so plain `nc` sees nothing. It is a **single connection per instance**, and the token is
minted only when you genuinely step onto the `$`.

The bug is in the **visibility/render** path, not movement: as the explored region is
computed, a hand-rolled index into the map can land a cell off and copy a neighbouring
tile's code, flipping a wall to a floor. Wandering and revealing cells eventually turns the
vault's top wall **(9,12)** from `%` into a floor - the vault then has an opening at the top.

`adaptive_client.py` (this directory) does it end to end. It explores nearest-unvisited
cell by cell, and **re-checks every move** whether `(11,11)` is reachable with ordinary
walk rules, so a warden reset can't desync it. On the trigger it BFS's
`(8,12)→(9,12)→(10,12)→(11,12)→(11,11)` and reads the token.

```
python3 adaptive_client.py --tls maze-breach-2baef7987401.chall.hiddeninvestigations.net 1337
```

Observed (reproducible; the trigger is deterministic at move 215):

```
[*] spawn (1, 12)
[*] move 100 pos (7, 16)
[*] move 200 pos (16, 13)
[+] prize reachable after 215 moves (pos (14, 4), 20 steps)
[+] at prize (11, 11)  eof=True
...
  The vault is open. You take the prize.
  hiCTF{maze-warden-vault-seed-2026_65d2638530}
FLAG=hiCTF{maze-warden-vault-seed-2026_65d2638530}
```

Sanity cross-check: the same client run against the packaged binary
(`GAME_PORT=7711 ./extracted/maze`, then `adaptive_client.py 127.0.0.1 7711`) prints the
default-seed token `hiCTF{warden_vault_cleared_845f9b65}` at the identical move 215 - same
mechanism, different seed ⇒ the live win is genuine, not a static string. (The live token
also uses a different template/seed string - `maze-warden-vault-seed-2026_…` - than the
packaged binary's `warden_vault_cleared_…`, confirming the hosted instance carries its own seed.)

## Flag
```
hiCTF{maze-warden-vault-seed-2026_65d2638530}
```
(Local default-seed token, for reference only: `hiCTF{warden_vault_cleared_845f9b65}`)
