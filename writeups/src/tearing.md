# tearing

**Event:** CryoVault CTF 2026
**Category:** pwn
**Flag:** `isfcr{t0ct0u_w1nd0w_0nly_0p3ns_c0ncurr3ntly}`

---

`nc 0.cloud.chals.io 26166`. A line-based text protocol: `status`/`redeem`/`claim`/`quit`, "vault" semantics `prizes`/`tickets`/`need=15`. The service shares one mutable `(prizes, tickets)` pair **across every connection** and checks the win guard separately from the update, with no locking:

```python
def claim():
    if prizes >= 15:          # check
        tickets += 1          # act, on a stale snapshot - no lock
        print(FLAG)
```

Because check and act are not atomic, a burst of concurrent `claim`s can all observe `prizes >= 15` simultaneously and all take the success branch. The `tickets > 0` guard on `redeem` tears open the same way, letting `prizes` climb past 15 under load (observed `prizes=17 tickets=-16`, breaking the normally-invariant `prizes + tickets == 1`). Single-threaded play can never escape `prizes = 1` - serial grinding is provably useless.

Extensive negative findings ruled out: command dispatch is pure prefix-match with no hidden commands (119-word sweep), there is no injection surface (format strings, quotes, NULs, long lines all bounce off a plain `?`), and idle-state drift is a red herring unrelated to the exploit.

**Exploit:** 64 threads sending randomised command bursts (`redeem` bursts to drive `prizes` up through the torn guard, `claim` bursts to land inside the window the instant `prizes` crosses 15), one recv per burst, stop on first flag seen.

```
2452  b'no tickets left'
1393  b'isfcr{t0ct0u_w1nd0w_0nly_0p3ns_c0ncurr3ntly}'
 683  b'prizes=17 tickets=-16 need=15'
 259  b'not enough prizes'
```

The flag was returned 1393 times - every racer that entered the window got it, exactly as the TOCTOU model predicts.

```
isfcr{t0ct0u_w1nd0w_0nly_0p3ns_c0ncurr3ntly}
```
