# echochamber-root

**Event:** CryoVault CTF 2026
**Category:** pwn
**Flag:** `isfcr{t0_w1n_th3_g4me_pl4y_a_d1ff3r3nt_g4me}`

---

Root half of ECHOCHAMBER, building on the User-stage foothold (default creds → Jinja2 SSTI → RCE as `analyst` → sentinel socket nonce computed from leaked source).

The sentinel process holds `CAP_DAC_READ_SEARCH`; any child process it spawns **inherits that capability**, and the `exec_shell` handler lets us spawn an arbitrary command as `sentinel`. So `/root/root.txt` is readable directly through the same socket - no classic privesc technique (SUID binaries, sudo misconfig, kernel exploit) is needed at all.

```python
cmd = base64.b64encode(b"cat /root/root.txt").decode()
# same socket call as the User stage
isfcr{t0_w1n_th3_g4me_pl4y_a_d1ff3r3nt_g4me}
```

Decoys again at `/var/lib/warden/decoy/root.txt` (`isfcr{s0_cl0se_but_s0_f4r}`). Takeaway: "to win the game, play a different game" - instead of fighting file permissions, abuse the capability a reachable service already holds and passes to its children. The sentinel socket was the intended root path all along.
