# Fluxgate G3

**Event:** CryoVault CTF 2026
**Category:** pwn
**Flag:** `isfcr{s1gn3d_p4rts_uns1gn3d_whole_ab84f1}`

---

`nc 0.cloud.chals.io 25537`, a simulated maintenance controller with an Ed25519-signed firmware artifact format (`pol`/`tab`/`rad` components, each with a security counter and dependency ranges) and a token/capability-gated command dispatcher.

The controller verifies each firmware artifact **individually** (signature, counter ≥ stored, dependency ranges satisfied) but **never validates the resulting combination as a coherent whole**. A low-tier service credential (`user_id=42`, `caps=0x0003`, no `SERVICE` bit) is issued by default.

**The composition:** `pol-v3rc.fw` is a same-counter "sidegrade" (counter 3 == stored 3, so it's accepted) that adds a handler for opcode `0x70` (UNLOCK) and relaxes the `tab` dependency range. `tab-v3.fw` is a counter-valid upgrade (3 ≥ stored 2) that lowers opcode `0x70`'s required capability from `0x8000` (SERVICE) to `0x0001` (BASIC_READ) - which the default token already has. Neither artifact alone grants anything: v3rc's handler is useless while `tab-v2` still demands SERVICE; `tab-v3`'s lowered requirement is useless without a `0x70` handler in `pol`. Installed together, opcode `0x70` becomes "UNLOCK, requires only BASIC_READ."

```
1. UPDATE pol-v3rc.fw   (sidegrade, counter 3 == 3)
2. UPDATE tab-v3.fw     (upgrade, counter 3 >= 2)
3. BOOT                 (dependency ranges still satisfied)
4. TOKEN                (user_id=42, caps=0x0003)
5. SEND opcode 0x70 with the token -> capability check passes on BASIC_READ
resp_b64=...  ->  isfcr{s1gn3d_p4rts_uns1gn3d_whole_ab84f1}
```

Fix: validate the *set*, not just the elements - pin an authorized (component → version/counter) manifest and verify a single signature over the whole installed image before boot/dispatch. "Signed parts, unsigned whole": composable trust boundaries (here, a policy table plus a capability table) must be validated as a unit, or two individually benign, individually-signed artifacts can degenerate into privilege escalation.
