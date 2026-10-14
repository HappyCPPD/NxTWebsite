# Fluxgate G3

**Event:** CryoVault CTF 2026
**Category:** pwn
**Flag:** `isfcr{s1gn3d_p4rts_uns1gn3d_whole_ab84f1}`

---

## TL;DR

The controller verifies each firmware artifact **individually** (Ed25519 signature over the
artifact, counter ≥ stored, dependency ranges satisfied) but **never validates the resulting
*combination* as a coherent whole**. You are handed a low-tier service credential
(`user_id=42`, `caps=0x0003`). By **sidegrading** `pol` v3 → v3rc (same counter = 3, allowed)
and **upgrading** `tab` v2 → v3 (counter 3 ≥ 2), the two changes compose into a privilege
escalation that neither artifact would allow alone:

* `pol-v3rc` **adds** a handler for opcode `0x70` (UNLOCK) and relaxes the `tab` dependency.
* `tab-v3` **lowers** opcode `0x70`'s required capability from `0x8000` (SERVICE) to
  `0x0001` (BASIC_READ) - which the issued token already has.

Boot, send a `SEND` frame with opcode `0x70` and your token → the service blob containing
the flag is returned. *Signed parts, unsigned whole.*

---

## 1. Recon

```
$ nc 0.cloud.chals.io 25537
OK Fluxgate G3 (sim)
$ HELLO
OK Fluxgate G3 (sim)
OK vendor_pk=1a3f...e2
$ STATUS
OK booted=False
OK   pol: v3 counter=3 build=0x0303 deps=[tab:v2-v2, rad:v2-v2]
OK   tab: v2 counter=2 build=0x1002 deps=[none]
OK   rad: v2 counter=2 build=0x2002 deps=[none]
```

The service is line-oriented ASCII over TCP; binary blobs are base64 after a `key_b64=` tag.
Device state is per-connection (`RESET` restores factory defaults). Commands: `HELLO`,
`STATUS`, `TOKEN`, `UPDATE <b64>`, `BOOT`, `SEND <b64>`, `RESET`, `HELP`, `QUIT`.

### Artifact format (`docs/artifact.md`)

Big-endian outer layout: magic `"FXG1"`, 4-byte component (`pol`/`tab`/`rad`), `version`,
`sec_counter`, `build_id`, `dep_count` + deps (`name[4] | min | max`, 6 bytes each),
`payload_len`, payload, then a **64-byte Ed25519 signature** over `[0 .. end-64)`.

Update rules (`docs/protocol.md`): (1) vendor signature verifies; (2) artifact counter **≥**
stored counter (equal permitted - "sidegrade between build variants"); (3) after install,
**every** installed component's dependency ranges must still be satisfied. Boot re-checks
(1) and (3) and additionally parses each payload.

### Token & frames

The issued operator token is 24 bytes: `user_id(2) | capabilities(2) | nonce(4) |
HMAC-SHA256(key, bytes[0..8])[:16]`. The device hands us **`user_id=42`, `caps=0x0003`**
(`BASIC_READ=0x0001` set, `0x0002` set; `SERVICE=0x8000` **not** set).

Frame layout: magic `"FG" | frame_version | opcode | payload_len | payload | 24-byte token`.
Dispatch: HMAC-check the token, look the opcode up in `tab` → required capability mask,
compare against `token.capabilities`; then look the opcode up in `pol` → run the action.

## 2. The vulnerability

Each `.fw` is individually signed and individually counter-gated, and the loader checks that
the *set* satisfies dependency ranges - but there is **no cross-component policy**: it never
checks that a given (pol, tab, rad) tuple is an *authorized, mutually-consistent* combination.
Two independently-valid artifacts therefore compose into behaviour the vendor never shipped:

* **`pol-v3rc.fw`** (counter 3, `==` the installed pol counter → sidegrade accepted):
  adds the `0x70 → action 0x07 (UNLOCK)` handler to the policy/handler table, and relaxes the
  `tab` dependency to `v1–v3`.
* **`tab-v3.fw`** (counter 3 ≥ installed tab counter 2 → upgrade accepted): changes opcode
  `0x70`'s **required capability** from `0x8000` (SERVICE) to `0x0001` (BASIC_READ).

Neither artifact alone grants anything: v3rc's UNLOCK handler is useless while `tab-v2` still
demands SERVICE, and `tab-v3`'s lowered requirement is useless without a `0x70` handler in
`pol`. Installed **together**, opcode `0x70` becomes "UNLOCK, requires only BASIC_READ" -
which our token satisfies.

## 3. Exploit chain

1. `UPDATE` `pol-v3rc.fw` - sidegrade pol v3 → v3rc (counter 3 == 3).
2. `UPDATE` `tab-v3.fw` - upgrade tab v2 → v3 (counter 3 ≥ 2).
3. `BOOT` - dependency ranges now satisfied (`rad:v2-v2` still met).
4. `TOKEN` - obtain the 24-byte token (`user_id=42`, `caps=0x0003`).
5. `SEND` a frame `b"FG" + 0x02 + 0x70 + 0x00 + token` → opcode `0x70` (UNLOCK). The
   capability check passes on `BASIC_READ`; the `pol` handler runs action `0x07`; the
   service blob (the flag) is returned in `resp_b64`.

## 4. Proof

```
=== UPDATE pol-v3rc ===     OK installed pol v3rc counter=3
=== UPDATE tab-v3   ===     OK installed tab v3   counter=3
=== BOOT            ===     OK boot ok: pol@v3rc.0304 tab@v3.1003 rad@v2.2002
=== TOKEN           ===     OK token_b64=ACoAAwD...        (user_id=42 caps=0x0003)
=== SEND UNLOCK     ===     resp_b64=...  ->  isfcr{s1gn3d_p4rts_uns1gn3d_whole_ab84f1}
```

Solver: `solve/exploit.py` (socket client; drives the 5 steps and decodes `resp_b64`).

## 5. Fix

Validate the *set*, not just the elements: pin an authorized (component → version/counter)
manifest and verify a **single signature over the whole installed image** (or a signed
capability-policy that the composition must satisfy) before boot/dispatch. Individually
signed parts, unsigned whole, is the bug.

## 6. Takeaway

`isfcr{s1gn3d_p4rts_uns1gn3d_whole_ab84f1}` - each part was signed, but the assembly wasn't.
Composable trust boundaries (here: policy table + capability table) must be validated as a
unit; per-component signing alone lets two benign artifacts degenerate into privilege escalation.

