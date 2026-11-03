# Cold Chain

**Event:** HICyberCon CTF 2026
**Category:** misc
**Flag:** `hiCTF{cold_chain_restored_defrost_cleared_142a475ab7}`

---

**Flag:** `hiCTF{cold_chain_restored_defrost_cleared_142a475ab7}`

## What was going on

"ColdLink" CM-900 case controllers speak **CLMP/1.1** - line-oriented UTF-8 over
TCP. On the hosted instance both the control service (port 7601 locally) and the
read-only historian feed (7602) are exposed as TLS/SNI-routed endpoints on the
challenge page. Two things were forcing continuous defrost:

- Schedule `S9 WINTER_DEFROST_ALL` with `action=force_defrost enabled=1`
- Macro `M2 AUTO_WINTERIZE` with `action=ensure_schedule target=S9 period=90`,
  which **re-enables S9 every 90 s** if a technician disables or deletes it -
  hence "a naive fix doesn't stick" (matches the historian sample: `event=macro_apply
  macro=M2 schedule=S9 detail=re-enabled_forced_defrost`).

`STATUS` before the fix:
`compliant=0 cases_cold=0/6 held=0s reason=forced_defrost_schedule_active,cases_above_5C=6,persistence_macro_enabled`

## Authentication

The toolkit ships the fleet master key `CLNK-FIELD-MASTER-6E1D-DO-NOT-DISTRIBUTE`.
The controller greets with `SERIAL` + per-connection `NONCE`; the token is
`sha256("<KEY>|<SERIAL>|<NONCE>")[:16]`. Then `AUTH <serial> <token>` → `OK role=technician`.

## Fix (order matters)

1. `MACRO DISABLE M2` - kill the persistence engine **first** (otherwise S9 returns
   within 90 s).
2. `SCHED SET S9 enabled=0` - stop the forced defrost (deleting S9 also works now,
   but disabling is less destructive).
3. Ensure the cool schedules (`S1`, `S3`, `action=cool_all`) stay enabled and
   `MODE <n> cool` on all six cases.
4. Wait out the **60 s sustained hold window** with all six cases ≤ 5 °C.

`STATUS` after: `compliant=1 cases_cold=6/6 held=136s` → `DATA flag=hiCTF{...}`.

## The flag line

```
DATA compliant=1 cases_cold=6/6 held=136s
DATA flag=hiCTF{cold_chain_restored_defrost_cleared_142a475ab7}
OK compliant
```
