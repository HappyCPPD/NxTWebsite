# Ground Station

**Event:** HICyberCon CTF 2026
**Category:** misc
**Flag:** `hiCTF{ground_station_fueling_test_nominal_66e05dd7a0}`

---

**Flag:** `hiCTF{ground_station_fueling_test_nominal_66e05dd7a0}`

Solved live against the platform instance (rCTF instancer).

## 1. Access derivation (reverse `gsc-fw.bin`)

`gsc-fw.bin` is a small stripped x86-64 ELF. Running it prints a POST banner and
`image-sig=de8c1297`.

Recovered functions:

* `0x40048e` - key/vector expansion. LCG from seed `0x1f2e3d4c`
  (`s = s*0x19660d + 0x3c6ef35f`), 16 iterations, byte =
  `((s >> 17) ^ (i*0x5b)) & 0xff`.
  → `KBUF = 50e5d52349171740d3823ef092cdb7bd`
* `0x400476` - `rol32(value, n)`.
* `0x4004ed`/`0x40053a` - little-endian 32-bit load/store.
* `0x400589` - the **access routine**: `out8 = access(in16, key8)`.
  Loads 4 dwords `a,b,c,d` from `in16` and 2 dwords `e,f` from `key8`, then
  12 rounds:
  ```
  a = rol32(a + e, 7)
  b = rol32(b ^ a, 11)
  c = rol32(c + b + f, 17)
  d = rol32(d ^ c, 19)
  e = (e + d + i*0x9e3779b9) & 0xffffffff
  f = rol32(f ^ a, 13)
  (a,b,c,d) = (b,c,d,a)
  ```
  output = `(a^c, b^d)` packed LE = 8 bytes.

`main` (0x4006f8) calls `access(KBUF, FIXVEC[:8])` where `FIXVEC` is the 16-byte
`.rodata` value at `0x401280` = `4753432d37000123011b033b54000000` (the "fixed
internal vector"), and prints the first 4 output bytes as `image-sig`. Our
reconstruction reproduces `de8c1297` exactly - the constant-verified anchor.

**Live auth:** the session `NONCE` is 8 bytes (16 hex). The access routine takes a
16-byte vector plus an 8-byte key - the nonce is the **key**, and the built-in
vector `KBUF` is the input. So:

```
response = access(KBUF, NONCE8)          # 8 bytes, hex
AUTH <response-hex>   ->  OK access=engineer
```

(Verified: the other argument orders - nonce as input, FIXVEC as input - all
returned `ERR bad-auth`.)

## 2. Altered safety logic

`PROG LIST` vs the control narrative (C1 - C4):

```
INTERLOCK_OK expr=(TANK_TEMP <= 145) AND (TANK_PSI <= 100)   # ALTERED
```

C3 requires tank temperature **≤ 45 °C**, so the live rung's `145` is a planted
`1` prefix. Fix:

```
PROG SET INTERLOCK_OK (TANK_TEMP <= 45) AND (TANK_PSI <= 100)
-> live_checksum 438a029650ce -> 9ebaae207f06
```

## 3. Making the fix stick (integrity watchdog)

After the edit `arm_will_restore=1`: the watchdog (`trigger=runtest`,
`action=restore_backup`) would revert the live program from the backup slot at
arm because the live checksum no longer matched `trusted_checksum`. Neutralise it
the clean way - promote the corrected program to the trusted backup:

```
BACKUP SAVE   -> trusted_checksum=9ebaae207f06
BACKUP STATUS -> live=backup=trusted=9ebaae207f06  arm_will_restore=0
```

(Disabling the watchdog with `WDOG SET enabled=0` also works, but leaves the
integrity model broken; `BACKUP SAVE` keeps the watchdog enabled and correct.)

## 4. Clean run

```
RUNTEST
DATA result=SUCCESS reason=fill_target_reached_scan_51
DATA flag=hiCTF{ground_station_fueling_test_nominal_66e05dd7a0}
OK compliant
```

## Repro

```
python3 solve.py              # verifies key expand + image-sig anchor
# live: gsp_client.py (TLS+SNI to the instance) -> auth, PROG SET, BACKUP SAVE, RUNTEST
```

Instance was reached over TLS with SNI (the platform's instancer terminates TLS):
`socat TCP-LISTEN:7603,reuseaddr,fork OPENSSL-CONNECT:<HOST>:<PORT>,snihost=<HOST>`
or plain `ssl` with `server_hostname=<HOST>` (used here).
