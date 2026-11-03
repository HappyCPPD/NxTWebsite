# The Foxglove Trace

**Event:** HICyberCon CTF 2026
**Category:** osint
**Flag:** `hiCTF{FoxgloveCoffee_Guest}`

---

**Category:** offline data analysis · **Artifacts:** `notes.txt`, `aps.conf`, `run.log`, `scan_export.csv`

## The scoring rule (reconstructed from the files)
`notes.txt` states the idea; `run.log` is the single good run of the (now lost) `tracker.py`
and leaks the one number that was deliberately left out of the notes:

* **"moving" filter** - from `run.log` for CafeDelMundo: `step_delta=40 -> stationary, dropped`
  but `step_delta=41 -> moving, kept`. Cutoff: **keep only rows with `step_delta >= 41`**.
* **per-AP score** - sum over kept rows of `signal * weight`, where weight comes from `aps.conf`:
  `FoxgloveCoffee_Guest=3`, `HomePlex_5G=2`, `CafeDelMundo=2`, `NETGEAR-8841=1`.
  (Check: CafeDelMundo kept rows 58+60+64=182, x2 = **364**, exactly the `subtotal = 364`
  in `run.log`; HomePlex_5G kept row 87, x2 = **174** = the logged `subtotal = 174`.)
* Only APs listed in `aps.conf` count; everything else in the export is ignored.

## Solve
```bash
python3 - <<'EOF'
import csv
W = {'FoxgloveCoffee_Guest':3,'HomePlex_5G':2,'CafeDelMundo':2,'NETGEAR-8841':1}
sc = {k:0 for k in W}
for r in csv.DictReader(open('scan_export.csv')):
    if r['ap_name'] in W and int(r['step_delta']) >= 41:
        sc[r['ap_name']] += int(r['signal']) * W[r['ap_name']]
print(sorted(sc.items(), key=lambda x: -x[1]))
EOF
# [('FoxgloveCoffee_Guest', 1044), ('CafeDelMundo', 364), ('NETGEAR-8841', 240), ('HomePlex_5G', 174)]
```

The traps work exactly as advertised: `HomePlex_5G` is the **loudest** AP (signal 87-92) and
also the **most frequent** (10 rows), but you are almost never moving there (1 kept row),
so it finishes last. `FoxgloveCoffee_Guest` - the place the person keeps returning to -
wins by a wide margin.

## Flag
```
hiCTF{FoxgloveCoffee_Guest}
```
