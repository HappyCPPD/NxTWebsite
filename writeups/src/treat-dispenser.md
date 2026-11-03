# Treat Dispenser

**Event:** October 2026 MetaCTF Flash CTF
**Category:** rev
**Flag:** `SkillBit{fu11_s1z3_tr34t_unl0ck3d}`

---


## 1. Recon

`treat-dispenser.zip` contains a single stripped PIE ELF, `dispenser` - a menu-driven
"treat dispenser" (options 1-4 hand out candy, 0 walks away). Nothing in the printed menu
path reveals the good candy; the prompt is "The keypad only takes numbers."

## 2. The key is in the embedded service log

`strings` on the binary leaks an internal maintenance log that names the unlock key:

```
$ strings -n 5 dispenser
...
svc 09/14: slot 3 coil jams on gummy worms, reseat before restock
svc 10/02: restock panel moved off the keypad label, KEY=6767
svc 10/20: coin mech disabled for Halloween night, treats are free
...
The keypad only takes numbers.
```

The menu loops reading the numeric keypad with `strtol`, so an out-of-menu number is
accepted as the keypad entry. `6767` is the key.

## 3. Solve

```
$ printf '6767\n' | ./dispenser
*CLUNK* The locked compartment swings open and a full-size bar drops out.
The wrapper reads: SkillBit{fu11_s1z3_tr34t_unl0ck3d}
```

## 4. Flag

```
SkillBit{fu11_s1z3_tr34t_unl0ck3d}
```
