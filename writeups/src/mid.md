# mid

**Event:** TFC CTF 26
**Category:** crypto
**Flag:** `TFCCTF{w3_l0v3_a_g0od_b1nary_se4rch}`

---

## Overview

A remote service picks a random 30-character password over `[0-9A-Za-z]` and
gives you 195 queries. Each query is a `state` (0 or 1) and a `guess` string.
The server keeps a hidden `mood` that starts at 0 and flips to 1 at a random
query index.

| `state` vs `mood` | response |
|---|---|
| equal | truthful: `smaller`, `larger`, or `equal` |
| not equal | random: `smaller` or `larger`, 50/50 |

Submit `state == mood` with `guess == password` and you get `equal` and the flag.

::: pitfall
When `state != mood` the answers are coin flips with zero information, and they
will silently corrupt any search that trusts them. Every step has to survive the
mood being wrong.
:::

## Detecting the flip, provably

The mood check has to be one-sided, because a false positive wastes the budget.

- `state = 0`, `guess = "0" * 30`: if `mood == 0` the honest answer is *always*
  `smaller` (all zeros sort below any password). So a `larger` here is
  impossible unless `mood` has already flipped to 1. `larger` is a definitive
  signal.

That single probe, repeated every few characters, is enough.

## Character-by-character search

Binary-searching the whole `62**30` space takes ~179 truthful queries but one
lie ruins the entire range. Instead, fix a known prefix and binary-search the
next character over the 62-symbol alphabet (~6 queries), padding the rest with
zeros so comparisons stay coherent:

```python
def make_guess(prefix, ci):
    return prefix + ALPH[ci] + "0" * (30 - len(prefix) - 1)
```

Every 3 characters, probe the mood with `query(0, "0"*30)`. On `larger`, the
mood switched: roll back one character (it may be corrupt) and continue with
`mood = 1`. A rollback costs ~6 queries, cheap next to restarting.

```python
ALPH = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
zeros = "0" * 30
a0, flag = query(sock, 0, zeros)
mood = 1 if a0 == "larger" else 0

prefix = ""; pos = 0
while pos < 30 and qc < 187:
    if pos and pos % 3 == 0:
        pa, flag = query(sock, 0, zeros)
        if mood == 0 and pa == "larger":       # switch detected
            mood = 1
            if pos: prefix = prefix[:-1]; pos -= 1
            continue
    lo, hi = 0, 61
    while lo <= hi:
        midc = (lo + hi) // 2
        ans, flag = query(sock, mood, make_guess(prefix, midc))
        if flag: return flag
        if ans == "smaller": lo = midc + 1
        elif ans == "larger": hi = midc - 1
        else: lo = midc; break
    ci = lo if lo <= hi else max(0, min(61, (lo + hi) // 2))
    prefix += ALPH[ci]; pos += 1

for st in (mood, 1 - mood):
    ans, flag = query(sock, st, prefix)
    if flag: return flag
```

```session
$ python3 solve.py
M=0 Q1
  6/30 q=38 eCAqBn
  12/30 q=76 eCAqBn33zuNv
  18/30 q=114 eCAqBn33zuNvbT
FLAG: TFCCTF{w3_l0v3_a_g0od_b1nary_se4rch}
```

In practice the mood either flipped early enough to catch on a probe, or not at
all; the password came out in about 152 queries.

## Flag

```text
TFCCTF{w3_l0v3_a_g0od_b1nary_se4rch}
```
