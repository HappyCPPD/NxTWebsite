# Careless Talk

**Event:** September 2026 SkillBit Flash CTF
**Category:** rev
**Flag:** `SkillBit{c4r3l355_t4lk_c05t5_l1v35}`

---

## Overview

A 64-bit Linux ELF that prompts for a "watchword." The flavor text hints
that the human clerks kept their secret fine — it's the terminal itself
that talked.

## Solution

No need to touch the password check or even run the binary. `strings`
alone gives it away, sitting among dozens of decoy lines (convoy rosters,
harbor ciphers, relay digests) meant to bury the real one in noise:

```session
$ strings watchword | grep -E 'FLAG|}'
FLAG_A=SkillBit{c4r3l355_t4lk_
FLAG_B=c05t5_l1v35}
```

Two environment-style strings, split down the middle, sitting in plaintext
in the data section. Concatenating them gives the flag directly.

::: pitfall
Padding a binary with decoy strings only raises the noise floor for eyeballing
`strings` output top to bottom — it does nothing against a `grep` for the
part of the format you already know, like a trailing `}`.
:::

## Flag

```text
SkillBit{c4r3l355_t4lk_c05t5_l1v35}
```
