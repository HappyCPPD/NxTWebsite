# Discord Shenanigans V6

**Event:** TFC CTF 26
**Category:** misc
**Points:** 340
**Flag:** `TFCCTF{CASTLE}`

---

## Overview

A baby misc challenge with a one-line brief: the hidden word is in `#announcements`,
wrap it in `TFCCTF{}`, and it is not meant to be guessy. The only artifact is the
pre-event announcement message.

## The announcement

```text
Less than half a day until TFC CTF 2026.
Come prepared for a day of challenges, exploits, puzzles, and flags.
Assemble your teams, sharpen your tools, and make sure everything is ready before the clock starts.
Stay focused, think creatively, and expect the unexpected.
The competition will be intense, so every minute and every flag will matter.
Let the hacking, debugging, reversing, and suffering begin.
Everyone, good luck and see you on the scoreboard.
```

## Solution

Seven sentences, and the wording is stilted in a way that only makes sense if the
first letter of each sentence is load-bearing. Read them top to bottom:

```text
Less      -> L
Come      -> C
Assemble  -> A
Stay      -> S
The       -> T
Let       -> L
Everyone  -> E
```

That gives `LCASTLE`, which is `CASTLE` with a stray leading `L`.

::: insight
The first sentence starts with "Less than", and "less" is the instruction:
take the acrostic result **less** the leading `L`. `LCASTLE - L = CASTLE`.
:::

## Flag

```text
TFCCTF{CASTLE}
```
