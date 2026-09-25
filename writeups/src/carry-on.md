# Carry On

**Event:** September 2026 SkillBit Flash CTF
**Category:** forensics
**Flag:** `SkillBit{0n3_f1l3_c4n_c4rry_4n0th3r}`

---

## Overview

One PNG, `checkpoint-plan.png`, showing a security screening hall layout.
The flavor text says the file is "heavier than the picture it shows" — a
straight hint that there's more appended after the image data than the
image needs.

## Spotting the append

A PNG stream ends at its `IEND` chunk. Anything after that byte is
invisible to an image viewer but not to a tool that reads from the end of
the file:

```session
$ xxd checkpoint-plan.png | tail -5
...
0000fe40: 4b01 0214 0314 0000 0008 0000 bd37 5d3b  K............7];
...
0000fe70: 652e 7478 7450 4b05 0600 0000 0001 0001  e.txtPK.........
```

`PK` — the ZIP local-file-header magic — and a legible `note.txt` filename
sit right there in the tail of the file.

::: insight
ZIP readers locate the archive by scanning backward from the end of the
file for the End of Central Directory record, not forward from byte zero.
PNG viewers stop at `IEND`. Same file, two formats, both perfectly happy to
read it, because each one only looks where its own format expects to find
its own ending.
:::

## Extracting it

```session
$ unzip checkpoint-plan.png
Archive:  checkpoint-plan.png
  inflating: note.txt
```

`note.txt` turns out to be a shift-handover memo for the checkpoint. Buried
in otherwise mundane operational notes is the flag, dressed up as a
diagnostic recovery key:

```text
The recovery key is SkillBit{0n3_f1l3_c4n_c4rry_4n0th3r}
```

## Flag

```text
SkillBit{0n3_f1l3_c4n_c4rry_4n0th3r}
```
