# Git Sleuth

**Event:** September 2026 SkillBit Flash CTF
**Category:** misc
**Flag:** `SkillBit{R3m3mb3r_t0_4lw4ys_3sc4p3_G1t_C0mm4nds}`

---

## Overview

A TCP service, source included, drops you into a shell that only runs `git`
commands. Somewhere under `/tmp` sit 501 randomly-named `.txt` files: 500
contain a copy-pasted fake flag, and exactly one is the real thing, copied
from `/flag.txt`.

## The filter

`challenge.py` splits each input line on spaces and rejects any token
containing a blocked character or word:

```text
chars:  | " ' ; $ \ # * ( ) & ^ @ ! < > % : , ? { } `
words:  diff grep flag patch ./ push alias remote
        Fake Flag For Testing work update-ref lfs-remote /dev/null
```

That kills most of the obvious moves in one pass: no `grep`, no `diff`, no
`*` globbing, no `:` (so `git show HEAD:file` is dead on arrival), and the
literal word `flag` blocks any path that mentions `/flag.txt` directly.

## Building a repo out of the haystack

None of these hit the blocklist:

```text
init /tmp
-C /tmp add -A
-C /tmp commit -m x
-C /tmp ls-tree -r HEAD
```

That initializes a repo over `/tmp`, stages and commits all 501 files, and
dumps the tree: one line per file, each with its blob SHA.

## Finding the odd one out

Locally, hash the known fake flag content the same way git would:

```session
$ echo 'SkillBit{This_Is_A_Fake_Flag}' | git hash-object --stdin
937fc2f3a9653a549fe41c35f4e3102c02a3cad9
```

In the `ls-tree` output, 500 files share exactly that hash. One file has a
different hash — that's the real flag, and git just told us which one
without us ever reading a single file's contents.

## Reading a blob without `:`

`git show HEAD:filename` is off the table, but `git cat-file -p <hash>`
reads any object straight by its SHA and needs no `ref:path` syntax at all:

```text
-C /tmp cat-file -p 35ab8c9e8787383f759aae2db4ee654c73080548
```

That prints the flag.

::: insight
The filter only ever looks at what you type in, never at what git prints
back out. `ls-tree` and `cat-file -p` are both read-only, blob-level
plumbing commands, so nothing about "diff" or "grep" or "flag" needs to
appear in the command line for them to do exactly that job.
:::

## Flag

```text
SkillBit{R3m3mb3r_t0_4lw4ys_3sc4p3_G1t_C0mm4nds}
```
