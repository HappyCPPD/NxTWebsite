# Provenance Expert

**Event:** TISC 2026
**Category:** forensics
**Server:** `http://chals.tisc26.ctf.sg:53219` &middot; `POST /submit`
**Flag:** `TISC{r1ch_h34d3r_t0ld_a_l1e_ab0ut_1ts_b1rth}`

---

## Overview

TISC 2026's "Provenance - Expert" hands over one 415 KB Windows binary,
`challenge.exe` - a PE32+ x86-64 console app built with native MSVC C++.
Running it prints only a taunting decoy:
`TISC{r3m3mb3r_th3_fl4g_c0m3s_0nly_fr0m_subm1tt1ng_th3_c0rr3ct_b1n4ry}`.

The brief sets the tone: *"This build tries to hide something about itself.
Everything the program does is a performance; look instead at what it can't
help admitting. Make the binary honest about where it came from. Change
nothing but the provenance record. Submit the binary you were given,
repaired, not rebuilt."*

So the runtime is theater. The task is forensic surgery on the PE headers:
something about where the binary *came from* was forged, and the fix is to
repair exactly that record, then POST the fixed file to the grader, which
returns the real flag only once the provenance is honest.

The grader gives three verdicts: *not internally honest*, *only the
provenance record may change - you altered other bytes*, or success and the
flag.

## The provenance record: the Rich header

Every MSVC-linked PE carries an undocumented **Rich header** between the DOS
stub and the PE signature. It's a XOR-masked histogram of the toolchain that
built the file: one entry per `(product id, build number)` pair, with a count
of how many object files came from that tool. It's effectively the binary's
birth certificate - a fingerprint the linker stamps automatically.

Decoding `challenge.exe`'s Rich header shows the forgery immediately - every
entry's build number is `25017` (0x61b9 = Visual Studio 2017 15.0):

| # | tool | build | count |
|---|---|---|---|
| 0 | C++ | 25017 | 158 |
| 1 | C | 25017 | 18 |
| 2 | ASM | 25017 | 7 |
| 3 | IMP | 25017 | 3 |
| 4 | Unmarked | 0 | 119 |
| 5-9 | ASM/C/C++/C++/LNK | 25017 | 10/16/80/1/1 |

A real linker never unifies every component to one build number - import
libs, the CRT and app code come from different tool builds. All-`25017` is
synthetic: the forger overwrote the build field on every entry.

**The editable region**, proven by single-byte flips against the grader: only
three spans may differ from the original, or the response is *you altered
other bytes*:

- Rich header `0x80-0xE7`
- OptionalHeader linker version `0x11A` (major) / `0x11B` (minor)
- PE checksum `0x158-0x15B`

Everything else - COFF timestamp, load config, debug directory, code - is
locked. And the grader is a static oracle with no progress signal; it only
ever answers "not honest" or "you changed other bytes". There is nothing to
hill-climb toward.

## What it can't help admitting

The Rich header and linker version both claim VS2017 15.0 (build 25017,
linker 14.10), and they agree with each other, so the file looks internally
consistent. The lie only shows when checking a structure the linker *cannot*
fake, and that sits in the locked region: the **load config directory**.

`challenge.exe`'s load config is `0x140` bytes and carries the modern Control
Flow Guard / CET / CastGuard / GuardMemcpy fields. That layout only exists in
Visual Studio 2022 (17.7+); VS2017 emits a much smaller load config. So the
*code* is unmistakably VS2022, while the *recorded provenance* says VS2017.

That's the whole challenge in one line: make the recorded provenance match
the contents. The performance says 2017; the thing it can't help admitting
says 2022. Honesty means rewriting the Rich builds and linker version to the
true VS2022 toolchain.

## The rabbit hole (~2000 wasted submissions)

Knowing it's "VS2022" isn't enough - the grader wants the exact build
numbers, and two wrong assumptions kept the answer out of reach:

::: pitfall
**Wrong version.** The load config looked byte-similar to Python 3.12.7's,
which is VS2022 17.11 (build 34120, linker 14.41). Every attempt anchored on
34120: downloading the Python embeddable and mining the real VS2022 build set
(33731, 33808, 33813, 33923, 34120, ...) and sweeping them hard.
:::

::: pitfall
**Over-thinking the structure.** A real Rich header can't have duplicate
`(prodid, build)` entries, and the forged one has C++ three times. So the
assumption was that the honest header must be a *valid de-duplicated
histogram* with distinct builds per entry - ~1,300 submissions on grouped
multi-toolchain models, plus splitmix64 derivations from the `.ctfid` token,
plus every simple consistency fix.
:::

Everything came back "not internally honest". The decisive datapoint: 1,320
structurally-valid VS2022 histograms all failed. That proved the check
doesn't want "any plausible VS2022 header" - it wants specific build numbers.

## The breakthrough: read the timestamp

The clue was in a locked field that had been ignored precisely because it
couldn't be edited: the COFF `TimeDateStamp = 0x6A878990` = 2026-08-20.

::: insight
That date is ~2 years *after* VS2022 17.11 shipped. The load config's `0x140`
layout doesn't pin an exact version - it spans 17.7 through the latest - so
anchoring on 17.11 was never justified. A build stamped August 2026 would use
a much newer toolchain.
:::

So instead of chasing exotic multi-build histograms, the simplest possible
header - every entry at one single build `V`, linker version matching `V` -
was swept across the *latest* VS2022 releases:

| build V | linker | VS version | verdict |
|---|---|---|---|
| 34120 | 14.41 | 17.11 | not honest |
| 34435 | 14.42 | 17.12 | not honest |
| **34808** | **14.43** | **17.13** | **FLAG** |

Build 34808 (VS2022 17.13, linker 14.43) was the honest birth date all along.
The COFF timestamp had been pointing at it the whole time.

## The repair

The fix keeps the forged Rich header's structure exactly - same product ids,
same counts, same order, duplicates and all - and only corrects the build
number and linker version:

1. **Rich header:** set every entry's build field from `25017` to `34808`
   (Unmarked stays `0`). Recompute the Rich XOR checksum key over the DOS
   stub plus entries.
2. **Linker version:** set OptionalHeader `0x11A`/`0x11B` to `14`/`43`.
3. **PE checksum:** zero `0x158-0x15B`, then write the correct checksum.

Result: 104 bytes changed, all inside the provenance region - the grader's
"only provenance may change" check passes, and the honesty check passes.
Core of the generator:

```python
import struct, pefile
orig = bytearray(open('challenge.exe','rb').read())
def rol(v,n): n&=31; return ((v<<n)|(v>>(32-n)))&0xffffffff
# forged entries: (prodid, count); build -> 34808 for all non-Unmarked
entries = [(0x0105,158),(0x0104,18),(0x0103,7),(0x0101,3),(0x0001,119),
           (0x0103,10),(0x0104,16),(0x0105,80),(0x0105,1),(0x0102,1)]
d = bytearray(orig)
# Rich checksum key over DOS stub (skip e_lfanew 0x3c..0x40) + masked entries
cs = 0x80
for i in range(0x80):
    if 0x3c <= i < 0x40: continue
    cs = (cs + rol(orig[i], i)) & 0xffffffff
for prod,cnt in entries:
    build = 0 if prod==0x0001 else 34808
    cs = (cs + rol((prod<<16)|build, cnt & 0x1f)) & 0xffffffff
k = cs
def put(o,v): struct.pack_into('<I', d, o, v ^ k)
put(0x80,0x536e6144); put(0x84,0); put(0x88,0); put(0x8c,0)   # DanS + pad
o = 0x90
for prod,cnt in entries:
    build = 0 if prod==0x0001 else 34808
    put(o,(prod<<16)|build); put(o+4,cnt); o += 8
d[0xe0:0xe4] = b'Rich'; struct.pack_into('<I', d, 0xe4, k)
d[0x11a], d[0x11b] = 14, 43                                    # linker 14.43
struct.pack_into('<I', d, 0x158, 0); open('_t.exe','wb').write(d)
struct.pack_into('<I', d, 0x158, pefile.PE('_t.exe').generate_checksum())
open('challenge_repaired.exe','wb').write(d)
```

```bash
curl -s -X POST http://chals.tisc26.ctf.sg:53219/submit -F "file=@challenge_repaired.exe"
# {"status":"correct","message":"Provenance restored. Flag captured.","flag":"TISC{...}"}
```

```text
TISC{r1ch_h34d3r_t0ld_a_l1e_ab0ut_1ts_b1rth}
```

## Takeaways

1. **Structural PE evidence beats metadata.** The Rich header and linker
   version are easy to forge and agreed with each other; the load config and
   timestamp are not, and they told the truth. When two records disagree,
   trust the one the toolchain can't fake.
2. **Read the timestamp.** The COFF TimeDateStamp (August 2026) pinned the
   toolchain era and directly named the version - it was ignored for hours
   because it sat in the *locked* region, but locked bytes are still
   evidence, not just obstacles.
3. **Don't over-engineer the check.** "A real Rich header has unique
   entries" was true but irrelevant; the grader only compared build numbers.
   ~2000 submissions built valid histograms when the answer was one
   substitution on the existing structure.
4. **A dead end is data.** 1,320 valid-but-rejected headers weren't wasted -
   they proved the check wanted a specific number, which is exactly what
   pushed the search from "construct a plausible header" to "find the one
   right version".
