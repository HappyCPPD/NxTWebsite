# frost-ledger

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{stale_cow_67c1_root_fc8fe97f_backwards_heap}`

---

## 0. Prompt

Bay 07's controller died with the vault and took the vendor reader with it. Survived:
the registry volume, the docs on the controller image, and `fvrctl`. Recover the
authority token from `bay/07/thaw-authority`. Flag format `isfcr{...}`.

Tarball `frost-ledger.tar.gz` extracts to:

```
registry.fvr                         # the volume (12 MiB, 3072 x 4096 B pages)
usr/sbin/fvrctl                      # static, stripped reader
usr/share/doc/fvregd/ONDISK-NOTES.txt
usr/share/doc/fvregd/RELEASE-NOTES.txt
include/fvr_format.h
var/log/fvregd.log
```

## 1. Recon

`fvrctl` tells us the shape, then explicitly refuses to do the useful thing:

```
$ ./usr/sbin/fvrctl info registry.fvr
volume            FVR, on-disk format version 1
page_size         4096
page_count        3072
...
$ ./usr/sbin/fvrctl lsroot registry.fvr
slot  epoch       root_pgid  wal_head  fnv1a64
   0  288         3018       0         ok
   1  289         3029       0         ok
   2  290         3039       0         ok
   3  291         3049       0         TORN
   ...
$ ./usr/sbin/fvrctl stat registry.fvr
  kind INDEX     291
  kind DATA      2619
  kind OVERFLOW  34
  kind other      127
crc mismatches    127
```

RELEASE-NOTES 1.4.2: *"fvrctl: drop the get and walk subcommands... Offline inspection
is now expected to go through libfvr. Note that libfvr is not installed on controller
images."* So there is no turnkey reader - the tree must be walked by hand.

The log is the story of the crash:

```
2026-10-18T08:02:13Z policy change accepted: bay/07 thaw predicates
2026-10-18T08:02:13Z re-issuing authority record bay/07/thaw-authority
2026-10-18T08:02:13Z superseded record retained in CoW history
2026-10-18T08:02:13Z new record stored out of line
2026-10-18T08:02:14Z commit ok
2026-10-18T09:14:38Z bay bus undervoltage, 11.2 V
2026-10-18T09:14:39Z bay bus undervoltage, 9.8 V
```

So: re-issued record committed at 08:02, then a crash at 09:14. The re-issued record
is the one we want and it is out-of-line (overflow). Everything else (v3 copies) is
just CoW history.

## 2. Superblock and picking the live root

Page 0: magic `FVR\x01`, u32 page_size=4096, page_count=3072, format_version=1, then
8 root slots, each 32 B = `{u64 epoch, u32 root_pgid, u32 wal_head, u64 reserved,
u64 fnv1a-64 over the first 24 bytes}`.

The FVR release notes (1.2.1) tell us exactly what to do with a bad checksum: *"a slot
that fails it is skipped at mount."* The slot array is a **ring buffer** of the last 8
generations (here 284→291 in slot order 4,5,6,7,0,1,2,3). Slot 3 (epoch 291) is the
crash-torn commit, so the highest *verifying* slot - the live generation - is
**epoch 290, root_pgid 3039**. (fvrctl already flags epoch 291 as TORN.)

## 3. The descriptor convention (the real puzzle)

ONDISK-NOTES documents format **v0**, but the volume is v1. Release notes 1.3.0:

> ON-DISK FORMAT CHANGE: version 0 -> version 1. The DATA and INDEX cell descriptor
> grows from 12 to 16 bytes and gains a trailing u32 flags word... Callers MUST obtain
> payload addresses from `fvr_cell_key()` / `fvr_cell_value()` rather than computing
> them; the helpers branch on `format_version`. ONDISK-NOTES.txt has NOT been revised
> for this change.

v0 (documented): descriptor 12 B, payload offsets counted **forward** from the page
body start (`page[24+off]`). v1 (actual): descriptor 16 B, and - once you look at the
bytes - the payload region is packed against the **end** of the page and the offsets
count **backward**:

```
payload at page[page_size - off]
```

Hex of the root INDEX page 3039 body makes it obvious: the first descriptor reads
`koff=0x0c ksize=8 vsize=4 voff=0x10`, and the 8-byte keys and 4-byte child pgids live
at the very end of the page (`seg/0052 …seg/0461` with children 3030..3037), plus the
rightmost child `0x0bde` in the last 4 bytes. With the v0 forward convention you read
descriptor bytes as "keys"; with the v1 backward convention you get a real B+tree.
The flag name - *backwards_heap* - is the author confirming this.

## 4. Walking to the record

Descend as a normal B+tree: for every INDEX page, take the N separators' child pgids
plus the rightmost child (last u32 of the page). Leaf DATA pages hold the records. The
target sorts before `seg/...`, so it lives in the leftmost subtree and is found on
DATA page **3030**:

```
key   = bay/07/thaw-authority    (ksize 22)
value = {u64 head_pgid = 966, u32 total_len = 2372}   flags = 0x2 (overflow)
```

Flags bit 0x2 means the value is out of line. OVERFLOW pages are
`{u32 next_pgid, u32 bytes_used, payload…}`. Walk the chain, no fixed stride:

```
966 -> 2675 -> 184 -> 355 -> 0        (bytes_used 739,662,489,482 = 2372)
```

Reassembled length 2372 == declared `total_len`. Note the release note's warning:
`total_len` is the **STORED** length (compare before decoding). The stored bytes start
`78 da` - a zlib stream. From record-version 4 on the payload is no longer stored
verbatim; decompress:

```
FROSTLINE VAULT AUTHORITY RECORD
record-version: 4
epoch: 290
bay: 07
subject: cryogenic-pod-array-07
issued-by: HALCYON/caretaker
issuer-key-id: 4164d8399f767c45
predicate.coolant-pressure: >= 4.10 bar
predicate.core-temp: <= -196.0 C
predicate.operator-present: true
predicate.second-factor: hardware-token
countersig[0..13]: ...
authority-token: isfcr{stale_cow_67c1_root_fc8fe97f_backwards_heap}
notes: representation changed in 1.3; see RELEASE-NOTES.txt
seal: c3812e29...  (same on every revision)
```

`epoch: 290` matches the live root generation and the logged re-issue commit - this is
the durable, current record.

## 5. The decoys

Scanning *every* page for the key (rather than walking the live tree) turns up **291**
copies of the record:

| pages | generation | record-version | internal epoch | token |
|-------|-----------|----------------|----------------|-------|
| 289 | 1 - 289 | 3 (verbatim) | 6 | `isfcr{thaw_authority_superseded_at_epoch_6}` |
| 1 | 290 (**live**) | 4 (zlib) | 290 | `isfcr{stale_cow_67c1_root_fc8fe97f_backwards_heap}` |
| 1 | 291 (**torn**) | 4 (zlib) | 326 | `isfcr{superseded_authority_rev6_0fa710}` |

- The 289 **version-3** copies are the superseded record the log says is "retained in
  CoW history". A `strings`/grep shortcut lands here → decoy.
- The **generation-291** copy is the crash-torn commit: its root slot fails fnv1a-64,
  so it is not part of any mounted generation, and its internal epoch (326) matches no
  logged operation. Reading it ("use the highest epoch slot, torn or not") → decoy.
- Only the **generation-290** record sits in the live tree and corresponds to the
  08:02 "commit ok" → the real authority token.

Note the torn generation is also where the 127 "kind other" / CRC-mismatch pages came
from in `fvrctl stat` - half-written pages from the interrupted commit.

## 6. Answer

```
isfcr{stale_cow_67c1_root_fc8fe97f_backwards_heap}
```

Reproducible with `python3 solve.py` (stdlib only).

