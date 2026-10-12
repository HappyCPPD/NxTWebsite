# frost-ledger

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{stale_cow_67c1_root_fc8fe97f_backwards_heap}`

---

A 12 MiB volume (`registry.fvr`, 3072 × 4096B pages) plus a static reader `fvrctl`. `fvrctl lsroot` shows 8 root slots with epochs 288-291, one marked `TORN`. The release notes explicitly removed the `get`/`walk` subcommands - the tree must be walked by hand. The log shows a policy change re-issuing `bay/07/thaw-authority` out-of-line at 08:02, then a crash (undervoltage) at 09:14.

**Picking the live root:** the slot array is a ring buffer of the last 8 generations; a slot failing its fnv1a-64 checksum is skipped at mount. The highest *verifying* slot is epoch 290 (root_pgid 3039) - epoch 291 is the crash-torn commit.

**The descriptor convention - the real puzzle:** `ONDISK-NOTES.txt` documents format v0 (12-byte descriptor, payload offsets counted forward from page body start) but the volume is v1 (16-byte descriptor, trailing flags word) and - crucially - the release notes admit `ONDISK-NOTES.txt` was never revised for the v1 change. Examining the actual bytes shows payloads are packed against the **end** of the page with offsets counting **backward**: `payload at page[page_size - off]`. The flag name *backwards_heap* confirms this.

**Walking to the record:** descend as a normal B+tree using the v1 convention; the target key sorts into the leftmost subtree, found on DATA page 3030 with an overflow flag. OVERFLOW pages chain `{next_pgid, bytes_used, payload}` with no fixed stride: `966 -> 2675 -> 184 -> 355 -> 0`, reassembling to 2372 bytes matching the declared `total_len`. The stored bytes start `78 da` (zlib); decompressing yields a FROSTLINE VAULT AUTHORITY RECORD with `epoch: 290` matching the live root generation.

```
authority-token: isfcr{stale_cow_67c1_root_fc8fe97f_backwards_heap}
```

**The decoys:** scanning every page for the key (instead of walking the live tree) turns up 291 copies - 289 superseded version-3 records (`isfcr{thaw_authority_superseded_at_epoch_6}`), the crash-torn generation-291 copy (`isfcr{superseded_authority_rev6_0fa710}`), and the one genuine generation-290 record. Only the generation-290 record sits in the live tree and corresponds to the logged "commit ok".

Reproducible with `python3 solve.py` (stdlib only).
