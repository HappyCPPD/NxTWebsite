# end-mark

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{28bc454d9b8fc1b73ff97a0d7db31a76}`

---

A "seal worker" performed 24 FETCH reads across six separate reader connections against a WAL-mode SQLite ledger while a single writer kept committing. The trace (`trace.ndjson`, 135 ordered events) records operations and total order but not the returned bytes. Recover the exact bytes each FETCH returned, concatenate the 24-byte payloads in slot order, and submit the first 32 hex digits of their SHA-256.

**WAL structure:** the 120 frames split into two salt groups of 60 frames each - the current generation (matching the WAL header) and a stale tail of the previous generation, left behind by a `PRAGMA wal_checkpoint(RESTART)` which only rewinds the WAL rather than truncating it. The current WAL thus holds writer transactions 61-90; the stale tail holds 31-60 (transactions 1-30 were physically overwritten and not needed).

**Full-snapshot trick:** each writer transaction appends two frames (data page, then commit page), and the entire `fragments` table (24 rows) fits in a single 1024-byte leaf page - so any transaction's page2 image is a self-contained snapshot, no replay from a base state required.

**Snapshot timing - the crux:** readers use `BEGIN DEFERRED` in autocommit mode, so no read-snapshot is taken until the first statement that touches the **main database** (verified empirically against real SQLite). Statements like `SELECT 1`, `sqlite_version()`, or reads from `temp.*` do **not** pin a snapshot, even though their log lines look like they should - several connections' logged "first" statement is a no-op, and the true snapshot transaction is the highest writer transaction committed before the connection's actual first main-db access.

**Recovery:** for each of the 24 FETCH events, read `payload[slot]` from the reconstructed state at that connection's true snapshot transaction; all 24 slots are covered exactly once.

```
blob = concat(payload[s] for s in 0..23)   # 576 bytes
sha256(blob) = 28bc454d9b8fc1b73ff97a0d7db31a76f16db9ebfa7690e2b48e3fa4600a5746
flag = isfcr{28bc454d9b8fc1b73ff97a0d7db31a76}
```

Traps avoided: assuming all 120 WAL frames are one generation (two generations coexist, selected by header salt); taking the reader snapshot at `BEGIN` instead of the deferred first main-db touch; assuming the checkpoint truncated the WAL (RESTART only rewinds).
