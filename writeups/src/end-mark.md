# end-mark

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{28bc454d9b8fc1b73ff97a0d7db31a76}`

---

## Flag
```
isfcr{28bc454d9b8fc1b73ff97a0d7db31a76}
```

## Challenge
A "seal worker" performed 24 `SELECT payload FROM fragments WHERE slot=?` (FETCH) reads on
six separate reader connections (C1..C6) against a WAL-mode SQLite ledger while a single writer
`W` kept committing changes. The log (`trace.ndjson`) records the operations and their total
order (`seq`) but not the returned bytes. Given the captured `ledger.db` + `ledger.db-wal`, recover
the exact bytes each FETCH returned, concatenate the 24-byte payloads in slot order 0..23, and
submit the first 32 hex digits of their SHA-256.

## Files
- `ledger.db`      : 3 pages (page1 = schema, page2 = `fragments`, page3 = `heartbeat`)
- `ledger.db-wal`  : 120 frames, page size 1024
- `trace.ndjson`   : 135 ordered events

## Solution

### 1. WAL structure - two generations survive in one file
The 120 frames split into two salt groups of 60 frames each:

| group | salt1 | meaning |
|-------|-------|---------|
| frames 1..60  | `0x0466e797` | **current** generation (matches the WAL header salt) |
| frames 61..120| `0x0466e796` | stale tail of the **previous** generation |

The header salt is the giveaway: SQLite bumps the salt by 1 whenever the WAL is reset. The trace's
one `PRAGMA wal_checkpoint(RESTART)` (seq 82, after writer transaction 60, with all readers closed)
reset the WAL: the file was *not* truncated, so the new generation was written from frame 1 and only
overwrote the *front* half - the old generation's last 30 transactions survived as dead tail frames.

Therefore the current WAL = 30 transactions (each = 2 frames) = writer transactions **61..90**, and the
stale tail = the previous generation's last 30 transactions = writer transactions **31..60**.
Transactions 1..30 were physically overwritten (and are not needed, see below).

`ledger.db` (3 pages, dbsize 3) is the checkpointed state **after tx60** - verified byte-for-byte:
`page1 + tx60.page2 + tx60.page3 == ledger.db`.

### 2. Every transaction carries a full snapshot of the table
Each writer transaction appends two frames: page2 (`fragments` leaf) then page3 (`heartbeat`),
the latter being the commit frame. A WAL frame holds a *complete page image*, and the whole
`fragments` table (24 rows) fits in a single 1024-byte leaf page. So **the page2 image of any
transaction is a self-contained snapshot of the fragments table** - no replay from a base state is
required. State at tx *T* is assembled as `page1(from ledger.db) + txT.page2 + txT.page3` and
queried with real SQLite.

### 3. Snapshot timing - the crux
Readers run `BEGIN DEFERRED` in autocommit mode, so no read-snapshot is taken until the **first
statement that touches the main database**. Verified empirically (SQLite 3.46.1; same semantics in
3.50.4):

| statement | opens main-db snapshot? |
|-----------|-------------------------|
| `SELECT marker FROM heartbeat WHERE id=1` (C1)        | **yes** |
| `SELECT 1` (C2 heartbeat read)                        | **no**  |
| `PRAGMA user_version` (C3)                            | **yes** |
| `SELECT marker FROM temp.pulse WHERE id=1` (C4)       | **no** (temp db only) |
| `SELECT count(*) FROM sqlite_schema` (C5)             | **yes** |
| `SELECT sqlite_version()` (C6)                        | **no**  |

So C2, C4 and C6 (whose log lines falsely look like a snapshot was taken) actually take their
snapshot at their first FETCH. Snapshot transaction = the highest writer transaction committed
before the reader's first main-db access (`seq` order):

| conn | first main-db read | seq | snapshot tx |
|------|--------------------|-----|-------------|
| C1   | heartbeat (marker) | 40  | 38 |
| C2   | FETCH slot 9       | 49  | 42 |
| C3   | PRAGMA user_version| 53  | 44 |
| C4   | FETCH slot 18      | 93  | 65 |
| C5   | sqlite_schema      | 96  | 67 |
| C6   | FETCH slot 1       | 105 | 71 |

(`SELECT 1`, `sqlite_version()`, temp reads are no-ops for the main-db snapshot.)

### 4. Recover payloads
For each of the 24 FETCH events, take `payload[slot]` from the reconstructed state at that
connection's snapshot transaction. All 24 slots 0..23 are covered exactly once.

```
blob = concat(payload[s] for s in 0..23)   # 576 bytes (24 x 24)
sha256(blob) = 28bc454d9b8fc1b73ff97a0d7db31a76f16db9ebfa7690e2b48e3fa4600a5746
flag = isfcr{28bc454d9b8fc1b73ff97a0d7db31a76}
```

## Reproduce
```
cd end-mark
python3 solve.py     # prints the flag; asserts tx60==ledger.db and full slot coverage
```

## Traps avoided
- Assuming all 120 WAL frames are one generation (they are two; header salt selects the live one).
- Taking the reader snapshot at `BEGIN` (it is deferred) or at a non-db statement
  (`SELECT 1` / `sqlite_version()` / temp-table reads do **not** pin a snapshot).
- Assuming the checkpoint truncated the WAL (RESTART only rewinds; the old tail survives).

