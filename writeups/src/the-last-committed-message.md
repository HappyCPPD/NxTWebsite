# the last committed message

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{a03a410f1b87dbc115dd1ef6}`

---

## Challenge

Recover a note and its attachment record as they stood when export `export-07abca69cd99` was acknowledged, then use the four evidence fields to derive an AES-GCM key and decrypt the flag.

**Key rules:**
- A note replacement, its attachment-record upsert, and its operation record commit together.
- An acknowledged export describes the state immediately after its operation committed.

## Solution

### Step 1: Identify the Target Operation

The export log contains two entries for `export-07abca69cd99`:

```
{"export_id":"export-07abca69cd99","operation_id":"op-c46dc0e04bdd","status":"timeout"}
{"export_id":"export-07abca69cd99","operation_id":"op-09e0d79b4b14","status":"acknowledged"}
```

The acknowledged entry has `operation_id` = `op-09e0d79b4b14`. We need the database state immediately after this operation committed.

### Step 2: Extract the Handout

```bash
unzip handout.zip -d handout
```

This gives us `case.db` (SQLite) and `case.db-wal` (Write-Ahead Log). The WAL contains historical transaction states that are not visible in the final database.

### Step 3: Parse the WAL File

The WAL file (824,400 bytes, 1,538 frames) contains three generations distinguished by salt values:

| Generation | Salt1        | Frames    | Commits |
|------------|-------------|-----------|---------|
| 0 (newest) | `0x3e895953` | 1 - 108     | 6       |
| 1 (middle) | `0x3e895952` | 109 - 725   | 30      |
| 2 (oldest) | `0x3e895951` | 726 - 1538  | 41      |

SQLite only reads frames matching the WAL header's salt values (generation 0). The target operation `op-09e0d79b4b14` does not exist in the final database state - it was overwritten by later operations. To find it, we must replay earlier WAL generations.

### Step 4: Replay WAL Transactions

By applying generation 0 on top of the base database, then replaying generation 1 transaction-by-transaction, the target operation first appears at commit 18 of generation 1. At that point, `note-7211098c21a6` has `operation_id = op-09e0d79b4b14`.

The replay works by:
1. Starting from the base `case.db` page data.
2. Overwriting pages as each WAL frame specifies (page number → new page content).
3. At each commit boundary (`commit_size > 0`), snapshotting the database and querying it.

### Step 5: Extract the Evidence

At the target state:

| Field | Value |
|-------|-------|
| `note_id` | `note-7211098c21a6` |
| `revision` | `5` |
| `destination` | `sftp://drop-edef61bb364d.example.invalid/inbox/f34143e1/...5ec4921ffe4835a0.bin?ticket=a638d0e59bf0b87a8d34c22020f0555d` |
| `attachment sha256` | `b89d5c5695803071522614060828e31e9bb4bc25813fdbc5d516db06ac4c2d58` |

### Step 6: Decrypt the Flag

```python
import json, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

evidence = [note_id, "5", destination, sha256]
E = json.dumps(evidence, ensure_ascii=True, separators=(",", ":")).encode("ascii")

key = hashlib.scrypt(
    b"isfcr-forensics\x00" + E,
    salt=bytes.fromhex("a3845b1a904c5ee73abe7329b5d735d7"),
    n=131072, r=8, p=1, maxmem=2**28, dklen=32
)

flag = AESGCM(key).decrypt(
    bytes.fromhex("ca98cff993b27fd3bb352436"),
    bytes.fromhex("3fa8b9049b01fb8d12df130b404352f9c678c272cccb7e6c034554c902f1ca4d574fc04db8892fead1ad394735e021"),
    b"the-last-committed-message"
)
```

## Flag

```
isfcr{a03a410f1b87dbc115dd1ef6}
```

## Key Techniques

- **SQLite WAL forensics**: The WAL file preserves historical database states across multiple checkpoint generations. By replaying frames in order and stopping at the right commit boundary, we can reconstruct any intermediate state.
- **WAL generation tracking**: Salt values in WAL frame headers identify which checkpoint generation each frame belongs to. Only frames matching the WAL header salts are read by SQLite normally; older generations require manual replay.
- **Transaction boundary detection**: Frames with `commit_size > 0` mark the end of atomic transactions. The database is consistent only at these boundaries.

