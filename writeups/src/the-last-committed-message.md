# the last committed message

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{a03a410f1b87dbc115dd1ef6}`

---

Recover a note and its attachment record as they stood when export `export-07abca69cd99` was acknowledged. Rule: a note replacement, its attachment-record upsert, and its operation record commit together; an acknowledged export describes the state immediately after its operation committed.

The export log has two entries for the export id: one `timeout`, one `acknowledged` with `operation_id = op-09e0d79b4b14`. The handout (`case.db` + `case.db-wal`) contains a 824,400-byte WAL with 1,538 frames split into **three generations** distinguished by salt values (0: frames 1-108/6 commits; 1: frames 109-725/30 commits; 2: frames 726-1538/41 commits). SQLite only reads frames matching the WAL header's current salt (generation 0); the target operation does not exist in the final database state - it was overwritten by later operations and must be recovered by replaying earlier generations.

**Replay:** apply generation 0 on top of the base database, then replay generation 1 transaction-by-transaction. The target operation first appears at commit 18 of generation 1, where `note-7211098c21a6` has `operation_id = op-09e0d79b4b14`. At each commit boundary (`commit_size > 0`), snapshot the database and query it.

**Evidence extracted:** `note_id = note-7211098c21a6`, `revision = 5`, an SFTP destination URL, and the attachment's SHA-256.

```python
evidence = [note_id, "5", destination, sha256]
E = json.dumps(evidence, ensure_ascii=True, separators=(",", ":")).encode("ascii")
key = hashlib.scrypt(b"isfcr-forensics\x00" + E, salt=..., n=131072, r=8, p=1, maxmem=2**28, dklen=32)
flag = AESGCM(key).decrypt(nonce, ct, b"the-last-committed-message")
isfcr{a03a410f1b87dbc115dd1ef6}
```

Key techniques: SQLite WAL frames preserve historical database states across checkpoint generations; replaying frames in order and stopping at the right commit boundary reconstructs any intermediate state; WAL frame-header salt values identify which generation a frame belongs to; frames with `commit_size > 0` mark atomic transaction boundaries.
