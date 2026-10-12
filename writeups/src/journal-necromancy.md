# Journal Necromancy

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{mft_slack_dies_but_data_clusters_remember_1a2f}`

---

A 64 MiB bare NTFS volume "WORK" (sector 512, cluster 4096, MFT at byte `0x4000`, 222 records). Live files include a vault (`Personal/vault/secure_archive.enc`, AES-256-GCM); deleted files include ~131 deleted cache blobs and a few individually-named deleted files. Most other files are decoys.

**The lock:** `Personal/reminders.txt` documents the construction - the vault is AES-256-GCM with a **three-way XOR key**, where each "carrier" holds a 32-byte share plus a 1-byte index and a 1-byte XOR-parity, self-identifying by index 1/2/3. The vault layout: 4-byte marker (`"ENC1"`), 12-byte nonce, ciphertext, 16-byte tag.

**Finding the carriers:** the decisive discriminator is a **4-byte magic `de ad 53 47`** ("necromancy" theme) - a grep finds exactly three hits, all sitting inside the binary tails of deleted files or a random cluster (the data clusters survive even though the files themselves are deleted).

**The one-byte trap:** the reminder says "a 32-byte share plus a 1-byte index and a 1-byte xor-parity" but doesn't fix the byte order. Two layouts (`[magic][idx][parity][share]` vs `[magic][idx][share][parity]`) both pass the parity self-check `parity == xor(share) ^ idx`, because the parity byte sits adjacent to the share either way. The **AES-GCM tag disambiguates**: only Layout `[magic][idx][share][parity]` verifies.

```python
key = bytes(a ^ b ^ c for a, b, c in zip(share1, share2, share3))
# AES-256-GCM: marker || nonce || ciphertext || tag
FLAG = isfcr{mft_slack_dies_but_data_clusters_remember_1a2f}
```

The title "Journal-Necromancy" and the fully-wiped `$LogFile` (2 MiB of `0xFF`) are a red herring pointing at journal/UsnJrnl recovery - the real lesson, spelled out by the flag itself, is that **deleting a file clears its MFT record/slack, but not its data clusters**, so the embedded carriers survive and can be "resurrected." A naive full-image parity scan (ignoring the magic) produces several bogus coincidental hits from pure-random clusters and from decoy cache blobs using a different parity convention.
