# Write-Hole

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{p4r1ty_n3v3r_l13s_wr1t3_h0l3_r3m3mb3rs}`

---

A three-drive NAS lost power partway through writing a sealed report; three raw images (`bay0.img`, `bay1.img`, `bay2.img`, 17 MiB each) are given. Every "easy" piece is a decoy for one genuinely nasty record at the end: a record whose GCM tag is the only thing the crash destroyed.

**Fingerprinting:** a structured band starting at `0x100000` (1 MiB) leaks an ext4 superblock (magic `0xEF53`) with volume label `ev-nas3`. The 1 MiB offset implies a metadata reservation area, and the superblock appears identically on `bay0`/`bay1` but is zero on `bay2` - two identical copies plus one zero chunk means **XOR parity (RAID5)**.

**Geometry brute force:** rather than trusting XOR-consistency (broken by design in a write-hole challenge, since the interesting stripes are deliberately inconsistent), the oracle used is **filesystem validity** (`e2fsck -fn`): assembling every `(chunk size, drive order, parity rotation, data order)` combination and checking which produces a clean ext4. Exactly one config works: `C=32768`, `D=0x100000`, left-symmetric parity rotation `(0+2t) mod 3`.

**What's on the volume:** `/etc/nas.conf` confirms RAID5 with **no write-intent bitmap** (the write hole is live) and `data=journal`. `/stage/isfc-stage.py` documents the sealing scheme: 32768-byte records, 12-byte nonce `job||index`, AAD `payload.bin|job|idx`, AES-256-GCM, key burn-after-read from `/stage/.keyslot`. `stage.log` shows job 7's keyslot was rotated and then consumed just before the crash.

**Recovering burn-after-read keys:** because the array overwrites in place nightly, old blocks linger. Scanning for a `KSLT` magic finds several 64-byte keyslot blobs including job 7's discarded (rotated) key and its live key (matched by `key_id`).

**The write hole itself:** `payload.bin` maps to 6 contiguous 32768-byte records across RAID5 stripes. Records 0/2/4 sit intact on single drives. Records 1 and 5 are in stripes where the data chunk was never (re)written but parity was updated - recovered trivially as `parity ^ surviving_neighbour`. **Record 3 is different:** the parity chunk's *write itself was torn* - the nonce bytes are correct but AES-GCM tag verification fails. Since AES-GCM is CTR + GHASH, and the keystream depends only on key+nonce (both already known), the plaintext is recovered by **bypassing the tag entirely**: manually computing the CTR keystream and XORing - no tag required. This is validated by running the identical CTR routine on a record whose tag does verify and matching byte-for-byte.

```python
nonce = rec[:12]
ks = AES_CTR_keystream(key, nonce)
plain = xor(rec[12:-16], ks)   # tag never consulted
```

Three records carry flag shards; concatenating in order:

```
isfcr{p4r1ty_n3v3r_l13s_wr1t3_h0l3_r3m3mb3rs}
```

(The decrypted plaintext literally reads `isfar{...}` due to an author typo - the event's accepted prefix `isfcr{` is substituted on output.) Lessons: use the artifact's own validity as the brute-force oracle instead of an XOR-consistency check that the challenge deliberately breaks; burn-after-read secrets survive in stale blocks on in-place-overwritten media; a lost AEAD authentication tag does not mean lost data if you hold the key and nonce.
