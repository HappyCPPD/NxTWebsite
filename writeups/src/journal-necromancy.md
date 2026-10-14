# Journal Necromancy

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{mft_slack_dies_but_data_clusters_remember_1a2f}`

---

## 1. The artifact

`evidence.img` (64 MiB, md5 `5bdfa57396e9705f071904223f29d7f4`) is a bare NTFS volume "WORK":

```
Sector 512, cluster 4096, MFT @ byte 0x4000, 222 records, flag format isfcr{...}
```

Two logical layers (both stamped `2026-09-30 00:20:18` - synthetic image):

- **Live:** `Documents/`, `Downloads/`, `Personal/{reminders.txt, vault/secure_archive.enc}`,
  `Photos/2026-03/IMG_2000..2005.png`, `Projects/`.
- **Deleted:** `Cache/_c/` (~131 deleted `c2_*/c1_*/c0_*.tmp`, all 80 bytes), plus deleted
  `wip.tmp`, `notes.txt`, `setup-2026-03.log`.

Most `.md/.txt/.csv` files are corporate word-salad; the PNGs are solid-colour 8×8 images.
All decoys.

## 2. The lock

`Personal/reminders.txt` (inode 86) states the construction:

```
- vault (aes-256-gcm). three-way xor key. do NOT lose a carrier.
  vault layout: 4-byte marker, 12-byte nonce, then ciphertext, 16-byte tag at the end.
  each carrier holds a 32-byte share plus a 1-byte index and a 1-byte xor-parity.
  shares self-identify by index (1/2/3).
```

`Personal/vault/secure_archive.enc` (inode 87, 85 bytes, confirmed via `icat 87`):

```
marker = 454e4331  ("ENC1")
nonce  = 0b19ec38c3998e78f2aa611b                            (12 bytes)
ct     = 72800e27932b3c4ae60108f7d3b387e900bdf8a9ef2ca9e4
         1adc7cc601f3c13b3c98f51c134adf4084910eff818a050d
         790c3dafa9                                           (53 bytes)
tag    = a90238a4c435931b6eb2602c5bc2af6d                     (16 bytes)
```

So `key = share1 ^ share2 ^ share3` (each 32 bytes), vault = `"ENC1" || nonce || ct || tag`,
AES-256-GCM, AAD none.

## 3. Finding the carriers - the magic marker

The decisive step: the three real carriers are tagged with a **4-byte magic `de ad 53 47`**
(`dead...` - the "necromancy" theme). A single grep for it finds exactly three hits (the only
other `de ad` runs are `$UpCase`-table noise, `deac dead deae ...`):

```python
import re
d = open('evidence.img','rb').read()
for m in re.finditer(b'\xde\xad\x53\x47', d):
    p = m.start(); print(hex(p), d[p:p+38].hex())
```

```
0x28b4a5d  dead5347 01 6d 71c9d7ea...4c9409bf   deleted setup-2026-03.log  (cluster 10420)
0x2f65960  dead5347 02 e1 785bae1e...74254034   random cluster 12133
0x36187ce  dead5347 03 ef 39842f22...56438334   deleted notes.txt          (cluster 13848)
```

All three sit inside the **binary tails of deleted files / a random cluster** - the data
clusters survive even though the files are deleted. (This is the whole puzzle: see §6.)

## 4. The carrier layout - the one-byte trap

The reminder says "a 32-byte share plus a 1-byte index and a 1-byte xor-parity" but does **not**
fix the order. Two interpretations both pass the parity self-check, because the parity byte is
adjacent to the share either way:

```
Layout A:  [magic 4][idx 1][parity 1][share 32]     share = bytes[p+6 : p+38]
Layout Y:  [magic 4][idx 1][share 32][parity 1]     share = bytes[p+5 : p+37]   ← correct
```

Both satisfy `parity == xor(share) ^ idx` (so parity alone cannot disambiguate). The GCM tag
disambiguates immediately: **Layout Y verifies, Layout A does not.**

Correct shares (Layout Y):

| idx | share (32 bytes) | parity | `xor(share)^idx` |
|-----|------------------|--------|------------------|
| 1 | `6d71c9d7ead70c055cfa2927a3d3c6a5fb0a7c341b18a986d0196d588b4c9409` | `0xbf` | `0xbf` ✓ |
| 2 | `e1785bae1e7ae88432441b37d3c3d9e3465f003e540d929367cf1f37cc742540` | `0x34` | `0x34` ✓ |
| 3 | `ef39842f2220d28e4a6c38c14e8442048ce9522b0794333c1b54fb3bde564383` | `0x34` | `0x34` ✓ |

## 5. Decrypt

```python
from Crypto.Cipher import AES
import binascii
s1 = binascii.unhexlify("6d71c9d7ead70c055cfa2927a3d3c6a5fb0a7c341b18a986d0196d588b4c9409")
s2 = binascii.unhexlify("e1785bae1e7ae88432441b37d3c3d9e3465f003e540d929367cf1f37cc742540")
s3 = binascii.unhexlify("ef39842f2220d28e4a6c38c14e8442048ce9522b0794333c1b54fb3bde564383")
key = bytes(a ^ b ^ c for a, b, c in zip(s1, s2, s3))

v = open('vault.bin','rb').read()        # icat evidence.img 87 > vault.bin
nonce, ct, tag = v[4:16], v[16:-16], v[-16:]
print(AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag))
# b'isfcr{mft_slack_dies_but_data_clusters_remember_1a2f}'
```

```
key  = 63301656d68d360f24d20ad13e945d4231bc2e2148810829ac828954996ef2ca
FLAG = isfcr{mft_slack_dies_but_data_clusters_remember_1a2f}
```

## 6. Why the "journal" angle is a red herring

- `$LogFile` (inode 2) is genuinely **2 MiB of 0xFF** (verified raw: `icat 2 | uniq`), i.e. the
  NTFS transaction journal was wiped. No `$UsnJrnl` / `$Extend\$UsnJrnl` exists either.
- The title "Journal-Necromancy" and the wiped `$LogFile` bait you into journal recovery. The
  plaintext spells out the real lesson: **"mft slack dies but data clusters remember"** - deleting
  a file clears its MFT record/slack, but the file's *data clusters* are not zeroed, so the
  embedded `dead5347` carriers survive and can be "resurrected."

## 7. Pitfalls that cost the earlier attempt

1. **Parity is only a 1-byte check** - scanning the whole image for `[32 random][idx∈1..3][par]`
   produces many coincidental hits in the two pure-random clusters (2155, 12133) and in the
   deleted cache blobs. Chasing those yielded three bogus "index-1" shares and a decoy idx-3
   (`c2_0017`, which uses `par==xor(share)` *without* the `^idx` term - a different convention).
   The `dead5347` magic is the real discriminator.
2. **The byte-order trap (§4).** Reading the share as the 32 bytes *after* the parity
   (Layout A) instead of *before* it (Layout Y) shifts every share by one byte and yields a key
   that decrypts to garbage. Always let the **GCM tag** arbitrate the layout - it is a perfect
   oracle.
3. NTFS record magic is the four bytes `FILE` (not `FILE0`); a 5-byte compare silently breaks
   hand-rolled MFT parsers.

## 8. Reproduce

```bash
cd ~/Downloads/ctfs/CRYOVAULT/Journal-Necromancy/journal-necromancy
icat evidence.img 87 > vault.bin                       # the vault
python3 - <<'PY'
import re, binascii
from Crypto.Cipher import AES
d = open('evidence.img','rb').read()
sh = {}
for m in re.finditer(b'\xde\xad\x53\x47', d):          # magic 'dead5347'
    p = m.start(); idx = d[p+4]; sh[idx] = d[p+5:p+37]  # layout: magic|idx|share32|par
key = bytes(a ^ b ^ c for a, b, c in zip(sh[1], sh[2], sh[3]))
v = open('vault.bin','rb').read()
print(AES.new(key, AES.MODE_GCM, nonce=v[4:16]).decrypt_and_verify(v[16:-16], v[-16:]))
PY
```

