# Cipher

**Event:** HICyberCon CTF 2026
**Category:** rev
**Flag:** `hiCTF{cryptography_should_be_implemnetd_properly}`

---

**Flag:** `hiCTF{cryptography_should_be_implemnetd_properly}`

**Master passphrase:** `smxvoisk-fcxfgnpl-poznukfv-zxpmztpo-yanlxwmm-yanlxwmm-42`

**Passphrase seed:** `764408707` (= `SeedWindow.base() + 258947`)

---

## 1. Artifact

`cipher.zip` → `cipher.apk` (SHA-256 `d32ec3f2c705e1aefcba505d5f3af157680fe0bab50bc69418927c9298126745`).
Native Kotlin/Java app (`com.hictf26.cipher`, minSdk 26), six small dex files, no native libs.
Three opaque raw assets:

| asset | size | role |
|---|---|---|
| `res/raw/p7.bin` | 6101 | the vault store (magic `V1LT`) |
| `res/raw/n3.bin`  | 96   | verifier anchor (expected HMAC tag) |
| `res/raw/m4.bin`  | 2048 | 256-word lexicon (8 ASCII chars per word) |

## 2. How access is derived (from jadx)

`MainActivity.unlock()` → `CryptoEngine`:

```java
root = PBKDF2WithHmacSHA256(passphrase, salt /*store salt*/, 32768, 256)   // deriveRoot
valid = HMAC_SHA256(root, "cipher-verifier-v3")[0:16] == AnchorReader.readExpected(ctx)
per-record subkey = HKDF-SHA256(ikm=root, salt=storeSalt, info={0x76,0x31,recordIndex})  // one block
plaintext = AES/GCM/NoPadding(key=subkey, iv=12-byte nonce, tag=128)   // AAD = "V1LT"||index
record layout after decrypt: "<title>\x1f<value>"
```

`AnchorReader.readExpected` obfuscates the tag by sampling `n3.bin`:
`expected[i] = n3[(i*11+7) % 96] ^ ((i*19+167) & 255)`.

`VaultStore.load` parses `p7.bin`: `"V1LT"` | version=`3` | salt[16] | count=64 |
then per record `index u8 | nonce[12] | length u16be | ciphertext[length]` (GCM ciphertext+tag).

The algorithm names are string-obfuscated in `Names` (an LCG string decoder), decoded to
`HmacSHA256`, `PBKDF2WithHmacSHA256`, `AES`, `AES/GCM/NoPadding`.

## 3. Finding the passphrase

The passphrase is not hardcoded. The unused-by-MainActivity `legacy` package generates it:

* `Lexicon.load` - `m4.bin` is XOR-masked with `mask = ((i*73)+93) ^ ((i>>3)*17)`, then split
  into 256 fixed 8-char words.
* `SeedWindow.base()` = `((x>>>11) ^ x) & 4095` shifted left by `bits()`=18, where
  `x = (7283617 ^ rol(1688791,7)) + 681`; `span()` = `1<<18`. → seed window
  `[764149760, 764411904)`.
* `LegacyPassphrase.fromSeed(seed)` - `java.util.Random(7640891576956012809L ^ seed)`, pick 6
  words (`nextInt(256)`), join with `-`, append `-%02d` checksum =
  `(nextInt(100) + Long.bitCount(seed)*7) % 100`.

So the passphrase space is 2^18 seeds. `brute.py` re-implements `java.util.Random` **exactly**
(the `nextInt(bound)` rejection loop for the non-power-of-two bound 100 matters - using the
`(bound*next(31))>>31` shortcut gives wrong checksums), runs PBKDF2(32768) + the verifier HMAC
per candidate over 16 cores, and finds the unique match:

```
FOUND (764408707,
  'smxvoisk-fcxfgnpl-poznukfv-zxpmztpo-yanlxwmm-yanlxwmm-42',
  '2803a69149bea3d3535a6ae6073cfb21c76f5ddeebcf7e6b719cbbd3ffb47879')
```

Verifier check passes: `HMAC(root,"cipher-verifier-v3")[:16] == f3840a2b902c711f0ac8f924c295e815`.

## 4. Decrypting the records

`decrypt.py` reimplements HKDF-SHA256 → AES-GCM and decrypts all 64 GCM-verified records.
Record index 47 (the "Archived security memo") yields the flag:

```
REC 47 | Archived security memo | hiCTF{cryptography_should_be_implemnetd_properly}
```

Reproduce:

```bash
unzip -o cipher.zip            # cipher.apk
python3 brute.py               # finds seed + passphrase (~90s, 16 cores)
python3 decrypt.py             # prints all 64 records + the flag
```

## 5. Notes

* The flag text contains the author's typo `implemnetd` (not "implemented") - verified twice
  against the AEAD-verified plaintext, so it is intentional/copied verbatim.
