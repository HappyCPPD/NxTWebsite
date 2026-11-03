# The Collector's Trail

**Event:** HICyberCon CTF 2026
**Category:** misc
**Flag:** `hiCTF{marble_sparrow_9eb44602eedb764aac082a3816b7d7cb}`

---

Flag format `hiCTF{}`.

## Flag

`hiCTF{marble_sparrow_9eb44602eedb764aac082a3816b7d7cb}`

## Overview

`the-collectors-trail.zip` contains `image_vault.zip` (6 museum images + a
catalogue colophon) and `sealed_cabinet.zip` (AES-encrypted, password unknown).
Each of the 6 images hides one **fragment** `xxxxxxxxxxxxxxxx-cccc` (8 raw bytes
+ SHA-256 first-2-bytes seal). Fragments and museum catalogue locators are ordered
by the artists' birth years, then fed into HKDF to derive the cabinet password.
The cabinet yields `stego.png`, whose HMAC-selected LSB payload points at a GitHub
release; the annotated tag note supplies a serial used to AES-256-GCM decrypt the flag.

## Step 1 - identify the six works

| Record dir | Painting | Artist | Born | Museum record |
|---|---|---|---|---|
| record-7f2a | Girl with a Pearl Earring | Vermeer | 1632 | mauritshuis.nl/670 |
| record-b19d | The Third of May 1808 | Goya | 1746 | museodelprado.es/P000749 |
| record-31c8 | The Starry Night | Van Gogh | 1853 | moma.org/472.1941 |
| record-d604 | The Kiss | Klimt | 1862 | belvedere.at/912 |
| record-5a73 | The Scream (1893) | Munch | 1863 | nasjonalmuseet.no/NG.M.00939 |
| record-e2f1 | Death and the Maiden | Schiele | 1890 | belvedere.at/3171 |

Order earliest-first: Vermeer, Goya, Van Gogh, Klimt, Munch, Schiele.

## Step 2 - mine the six fragments (each hidden differently)

| Record | Hint (conservation.txt) | Technique | Fragment |
|---|---|---|---|
| 7f2a (Vermeer) | "entries preserved inside the object's own structure" | non-standard PNG chunk `coLl` (21 bytes) | `be5f329a4841bece-ee99` |
| b19d (Goya) | "what remains beyond the final mark" | base64 appended after `IEND` | `b086be35786cac71-8ab3` |
| 31c8 (Van Gogh) | "absence from view does not mean absence of information / what survives when opacity disappears" | text drawn in the **transparent (alpha=0) border** - read the RGB there | `c1d322deee71edf2-cfb8` |
| d604 (Klimt) | "asks for an identity, not merely a number" | `steghide`, passphrase = canonical locator `belvedere.at/912` | `07961017e80fb1e3-b14e` |
| 5a73 (Munch) | "repeated interval through the blue, count begins at zero, every seventh position" | LSB of **blue** channel, `pixels[0::7]` | `7141415e3a146329-c2dc` |
| e2f1 (Schiele) | "before each row can be seen it must be reconstructed / what precedes the row's pixel data" | strip PNG **filter bytes**: `filter==2` → bit, MSB-first | `74718896e450c77c-e551` |

All six pass the seal check: `sha256(first16hex)[:4] == check`.

## Step 3 - master key (HKDF-SHA256)

```
IKM  = concat of the 6 fragments' 8 raw bytes (artist-birth order)
salt = "collector-v2:ossuary"
info = "master"
L    = 32
master = bbb26315a1493bc6e013364b1ccf78ecb7bcc2a3aeb3972f2885f9b2b444b9bf
```

## Step 4 - catalogue salt + cabinet password

Canonical locators (domain lowercased, scheme/`www.` stripped, `/<accession>`,
exact punctuation), joined with `\n` in birth order:

```
mauritshuis.nl/670
museodelprado.es/P000749
moma.org/472.1941
belvedere.at/912
nasjonalmuseet.no/NG.M.00939
belvedere.at/3171
```

`catalogue_digest = sha256(that text)` (raw 32 bytes).

```
cabinet_pw = HKDF-SHA256(IKM=master, salt=catalogue_digest, info="zip", L=16).hex()
           = 77dad76b506abec33742bc43b14710e4
```

`7z x -p77dad76b506abec33742bc43b14710e4 sealed_cabinet.zip` → `readme.txt`, `stego.png`.

![stego.png from the cabinet: thin concentric circles on a dark background](../images/writeups/the-collectors-trail-stego.jpg "1200x675")


## Step 5 - stego.png (HMAC-indexed LSB)

```
image_key = HKDF-SHA256(IKM=master, salt=<empty>, info="stego", L=32)
for counter i = 0,1,2,...:
    pos = int.from_bytes(HMAC-SHA256(image_key, i.to_bytes(8,"big"))[:8], "big") % (W*H*3)
    if pos not seen: record LSB of RGB byte at pos (row-major R,G,B)
assemble bits MSB-first -> [len u32 BE][payload][crc32 u32 BE]
```

Payload (CRC verified):

```
A sealed cabinet remembers its keeper.
GitHub: broski-creator/velarium-ossuary-ledger-7f3c2a
Release tag: v1.0   Asset name: flag.enc   (asset is in the Release, not the tree)
SHA-256: cf9932777723fb3b768006dc21bb832baf3cfa6ffba59c8d84f43f095e3e4bb4
the serial is in the tag's note
Final: flag_key = HKDF(master, salt=bytes.fromhex(serial), info=b"flag", L=32);
       AES-256-GCM decrypt nonce(12)||ct||tag(16), AAD=b"collector-v2".
```

## Step 6 - release, serial, flag

Download asset `flag.enc` (82 bytes, SHA-256 matches). The **annotated** tag
`v1.0` note contains `Serial: 1ec5d6c0778858ef9bd8e651ef1efeae`.

```
flag_key = HKDF-SHA256(master, salt=bytes.fromhex(serial), info="flag", L=32)
plaintext = AESGCM(flag_key).decrypt(nonce, ct+tag, AAD=b"collector-v2")
          = hiCTF{marble_sparrow_9eb44602eedb764aac082a3816b7d7cb}
```

## Notes

- The seam to watch: the Klimt image is a JPEG so `steghide` (not pixel LSB) applies;
  the passphrase is the full canonical locator, not just `912`.
- `record-e2f1`'s data lives in the PNG *filter byte stream* (`filter==2`), not the
  pixel LSBs - a naive LSB scan finds nothing.
- Two Belvedere works (Kiss `912`, Death and the Maiden `3171`) share a domain, so
  birth-year ordering is the only thing that disambiguates them in the digest.
