# Level 0: First Fragment

**Event:** ByteMe CTF 26
**Category:** misc
**Points:** 100
**Flag:** `OWASP{Th3_f1rst_fr4gm3nt}`

---

**Attachment**

`pieces_0.zip` (Google Drive `1xzftGKuzaUB9p3oSCpjp3uISb_VJlXIr`). Contains
a single folder `pieces_0/` with **9 PNG tiles** `piece_001.png …
piece_009.png`, each **400×400, 8-bit grayscale**.

The zip uses **WinZip AES-256** (compress method `99`, PK version 5.1). Old
`unzip` and Python `zipfile` both refuse it ("need PK compat v5.1 /
encrypted"). `7z` handles it.

## Step 1 - Crack the zip password

The zip has no comment and the challenge ships no hint, but the whole event
is OWASP-branded and the resource attachment literally says "OWASP". The
password is simply:

```
OWASP
bash
for p in owasp OWASP soulstone ... ; do 7z t -p"$p" pieces_0.zip && echo "$p"; done
# -> OWASP
7z x -pOWASP pieces_0.zip
```

## Step 2 - Recognise the puzzle

The nine 400×400 tiles are slices of one **1200×1200 QR code** smashed into
a 3×3 grid and shuffled. Two giveaways:

- Module size ≈ **24.49 px** (measured from the smallest dark/white run),
  so a 1200 px image is ≈ **49 modules** → a QR version 6..8 with a quiet
  zone.
- Three tiles (**007, 008, 009**) each contain a full QR **finder pattern**
  (the 1:1:3:1:1 bullseye). The other six are dense data modules. One tile
  (**006**) carries the small **alignment pattern**.

Locating the finder centre in each of those tiles by template-matching the
ideal 7-module finder (module = 1200/49):

| tile | finder centre (local px) |
|------|--------------------------|
| 008  | (183, 183) |
| 009  | (216, 183) |
| 007  | (183, 216) |

## Step 3 - Solve the geometry (this is the whole trick)

Work out where a valid QR's finders *should* be. Assume a QR **version 6** =
41 modules, module `m = 24.49 px`, drawn with a **quiet zone `q`**:

- top-left finder centre  = `(q + 3.5m, q + 3.5m)`
- top-right finder centre = `(q + 37.5m, q + 3.5m)`
- bottom-left finder centre = `(q + 3.5m, q + 37.5m)`

From tile 008's (183,183): `q + 3.5·24.49 = 183 → q ≈ 97 px`. Then
`q + 37.5·24.49 = 97 + 918 ≈ 1015`.

- Tile **008** local (183,183) → top-left cell **(row 0, col 0)** ✓
- Tile **009** local (216,183): 216 + 800 = **1016** → top-right cell
  **(row 0, col 2)** ✓
- Tile **007** local (183,216): 216 + 800 = **1016** → bottom-left cell
  **(row 2, col 0)** ✓

No rotation needed - the corner tiles drop straight in. Only the **6 data
tiles remain**: `{001, 002, 003, 004, 005, 006}` into the 6 open cells
`{1,3,4,5,7,8}` → just **6! = 720** candidate assemblies instead of
9! = 362 880.

## Step 4 - Brute-force the last six and decode

Assemble each of the 720 permutations into a 1200×1200 image and hand it to
a QR decoder (`zxing-cpp`). The correct one:

```
cells (row-major 0..8):  [008, 001, 009,
                          005, 003, 004,
                          007, 002, 006]
```

decodes to:

```
SOUL STONE // FIRST FRAGMENT // OWASP{Th3_f1rst_fr4gm3nt}
```

## Step 5 - Flag

```
OWASP{Th3_f1rst_fr4gm3nt}
```

## Reproduce

```bash
7z x -pOWASP pieces_0.zip -opieces_0
python3 solve.py     # see solve.py - arranges tiles + decodes
# needs: pip install pillow numpy zxing-cpp
```

`solved_first_fragment.png` in this folder is the reconstructed QR.
