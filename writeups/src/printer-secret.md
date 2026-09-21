# My Printer Has a Secret

**Event:** TISC 2026
**Category:** osint
**Flag:** `TISC{abn2263123_grey_MS-18E}`

---

## Overview

The challenge hands over one PNG: a fake "PRIVATE ARCHIVE COVER SHEET" printout,
1200x1900, dated 2021-02-16, set in monospace, with a black-framed square of
coloured triangles in the middle and faint yellow dot blocks scattered across
the margins. Three lines of body copy are instructions in disguise:

- *"In case I forget, the color tag points to an archive copy."* - the triangle
  block encodes a URL.
- *"Private-hold jobs may include diagnostic marks on light paper."* - the
  yellow dots are a Machine Identification Code pattern, and they carry a
  password.
- *"Reprints may not preserve all release data."* - some of what you decode is
  deliberately damaged. Don't trust a single copy of anything.

There's also a plaintext `TISC{try_h4rd3r}` sitting in the tag if you decode it
wrong, which is the challenge repeating itself a fourth time.

## Stage 1: the colour tag

The block is a High Capacity Color Barcode lookalike - rows of triangles that
alternate apex-up and apex-down, each painted one of eight colours, so each
triangle carries three bits. Decoding needs the right grid and the right
colour-to-bits permutation. The permutation space is only `8! = 40,320`,
nothing. The grid is where the challenge actually lives.

### Measuring the frame instead of guessing it

Eyeballing the geometry produces tantalising garbage - fragments like
`https://pr` and `r-secret.dm` separated by corrupt bytes. That looks like
channel noise and sends you hunting for error correction that isn't there. It
was just a misaligned grid.

Thresholding for near-black pixels and taking row/column sums across the tag
region gives the frame precisely:

```text
top border    rows  683-695      left border   cols 354-365
bottom border rows 1177-1189     right border  cols 834-845

interior  x = 366..833   (468 px)
          y = 696..1176  (481 px)
```

::: insight
The pitch is **40/3 = 13.333 px**, not 13. That single detail is the whole
puzzle: `481 / 13.333 = 36.07` and `468 / 13.333 = 35.1`, so the tag is
**36 rows x 36 symbol columns**, and the right-hand column is clipped by the
border - exactly the "reprints may not preserve all release data" hint made
literal.
:::

Orientation follows **column parity alone**: even columns point up, odd
columns point down, and column 0 is the left half of an up-triangle whose
centre sits on the frame edge.

### Extracting with a confidence check

For each triangle: walk its scanlines, erode two pixels off every edge to
dodge anti-aliasing, quantise each surviving pixel to the nearest palette
entry, and take the majority. Recording *how dominant* the majority was is the
useful part - it's proof the geometry is right:

```text
low confidence (<0.9): 0      ambiguous symbols: 0
```

All 1296 symbols read cleanly. When the geometry was wrong, hundreds sat in
the 0.45-0.65 range - a much better signal than staring at candidate plaintext.

### Brute-forcing the mapping

With a clean grid, sweep all 40,320 permutations across six reading orders
(row-major, column-major, both boustrophedons, and reversals) and all eight
bit offsets, scoring by the longest run of printable ASCII:

```text
row       (3, 1, 0, 7, 6, 4, 5, 2)  offset 0   run 71   <-- winner
rowrev2   (3, 1, 0, 7, 6, 4, 5, 2)  offset 4   run 68
rowrev    (1, 3, 7, 0, 4, 6, 2, 5)  offset 1   run 41
boust     (5, 3, 7, 2, 4, 6, 0, 1)  offset 1   run 20
col       (2, 5, 7, 3, 1, 4, 0, 6)  offset 0   run 19
colboust  (2, 0, 3, 1, 7, 6, 5, 4)  offset 2   run 17
```

Row-major, offset 0, no header to skip. Scoring on longest printable run
rather than total printable count is what makes the winner unambiguous.

### Two messages, one grid

The 486-byte output is mostly random filler with the URL sitting at bytes
297-366:

```text
b'\x15\xbd\x0f\x85<ihttps://printer-secret.chals.tisc26.ctf.sg/Fn8u92fhuiWAfeAfGu23dy.zip\x9d\x16\x1f\t\x18;\x8a'
```

Re-reading the *same* symbols under permutation `(3,2,4,6,5,1,7,0)`, in a
different byte range, turns into English:

::: pitfall
`this is the flag: TISC{try_h4rd3r}` - decoy, do not submit. The two messages
occupy disjoint byte ranges, encoded under different permutations, so decoding
"wrong" for one region decodes "right" for the other. A tell that this was
hand-tuned: the decoy's leading capital decodes as lowercase `t`, one bit off
from `T`.
:::

## Stage 2: the tracking dots

Real colour laser printers stamp a faint yellow Machine Identification Code
across every page; this sheet fakes one. Isolating pixels where blue sits well
below red and green (while masking out the colour tag, which is full of
yellow triangles) and labelling connected components finds **eight** dot
blocks in the margins, not one.

Each block is a 16x16 lattice on a 10 px pitch. Row 0 and column 0 are
calibration - they sit on the lattice exactly. The remaining 14x14 = 196
positions are payload, and the bit is a **horizontal displacement**: roughly
+1 px for a 0, +4 px for a 1. The last four bits are padding, leaving 192
bits, or 24 ASCII characters.

Decoding all eight and comparing is where the "reprints may not preserve all
release data" hint pays off:

```text
block 1   sut0roberi1-fure!b4a_*<^     4 dots missing
block 2   sut0roberi1-fure!b4a_*=^     clean
block 3   sut0roberi1-fure!b4A_*=^     4 dots missing
block 4   sut0roberi1-fure!b4a_*<\x00  14 dots missing
block 5   sut0roberi1-fure!b4A]*\r^    6 dots missing
block 6   sut0roberi1-fure!b4a_*=^     clean
block 7   sut0roberi1-fure!b4a_*=^     clean
block 8   sut0roberi1-fure!b4a_*=^     clean
```

::: pitfall
Four blocks are pristine and agree exactly: `sut0roberi1-fure!b4a_*=^` is the
password. Read only one block and there's a 50% chance of a wrong character -
reading block 1 alone gives `*<^` instead of `*=^`.
:::

## Stage 3: the archive

```bash
curl -O https://printer-secret.chals.tisc26.ctf.sg/Fn8u92fhuiWAfeAfGu23dy.zip
unzip -P 'sut0roberi1-fure!b4a_*=^' Fn8u92fhuiWAfeAfGu23dy.zip
# inflating: printer-secret-part2.txt
```

The text file is a brief, not a flag. It opens with strict rules of
engagement (passive OSINT only, never contact the seller, no forms, no carts,
no aggressive scraping), then sets the actual puzzle: a modeller is hunting a
deleted Yahoo Auctions listing for a weathered RGM-79[G] Gundam kit, auction
ID `d500233180`, and wants the seller traced across three places:

1. The seller's Flickr username.
2. On a plastic-model hobby site, the colour of the pants they're wearing in a
   photo featuring their pet.
3. On their own shop site, the model number of the item in the cover photo.

Format: `TISC{flickruser_colour_MODELNUMBER}`.

## Stage 4: the OSINT chain

### Getting a seller ID out of a deleted listing

The auction ID is genuinely dead - Yahoo 404s it, the Wayback Machine has no
snapshot under any URL form, and no search engine has a single result for the
string. Proxy-buying mirrors are all Cloudflare-walled.

What does have it: **aucfan**, a Japanese auction-archive service, at
`aucview.aucfan.com/yahoo/d500233180/`. The archived page confirms the item
(a weathered Ground Type GM kit, listing opened 2021-02-15, which lines up
with the cover sheet's `Created: 2021-02-16` date).

aucfan masks the seller as `Dl-Le7RY0p1`, which returns nothing anywhere. The
real ID leaks through the affiliate redirect behind the "view this seller's
other auctions" link:

```html
<a href="https://linkout.aucfan.com/?to=...vc_url=https%3A%2F%2Fauctions.yahoo.co.jp%2Fseller%2Fabn22631">
```

Read the anchors, not the rendered text.

### The three answers

| where | answer | how |
|---|---|---|
| Seller ID | `abn22631` | Recovered from the aucfan affiliate link; searching it surfaces two hobby profiles. |
| Flickr | `abn2263123` | `flickr.com/photos/197582828@N07/`, display name "22631 abn", 942 photos. No vanity URL exists at `/abn22631`, so the NSID path is the only way in - and the flag wants the **username**, not the display name. |
| Hobby site | `grey` | ARTHOBYCOMM. The profile header photo shows their cat on a chevron rug, with the owner's knee in frame in heather-grey sweatpants (sampled RGB ~90/92/96, saturation 0.06 - genuinely neutral). |
| Shop | `MS-18E` | A BASE storefront, `abn2263123.base.ec`, linked from a GUNSTA profile. No background image is set, so the cover photo is the single product's lead image: a title card reading MS-18E KAMPFER. |

### The two traps

::: pitfall
**GUNSTA is a decoy for question 2.** The same handle has a busy account on
GUNSTA (`gumpla.jp`), a Gunpla-posting community, and it's the obvious
candidate for "a plastic model hobby website". It isn't the answer - pulling
all 66 posts (292 deduplicated images) shows all Gunpla, no pet, no person,
and a default avatar. GUNSTA's real job in the chain is carrying the link to
the shop.
:::

::: pitfall
**ARTHOBYCOMM renders client-side.** The right profile is at
`app.arthobycomm.net/user/1747963602149376`, and curling it returns:

```text
NO IMAGE  Profile  0 posts  0 followers
self-introduction not yet set.
loading...
```

That's the SSR shell, pre-hydration - easy to write off as an empty account.
Loaded in a real browser it fills in: 36 posts, 29 followers, a bio reading
"I moved over from Hobbycom", a ragdoll-cat avatar, and the header photo that
answers the question. If you only ever curl, this challenge has no answer.
:::

```text
TISC{abn2263123_grey_MS-18E}
```

The two judgement calls: *grey* over *gray* (the brief spells it "colour"),
and the Flickr **username** over the display name (the format example is a
handle, not a display name).

## Takeaways

- **Guessing the grid instead of measuring it.** A 13 px pitch against a true
  13.333 px drifts by half a cell over 36 columns - the output degrades
  gradually rather than failing outright, which reads like channel noise.
  Measure the boundaries, then confirm with a per-symbol confidence score.
- **Trusting one copy.** Eight dot blocks exist precisely so you cross-check
  them; decoding one and moving on gets a password that's one character
  wrong, and the failure surfaces much later as a zip that won't open.
- **Trusting curl.** The decisive page returns a hydration placeholder to
  non-browsers. If a profile looks suspiciously empty, render it before
  believing it.
