# Paper Trail

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{n3w_ar34_fOr_hid!ng_d4t4_n4m3d_TJ}`

---

## Challenge

> "The document passed its final review without raising any concerns. What was submitted
> appeared complete, and nothing seemed out of place. But the archived copy tells a different
> story. Some changes leave no visible trace."

We get `chall.pdf`, 13 pages, 516,033 bytes.

## Finding what changed

The PDF is a real published paper, *"Forensic Analysis of Virtual Hard Drives"* (JDFSL, 2017).
The description says the archived copy tells a different story, so I pulled the original from
the Wayback Machine and diffed the two at the object level, hashing every object and every
decompressed stream.

* The challenge file has **exactly four** streams the original lacks, objects 179 to 182, and
  nothing removed or altered. The other new objects are structural (StructTree kids, `/Nums`, a
  rewritten `/Info`).
* `pdftotext` output is byte-identical on all 13 pages, so no visible text changed.
* The original has no `Tr` operators at all. The challenge file has four.
* Every font is byte-identical to the original, there are no embedded files, and the XMP is
  clean.

So the whole plant is those four streams.

## The invisible overlays

Each new stream is appended to the content of pages 2, 5, 8 and 11 (zero-indexed), and looks
like this:

```
q BT /F1 1 Tf 3 Tr 1 0 0 1 8 8 Tm
[() A () B () C n1 n2 ... nk] TJ
... ET Q
```

`3 Tr` is render mode 3, invisible text, at 1 pt in the corner of the page. Every string in the
`TJ` arrays is empty, so the only thing these streams carry is the numbers, which `TJ` would
normally treat as kerning adjustments.

* There are 20 `TJ` lines and **169 integers** in total, ranging from -77 to 254.
* Real kerning elsewhere in this PDF is fractional (for example `-18688.6`). These are all
  integers, so they are data.
* Three of the lines are much longer than the rest and hold 64 values, all between 1 and 254.
  Every other value sits in a small band around zero and acts as a decoy.

64 values in byte range is exactly four AES blocks, which points at a block cipher rather than a
text encoding.

## The key was in the trailer

The trailer `/ID` array normally stays the same when a PDF is re-saved with qpdf or pikepdf. Here
**both** `/ID` elements differ from the archived original, which means the author set them on
purpose. They are 16 bytes each, a perfect AES-128 key and IV.

* Key = `/ID[0]` = `e3b51a3ba231502d79c55593eb522037`
* IV = `/ID[1]` = `6749db1175e3e659a640695dcc830c82`
* Ciphertext = the three long `TJ` arrays from their third number onward, in stream order
  179, 180, 181 (21 + 21 + 22 = 64 bytes)

AES-128-CBC decryption gives a small framed record:

```
"CTF1" | u16 BE length (0x0028 = 40) | flag (40 bytes) | 8-byte tag | PKCS#7 padding (10 x 0x0a)
```

The length field matches the flag exactly and the padding is valid, which confirms the key, IV
and byte selection are right.

## Flag

```
hiCTF{n3w_ar34_fOr_hid!ng_d4t4_n4m3d_TJ}
```

The flag names the carrier: data hidden in the `TJ` operator.
