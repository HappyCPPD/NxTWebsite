# Shadow Identity

**Event:** HICyberCon CTF 2026
**Category:** osint
**Flag:** `hiCTF{Jihan-Mohin-Dimachk}`

---

## Challenge

We were given a single file, `miss_grand.jpeg` (481x636), an AI-styled promotional poster reading "Miss Grand Tanzania 2026". The task is to put the woman's full name in the flag.

![The challenge poster: a woman in a green beaded gown and crown, with a Tanzanian flag, Mount Kilimanjaro and gold filigree, captioned Miss Grand Tanzania 2026](../images/writeups/shadow-identity-attachment.jpg "481x636")

## Solution

### Step 1 - Rule out hidden data

First the usual checks, in case the name was buried instead of visible:

| Check | Result |
|-------|--------|
| EXIF / GPS | none, only basic JFIF density tags |
| C2PA / JUMBF manifest | none |
| Trailing data after the JPEG EOI | none (0 bytes) |
| ASCII strings | nothing readable, no flag, no handle |

The image is clean. Everything we need is in the picture itself, so this is a face-identification problem, not a forensics one.

### Step 2 - Reverse search the face

The background (Kilimanjaro, the flag, the gold mandala) is AI filler, so the "Miss Grand Tanzania 2026" caption plus a crop of the face is what we search on. Running the face through reverse image search returns the real person behind the styled poster:

| Engine | Result |
|--------|--------|
| Reverse image / face search | matches the Miss Grand Tanzania 2026 titleholder |
| News confirmation | crowned Miss Grand Tanzania 2026 (Mwanza), then won Miss Grand International 2026 in Bangkok |

Her full name, as carried by the international pageant press, is **Jihan Mohin Dimachk** (Tanzanian outlets also write it *Jihan Dimack*).

### Step 3 - Confirm

Cross-checking the news: Jihan Mohin Dimachk, representing Mwanza, won the national Miss Grand Tanzania title on 8 August 2026, then on 10 October 2026 became the first African woman to win Miss Grand International. The face, the sash title and the year all agree with the poster.

## Flag

```text
hiCTF{Jihan-Mohin-Dimachk}
```

## Takeaways

- Check for metadata, trailing bytes and embedded strings before assuming a poster is "just" an identify-the-person task, but do not over-think a clean file.
- AI-styled graphics still reverse-search on the real face. Crop to the face and ignore the generated background.
- Names cross borders in more than one spelling. Pin the identity down with a dated news source, and note the variant spelling the scoreboard expects.
