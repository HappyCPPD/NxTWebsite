# One Pound Fish

**Event:** CryoVault CTF 2026
**Category:** osint
**Flag:** `isfcr{russell_market}`

---

A single image `fish.png` (745×999) with only the title "One-pound-fish" - no description, no EXIF/GPS. Standard steganography checks (`exiftool`, `binwalk`, `zsteg`, PNG chunk walk) confirm this is a pure visual geolocation challenge.

**Visual analysis:** an outdoor fish market in a narrow lane - a tall old stone/masonry compound wall on the left with blue-painted stalls at its base; multi-story concrete buildings on the right with colonial-era arched windows and roll-up metal shutters; a blue circular "SA" sign in the background; a woman in a black hijab selling fish; a deliberate white blur across the center obscuring signage.

**Reverse image search:** TinEye found zero matches (image not indexed), Yandex CBIR returned only generic "fish market" tags (Malé, Hurghada, Blida - no exact match), Bing Visual Search mis-guessed "Essaouira Fish Market." **Google Lens correctly identified Russell Market, Shivajinagar, Bengaluru, India**, with its AI Overview explicitly describing "the open-air fish and seafood market section outside Russell Market."

**Confirmation:** Russell Market fits every visual clue - built in 1927 in Tudor/colonial style by the British (explaining the arched windows and old masonry), located in Shivajinagar, a predominantly Muslim neighborhood in central Bengaluru (explaining the hijab-wearing vendors), with the tall wall being the market complex's boundary wall and outdoor fish-selling spilling into adjacent lanes. The CTF is organized by ISFCR at PES University, Bengaluru - the photo was almost certainly taken by a student at their own city's iconic market, 3 km from campus.

```
isfcr{russell_market}
```

Lessons: Google Lens's visual feature matching and AI overview outperformed TinEye/Yandex/Bing on this unindexed photo (datacenter/VPN IPs get aggressively captcha'd by Lens - the solve required uploading via imgur and using the `uploadbyurl` Lens endpoint). The "One-pound-fish" title references a viral 2012 fishmonger song and is thematic rather than a direct geographic pun - extensive incorrect analysis chasing "pond" (Pondicherry) and Algeria wasted time before the simplest reading (it's a fish market challenge) proved correct. Local organizer context (a Bengaluru-based CTF) made the market's local fame the deciding signal.
