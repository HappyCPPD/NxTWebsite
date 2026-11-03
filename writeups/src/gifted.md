# GIFTed

**Event:** October 2026 SkillBit Flash CTF
**Category:** forensics
**Flag:** `Skillbit{the_wrapping_was_more_interesting_than_the_gift}`

---


## 1. Recon

`gifted.zip` unpacks to a single file: `gifted/gift.gif`.

```
$ file gift.gif
gift.gif: GIF image data, version 89a, 82 x 82
```

Its 82x82 size is tiny for a "gift" - the interesting part is the frame count.


The gift itself, playing through its 25 frames:

![The animated 82x82 gift.gif](../images/writeups/gifted-attachment.gif "82x82")

## 2. The trick - 25 frames are a 5x5 tile grid

The GIF is animated, 25 frames. 25 = 5x5. Each 82x82 frame is one tile of a larger
410x410 image (5*82 = 410). Paste every frame at `(row, col) = (i//5, i%5)` in frame
order and the tiles line up: the three finder patterns of a QR code land exactly in the
corners. That reassembled image is a QR code.


Reassembled, the frames give this:

![The 25 frames tiled 5 by 5 into a QR code](../images/writeups/gifted-qr.png "410x410")

## 3. Solve

```python
from PIL import Image, ImageSequence
import cv2

im = Image.open("gifted/gift.gif")
frames = [f.convert("RGB") for f in ImageSequence.Iterator(im)]   # 25 frames
w, h = frames[0].size                                             # 82x82
side = int(len(frames) ** 0.5)                                    # 5

big = Image.new("RGB", (w * side, h * side))
for i, fr in enumerate(frames):
    big.paste(fr, ((i % side) * w, (i // side) * h))
big.save("qr.png")

print(cv2.QRCodeDetector().detectAndDecode(cv2.imread("qr.png", 0))[0])
```

Output:

```
Skillbit{the_wrapping_was_more_interesting_than_the_gift}
```

## 4. Flag

```
Skillbit{the_wrapping_was_more_interesting_than_the_gift}
```

(Note the lowercase `b` - the platform uses the `Skillbit{` prefix here, per the source.)
