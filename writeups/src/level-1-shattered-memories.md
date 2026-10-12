# Level 1: Shattered Memories

**Event:** ByteMe CTF 26
**Category:** misc
**Points:** 100
**Flag:** `OWASP{Sh4tt3r3d_m3m0r13s}`

---

**Challenge Description**

> The fragments carry memories distorted by the collapse of Vormir. Sixteen
> pieces remain, but each has been twisted from its original orientation.
> Restore the memories and reveal what the Stone is trying to tell you.

A Google Drive link provides a file: `pieces_1.zip`.

## Solution

### Step 1 - Extract the archive

The zip is password-protected (PK v5.1, requires 7zip). The password is
`OWASP`.

```bash
7z x pieces_1.zip -pOWASP
```

This produces 16 grayscale PNG files (`piece_001.png` through
`piece_016.png`), each 300x300 pixels with strictly binary pixel values (0
or 255).

### Step 2 - Identify the puzzle

Sixteen 300x300 tiles forming a 1200x1200 image - this is a QR code split
into a 4x4 grid. The challenge says each piece has been "twisted from its
original orientation," meaning:

- Each piece is **rotated** by some multiple of 90 degrees
- The pieces are also **shuffled** out of their correct grid positions

### Step 3 - Solve with edge-matching + QR validation

Since the images are strictly black-and-white, adjacent tiles must share
identical pixel values along their shared edge. This gives an exact
constraint for backtracking.

The solver:
1. Precomputes all 4 rotations of each piece and their edge signatures
   (top/right/bottom/left pixel rows)
2. Builds a compatibility graph - for each (piece, rotation), which other
   (piece, rotation) pairs can sit to its right or below
3. Backtracks through all 16 grid positions, placing pieces that match their
   left and top neighbors exactly
4. When all 16 positions are filled, tests the assembled image with
   OpenCV's QR decoder
5. Stops on the first assembly that decodes successfully

```python
from PIL import Image
import numpy as np
import cv2

pieces = [np.array(Image.open(f'pieces_1/piece_{i:03d}.png')) for i in range(1, 17)]
rotated = [[np.rot90(p, r) for r in range(4)] for p in pieces]

def get_edges(arr):
    return (tuple(arr[0,:]), tuple(arr[:,-1]), tuple(arr[-1,:]), tuple(arr[:,0]))

edges = [[get_edges(rotated[pi][r]) for r in range(4)] for pi in range(16)]

# Build compatibility sets
right_compat, below_compat = {}, {}
for pi in range(16):
    for ri in range(4):
        right_compat[(pi,ri)] = set()
        below_compat[(pi,ri)] = set()
        for pj in range(16):
            if pj == pi: continue
            for rj in range(4):
                if edges[pj][rj][3] == edges[pi][ri][1]:
                    right_compat[(pi,ri)].add((pj,rj))
                if edges[pj][rj][0] == edges[pi][ri][2]:
                    below_compat[(pi,ri)].add((pj,rj))

detector = cv2.QRCodeDetector()
solution = [None]*16
used = [False]*16

def solve(pos):
    if pos == 16:
        grid = np.zeros((1200,1200), dtype=np.uint8)
        for idx in range(16):
            r,c = idx//4, idx%4
            pi,ri = solution[idx]
            grid[r*300:(r+1)*300, c*300:(c+1)*300] = rotated[pi][ri]
        data, _, _ = detector.detectAndDecode(grid)
        if data:
            print(f"DECODED: {data}")
            Image.fromarray(grid).save('solved.png')
            return True
        return False
    r, c = pos//4, pos%4
    for pi in range(16):
        if used[pi]: continue
        for ri in range(4):
            ok = True
            if c > 0 and (pi,ri) not in right_compat[solution[pos-1]]:
                ok = False
            if ok and r > 0 and (pi,ri) not in below_compat[solution[pos-4]]:
                ok = False
            if ok:
                solution[pos] = (pi,ri)
                used[pi] = True
                if solve(pos+1): return True
                used[pi] = False
    return False

solve(0)
```

## Result

The decoded QR code reads:

```
SOUL STONE // SHATTERED MEMORIES // OWASP{Sh4tt3r3d_m3m0r13s}
```

## Key Takeaways

- Password-protected zips in CTFs often use the competition name or a
  previous flag as the password
- Binary (black/white) image edges enable exact matching - no tolerance
  needed
- Edge-matching alone produces multiple valid assemblies (trivial matches on
  all-white/all-black edges), so QR decoder validation is needed to find the
  correct one
- Backtracking with pruning makes the search space tractable despite
  16! x 4^16 theoretical combinations
