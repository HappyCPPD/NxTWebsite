# Neuropet

**Event:** SolarCTF
**Category:** rev
**Flag:** `SOLARCTF{FR1d0Mp_Sc4n_p4G3s_in_GamEEE}`

---

**Flag: `SOLARCTF{FR1d0Mp_Sc4n_p4G3s_in_GamEEE}`**

Artifact: `neuropet.ab` (359,458 B). Description: "A Neuro Tamagotchi in every home, password 0000"
(neuro-tamagotchi in every home, password 0000). Author M0shp1t.

---

## 1. `neuropet.ab` is an Android Backup

```
$ file neuropet.ab
Android Backup, version 1, Compressed, Not-Encrypted
$ xxd neuropet.ab | head -2
00000000: 414e 4452 4f49 4420 4241 434b 5550 0a31  ANDROID BACKUP.1
00000010: 0a31 0a6e 6f6e 650a 78da ...
```

Header = 4 text lines (`ANDROID BACKUP`, `1`, `1`, `none`); the zlib stream starts at offset
24 (`78 da`). Decompress → 378,880 B → a tar archive:

```
$ python3 -c "import zlib;open('backup.decompressed','wb').write(zlib.decompress(open('neuropet.ab','rb').read()[24:]))"
$ tar -tvf backup.decompressed
apps/com.solarlabs.neuropet/_manifest      1672
apps/com.solarlabs.neuropet/f/rList          71
apps/com.solarlabs.neuropet/a/base.apk   364193
```

## 2. APK contents

```
classes.dex                        24,764 B   (R8 full mode, min-api 26)
assets/neuro/brain.bin              1,865 B   magic NRBC
assets/neuro/weights.bin          262,154 B   magic NRWT
assets/neuro/skin.dat               5,342 B   no magic, high entropy
lib/arm64-v8a/libneurocore.so      11,320 B
lib/x86_64/libneurocore.so         11,960 B   <-- the APK ships an x86_64 slice!
resources.arsc                              (Russian UI labels only)
```

Java package `com.solarlabs.neuropet`: `MainActivity`, `AboutActivity`, `PetView`, `App`,
`core/Q` (JNI), `proto/{Io,Wire}`.

## 3. `skin.dat` is a hidden DEX (LCG-xor)

`App.onCreate` (jadx `--show-bad-code`) builds an asset name from
`{69,78,94,89,68,4,88,64,66,69,5,79,74,95} ^ 43` = `neuro/skin.dat`, then decrypts it:

```java
long j2 = (g2[0] & 255) | ((g2[1] & 255) << 8);       // 16-bit LE seed
for (i = 0; i < len; i++) {
    long j3 = ((j2 * 1103515245) + 12345) & 0xffffffff;  // LCG
    bArr[i] = (byte)(((j3 >> 16) & 255) ^ g2[i + 2]);
    j2 = j3;
}
bArr[0]=100; bArr[1]=101; bArr[2]=120; bArr[3]=10;    // "dex\n"
InMemoryDexClassLoader(ByteBuffer.wrap(bArr), getClassLoader());
```

Decrypting gives a 5,340-byte DEX (`lab.dex`, sha256
`f70eeb6f155f2cd9d026017e7d14166c9437636a6865197a764a987af1a2cdff`) holding three hidden
classes: **`Trig`, `LabActivity`, `LabHold`**.

## 4. The hidden "lab" and the flag path

`AboutActivity.onCreate` attaches a click listener to `brand_word`. The handler builds a class
name with XOR-61 (`{94,82,80,19,...}` → `com.solarlabs.neuropet.lab.Trig`) and calls
`Trig.hit()`; on success it starts a second XOR-61-decoded class
(`...lab.LabActivity`) from the in-memory loader; otherwise it toasts `lab_unavailable`.

`Trig.hit()` = **5 taps within 1500 ms** (`TAPS=5`, `WINDOW_MS=1500`).

`LabActivity`'s `LabView.onDraw` steps a phase counter; once, at phase 2:

```java
io.run(LabActivity.de(53, new int[]{81,80,67,71,90,90,88}));   // de() = XOR 53 -> "devroom"
LabHold.seg = io.query(0);                                      // -> Q.nQuery(0)
```

So the flag path is: run the native script **`devroom`**, then read query index 0.
(The screen only ever draws "4/4" - the flag is never displayed, so you must instrument or
emulate; that's why the challenge needs RE rather than just running the app.)

## 5. Driving the native core directly (no JNI, no watchdog)

`libneurocore.so` exports four JNI functions that are thin bridges. Disassembling the x86_64
slice shows the real entry points, and they are plain C:

```
nInit  -> init (0xff0)  : void* init(uint8_t* data, long len)          // data = brain.bin
nRun   -> run  (0x1300) : int   run(void* obj, const char* script, int, long budget)
nQuery -> query(0x1e10) : long  query(void* obj, int idx, uint8_t* out, long cap)
```

`nInit` additionally spawns a detached anti-analysis thread (scans `/proc/self/maps` for
`frida`, `gum-js`, `gadget`, `substrate`, `/data/local/tmp/re.frida.server` and `_exit(7)`s on a
hit). Calling **`init`/`run`/`query` directly bypasses both the JNI plumbing and that thread.**

Running the Android x86_64 `.so` under glibc needs two fixes:

1. It demands a bionic symbol version `LIBC`. Patch a **copy**: rewrite the `DT_VERNEED`,
   `DT_VERNEEDNUM`, `DT_VERSYM` tags in `.dynamic` to `DT_DEBUG` (21) - the loader then ignores
   versioning. (`patch_so.py`)
2. It needs bionic's `__errno`. Supply it via `LD_PRELOAD` (`bionic_shim.so`:
   `int *__errno(void){return __errno_location();}`). A dummy `liblog.so` and `libc.so` symlink
   complete the stub dir.

Then (see `harness4.c`):

```c
void* obj = init(data_brain_bin, 1865);
run(obj, "devroom", 0, 0x2faf080);        // budget matters: rc=5 without it, rc=0 with it
for (idx = 1..4) query(obj, idx, out, 0x80);
```

## 6. The four "neurons" and their encodings

Four query indices return one fragment each, each prefixed with a marker and each encoded
differently - the marker is what identifies the inverse transform:

| idx | raw output | inverse transform | marker + payload |
|---|---|---|---|
| 1 | `NEUROC1!SOLARCTF{F` | identity | `SOLARCTF{F` |
| 2 | `LGWPMA0#P3f2Or]Qa6` | XOR 0x02 | `NEUROC2!R1d0Mp_Sc4` |
| 3 | `i_s3G4p_n!3CORUEN` | reverse | `NEUROC3!n_p4G3s_i` |
| 4 | `4e 00 45 00 55 00 …` | de-interleave (every 2nd byte) | `NEUROC4!n_GamEEE}` |

Concatenating the payloads in marker order:

```
SOLARCTF{F + R1d0Mp_Sc4 + n_p4G3s_i + n_GamEEE}
```

Note the fragments interlock across their boundaries: `_Sc4` + `n_p4G3s` = `_Sc4n_p4G3s`
(`…scan_pages…`), and `s_i` + `n_GamE` = `s_in_GamE`. This confirms the order.

**Flag: `SOLARCTF{FR1d0Mp_Sc4n_p4G3s_in_GamEEE}`**

## 7. Reproduce

```bash
cd ~/Downloads/ctfs/Solarctf/Neuropet
python3 tools/unpack.py            # android backup -> tar -> apk  (or the one-liners in §1)
python3 tools/decrypt_skin.py      # -> lab.dex
~/tools/jadx/bin/jadx -d lab_java --show-bad-code lab.dex
python3 tools/patch_so.py          # neutralise bionic LIBC symbol versioning
gcc -shared -fPIC -o tools/stubs/bionic_shim.so tools/bionic_shim.c
gcc -O1 -o tools/harness4 tools/harness4.c -ldl
LD_LIBRARY_PATH=tools/stubs LD_PRELOAD=tools/stubs/bionic_shim.so \
  tools/harness4 devroom
# -> ASSEMBLED (payloads concatenated): SOLARCTF{FR1d0Mp_Sc4n_p4G3s_in_GamEEE}
```
