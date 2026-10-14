# FlaGuard

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{sh4d0w_cl455l04d3r_tr1ckery}`

---

## 0. Prompt

> A small Android app called FlaGuard turned up on a forum, pitched as the
> strictest flag-format validator around. Nobody will say which flag it
> actually accepts. Flag format: `isfcr{...}`.

The wording ("which flag it **actually** accepts") is the whole clue: there are
two candidate flags, and only true runtime behaviour picks the winner. The
answer turns out to hinge on a one-line buffer bug.

## 1. Triage

```
flaguard.apk: Android package (APK), with AndroidManifest.xml, with APK Signing Block
```

Unzipping shows a deliberately tiny app:

```
AndroidManifest.xml
classes.dex          (9,780 bytes)
resources.arsc
res/layout/activity_main.xml
assets/theme.pack    (1,296 bytes, opaque)
assets/palette.webp  (1,318 bytes, "lossless WebP")
META-INF/...
```

Two odd assets stand out: `theme.pack` (high entropy - looks encrypted) and
`palette.webp` (a "lossless WebP" that the code nonetheless consults).
`strings classes.dex` surfaces `isfcr{`, `sha256`, `SecretKeySpec`/`javax.crypto`,
and the classes `App`, `Analytics`, `FlagChecker`, `MainActivity`, `obf/Veil`.

```bash
/tmp/jadx/bin/jadx -d /tmp/fg_src flaguard.apk
```

## 2. First candidate - the visible checker

`FlagChecker.java` in `classes.dex`:

```java
private static final int INIT = 7039;
private static final int[] P = {55,141,25,242,75,166};
private static final int[] C = {4765,34647,...,61896};      // 34 entries

public static boolean check(String s) {
    if (s==null || !s.startsWith("isfcr{") || !s.endsWith("}")) return false;
    byte[] b = s.getBytes();
    if (b.length != C.length) return false;
    int i = INIT;
    for (int k=0; k<b.length; k++) {
        i = ((i*131) + (b[k]&255) + P[k % 6]) & 0xFFFF;
        if (i != C[k]) return false;
    }
    return true;
}
```

A deterministic affine recurrence: every term except `b[k]` is known, so each
byte inverts directly - `b[k] = (C[k] - P[k%6] - i*131) & 0xFFFF`, then
`i = C[k]`.

```
isfcr{sh4d0w_cl455l04d3r_tr1ckery}
```

34 bytes, validates.

## 3. String obfuscation (`obf/Veil.java`)

`App`/`Analytics` pull their constants from an XOR pool:

```java
private static final byte K = 91;
private static final byte[] POOL = {...};
private static final int[]  OFF = {0,12,22,38,74,80,87,104,107,126,130,139,150,161};
private static final int[]  LEN = {12,10,16,36,6,7,17,3,19,4,9,11,11,9};
public static String s(int i) {
    int o=OFF[i], l=LEN[i]; char[] c=new char[l];
    for (int j=0;j<l;j++) c[j]=(char)((POOL[o+j]^K)&255);
    return new String(c);
}
```

Decoding the 14 strings:

| i | string |
|---|--------|
| 0 | `palette.webp` |
| 1 | `theme.pack` |
| 2 | `flaguard-boot-v3` |
| 3 | `dalvik.system.InMemoryDexClassLoader` |
| 4 | `parent` |
| 5 | `SHA-256` |
| 6 | `AES/CBC/NoPadding` |
| 7 | `AES` |
| 8 | `java.nio.ByteBuffer` |
| 11 | `classes.dex` |
| 12 | `trust.chain` |
| 13 | `.internal` |

The app intends to boot a second dex **in memory**. This is where the decoy
lives.

## 4. `App.bind()` - the intended (but broken) shadow

`attachBaseContext()` runs `bind()` before anything else:

```java
byte[] all  = readAll(assets.open(Veil.s(0)));   // palette.webp
byte[] all2 = readAll(assets.open(Veil.s(1)));   // theme.pack  (encrypted dex)
byte[] hDex = sha256(readSelfEntry(ctx, Veil.s(11)));   // sha256 of classes.dex entry

byte[] bArr = new byte[128];
System.arraycopy(all, (all[16] & 63) + 64, bArr, 0, 128);      // carve 128B out of palette
byte[] key  = sha256(concat3(bArr, "flaguard-boot-v3".getBytes(), hDex)); // 32B AES key
byte[] iv   = sha256(concat(hDex, bArr[0..16])).slice(0,16);   // 16B IV

Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
c.init(DECRYPT, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
byte[] dex = c.doFinal(all2);                                   // hidden dex

ByteBuffer bb = ByteBuffer.allocateDirect(dex.length);
bb.put(dex);                                                    // <-- position = len
Object loader = Class.forName("dalvik.system.InMemoryDexClassLoader")
        .getConstructor(ByteBuffer.class, ClassLoader.class)
        .newInstance(bb, ctx.getClassLoader().getParent());     // <-- dead buffer

Field f = ClassLoader.class.getDeclaredField("parent");
f.setAccessible(true);
f.set(ctx.getClassLoader(), loader);
```

Notes:
- `palette.webp` is not a palette: it is a **128-byte key-shard container**.
  The shard offset is `(palette[16] & 63) + 64` = 82.
- `Analytics.enabled()` is true only when the package name ends in `.internal`;
  the shipped package `dev.srspace.flaguard` does not, so the `trust.chain`
  branch (asset index 12) is skipped and the IV is the plain
  `sha256(classes.dex_hash || bArr[0:16])[:16]`.
- `theme.pack` is `AES-256-CBC/NoPadding`; length 1296 is a clean multiple of 16
  and the plaintext is a `dex\n038` file of declared size 1288.

In principle the last lines *would* shadow the visible checker: replacing the
app ClassLoader's `parent` with the in-memory dex loader means parent-first
lookup finds the hidden `FlagChecker` before the app's own dex. **But the
buffer is never prepared for reading.**

## 5. The bug that decides the challenge

```java
ByteBuffer bb = ByteBuffer.allocateDirect(dex.length);
bb.put(dex);                     // advances position to dex.length
```

After `put`, the buffer's `position == limit == capacity`, i.e.
`remaining() == 0`. A `ByteBuffer` is read from `position` to `limit`, and
`InMemoryDexClassLoader` expects the dex bytes starting at `position`. There is
**no `bb.flip()` (or `bb.rewind()`/`bb.position(0)`)** before the buffer is
handed to the constructor. The loader therefore sees an empty slice and
contributes **no classes at all**.

Consequence at runtime:
1. `bind()` still succeeds (no exception - an empty in-memory dex file yields an
   empty loader rather than a hard failure).
2. The app ClassLoader's parent points at the inert loader.
3. `MainActivity.verify()` calls `dev.srspace.flaguard.FlagChecker.check()`.
   Parent-first lookup asks the inert loader (miss), then resolves from the
   app's own `classes.dex` - the **visible** `FlagChecker`.
4. The visible checker is what actually validates input.

So the shadowed/decrypted flag is the decoy, and the ordinary static checker is
the real one. The name of the hidden flag (`p4r3nt_f1rst_d3x_1s_s0_m34n`)
narrates the trick the author *wanted* you to fall for; the accepted flag
(`sh4d0w_cl455l04d3r_tr1ckery`) calls the dynamic loader itself the trickery.

## 6. The decoy dex (for completeness)

Reproducing the derivation (see `solve.py`):

```
sha256(classes.dex)  = 91400bf2...920f6a
palette[16] & 63 +64 = 82
AES key = SHA256(shard || "flaguard-boot-v3" || dexhash)
        = 799ac08bc7db682485c6b20fe68cd1f927a15887b14700c2ea85c26bfbc7df24
AES iv  = SHA256(dexhash || shard[0:16])[:16]
        = 2eaf112eab19925f3f1c14537de15c73
```

`openssl enc -aes-256-cbc -d -nopad -K <key> -iv <iv> -in theme.pack` yields a
valid `dex\n038` (1288 bytes) containing a single class with the **same FQN** as
the visible one:

```java
public final class FlagChecker {
    private static final byte[] T = {41,105,110,102,40,-89,...,-40,31};
    private static final byte[] M = {26,41,72,35,31,-21,...,-36,102};
    public static boolean check(String s) {
        byte[] b = s.getBytes();
        if (b.length != T.length) return false;
        int i = 90, acc = 0;
        for (int k=0;k<b.length;k++) {
            int x = ((T[k]^M[k]) ^ i) & 255;
            acc |= x ^ (b[k]&255);
            i = (i ^ (b[k]&255)) & 255;
        }
        return acc == 0;
    }
    public static String token() { return "ok"; }
    public static int fingerprint() { return 1990058842; }
}
```

Inverting that recurrence (`b[k] = (T[k]^M[k]^i)&255; i = (i^b[k])&255`,
`i0 = 90`) gives the decoy `isfcr{p4r3nt_f1rst_d3x_1s_s0_m34n}`. Because the
loader never receives the bytes (section 5), this class is never registered and
this flag is never accepted.

## 7. Which flag does the app *actually* accept?

| # | Location | Flag | Role |
|---|----------|------|------|
| 1 | visible `classes.dex` | `isfcr{sh4d0w_cl455l04d3r_tr1ckery}` | **accepted** |
| 2 | shadow dex (`theme.pack`) | `isfcr{p4r3nt_f1rst_d3x_1s_s0_m34n}` | decoy |

Decided by the missing `ByteBuffer.flip()` in `App.bind()`, which leaves the
in-memory dex loader empty so the intended parent-first shadowing never occurs.

## 8. Answer

```
isfcr{sh4d0w_cl455l04d3r_tr1ckery}
```

