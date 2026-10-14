# Mirror Garden

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{m1rr0r_g4rden_bl00ms_@t_m1dn1ght_7f3a}`

---

> "Something is growing in the mirror garden, and only one leaf remembers."

## 1. Triage

`mirror-garden.apk` (925 KB) contains:

```
AndroidManifest.xml        package one.sr.garden, single activity MainActivity
classes.dex                1026 classes: MainActivity, R, and 1024 obfuscated leaves
lib/arm64-v8a/libgarden.so 9.8 KB native library
res/layout/activity_main.xml
```

`MainActivity` is minimal:

```java
public class MainActivity extends Activity {
    private native String bloom(byte[] bArr);
    static { System.loadLibrary("garden"); }
    protected void onCreate(Bundle b) { ...
        ((Button) findViewById(R.id.water)).setOnClickListener(v ->
            result.setText(MainActivity.this.bloom(editText.getText().toString().getBytes())));
    }
}
```

So the real logic lives in `libgarden.so`; it validates the text typed into the app.

## 2. The 1024 leaves

`one/sr/garden/leaf/` holds `L0000` … `L1023`. Each has exactly one method:

```java
public static byte[] verify(byte[] bArr) {
    if (bArr == null || bArr.length != 16) return null;
    long j5 = bArr[4] & 255; ...                 // 16 input bytes
    long j17 = (173 * j5) & 0xffffffffL;         // products of bytes
    long j19 = (j17 | j18) - (j17 & j18);        // == j17 ^ j18
    long j20 = ((j19 << 2) | (j19 >>> 30)) & 0xffffffffL;   // rotl32
    long j30 = ((((j25 ^ j29) + ((j25 & j29) * 2)) & 0xffffffffL) * 45) & 0xffffffffL; // (A+B)*45
    ...
    if ( <8 expressions> != <8 constants> ) return null;     // 8 x 32-bit equations
    byte[] bArr2 = { ... 48 bytes ... };
    byte[] bArr3 = new byte[48];
    for (int i=0;i<48;i++) bArr3[i] = (byte)(bArr2[i] ^ bArr[i & 15]);
    return bArr3;
}
```

Each leaf therefore defines a system of 8 equations over 16 byte-variables. The two
algebraic identities used by jadx's decompiler make this tractable:
`(a|b)-(a&b) == a^b` and `(x^y)+2(x&y) == x+y` (all mod 2^32).

### Solving all leaves

I wrote a tiny symbolic evaluator: every `long jN = ...` line is textually rewritten
(`4294967295L`→`M32`, `bArr[N] & 255`→`B(N)`, `>>>`→logical shift) and evaluated with
an operator-overloading `Sym` class wrapping z3 32-bit BitVectors. The final `if (E1 != C1
|| ...)` is split on `||` into equalities. Gravity: watch out for the two guard lines
`if (bArr == null || bArr.length != 16)` - skip them or the parser chokes.

Result: **all 1024 leaves are satisfiable**. For each leaf, `bArr2 XOR input[i&15]` is a
48-byte value. 1023 of them begin with `isfcr{<plant-name>_<hex>}` followed by 24 junk
bytes - i.e. decoys. Condition grep `^isfcr\{...}` matched every leaf **except one**:

```
leaf 357 -> b'\x85\xd3\xd1\xdf\xac\xd6\xab\xaaB\x93\x1f\x9a{&\xb76i\xde\xcf@\xa7\xe4$g\xc9\x96\xe91\xba\xacn\x8dl\xe5\xefC\xf2+\xcb\xd1O\xaf\xbf\xc36\x0bX\x9b'
```

Leaf 357 is the odd one out - "the only leaf that remembers". But its raw output isn't a
flag, so the native code must post-process it.

## 3. Reversing `bloom()`

`libgarden.so` `.text` is only 0x12b8 bytes. `Java_one_sr_garden_MainActivity_bloom` does:

1. `bl fcn.00002374` with `x0 = buffer`, then `w21 = word0(buffer) & 0x3ff` → **leaf index**.
2. Builds a format string and `snprintf(buf, 0x40, fmt, w21)`.
3. `FindClass(buf)`, `GetStaticMethodID(clazz,"verify","([B)[B")`, then
   `CallStaticObjectMethodA(env, clazz, mid, inputArray)` → the leaf's 48-byte result.
4. `GetArrayLength` must be 48, `GetByteArrayElements`, XOR with an internal 48-byte
   state, `ReleaseByteArrayElements`.
5. A chain of internal transform routines (`fcn.00002810`, `fcn.00002b0c`) - the
   "mirror" - over the XOR result.
6. `NewStringUTF(env, buf)` returns the displayed string.

### Step 3a - the index is a constant

I emulated `fcn.00002374` with Unicorn (ARM64). It builds a 16-word state from constant
tables at `.rodata` 0x600 / 0x72c / 0x5a0, runs 24 rounds using `fcn.000027e8`
(`((x^y)*0x9e3779b1 + z)` ror-based mixer), and writes 0x40 bytes to its output buffer.
It never reads the input arguments. Output word0 = `0x1ab67d65`, so:

```
index = 0x1ab67d65 & 0x3ff = 357   ->  class "one/sr/garden/leaf/L0357"
```

Emulating the string-builder region confirmed `fmt = "one/sr/garden/leaf/L%04d"`,
`name = "verify"`, `sig = "([B)[B"`.

### Step 3b - emulate the whole thing instead of hand-reversing the mirror VM

Rather than reimplement `fcn.00002810`/`fcn.00002b0c` by hand, I emulated the **entire
`bloom()`** in Unicorn with a **stub JNI environment**:

- JNIEnv is a pointer-to-pointer-to-table; I mapped a table of 256 stub `ret`
  instructions and implemented, by observed offset:
  `0x30` FindClass, `0xb8` DeleteLocalRef, `0x388` GetStaticMethodID,
  `0x390` CallStaticObjectMethodA, `0x558` GetArrayLength, `0x580` NewByteArray,
  `0x5c0` GetByteArrayElements, `0x600` ReleaseByteArrayElements, `0x538` NewStringUTF.
- `CallStaticObjectMethodA` is honoured by computing leaf 357's `verify` for the passed
  array (I precomputed the 48-byte result and the 16-byte preimage).
- The two libc imports are stubbed: `snprintf` (PLT 0x2dd0, handles `%04d`) and `memcpy`
  (PLT 0x2de0).

Run with `x0=ENV`, `x2 = 16-byte leaf-357 solution`, executed `0x1b28 → 0x2288`:

```
FINAL: isfcr{m1rr0r_g4rden_bl00ms_@t_m1dn1ght_7f3a}
```

### Step 3c - negative control

Same emulation with `x2 = 16 zero bytes`, or `x2 = "AAAAAAAAAAAAAAAA"`, both stop at the
`GetStatic...`/length checks and return the error string `the mirror cracks.`. Only the
true preimage of leaf 357 passes. This proves the flag is produced by the leaf and not by
a branch artifact.

## 4. Answer

Leaf 357's unique 16-byte preimage is
`4c 2e 5d 5e 6f 6f 71 28 4c 6c 55 5e 28 61 5d 23` (`L.]^ooq(LlU^(a]#`). The native
mirror transform turns `bArr2 XOR input[i&15]` into the flag:

```
isfcr{m1rr0r_g4rden_bl00ms_@t_m1dn1ght_7f3a}
```

## 5. Files

```
solve/solve_leaves.py   z3 parser + solver for one leaf (Sym wrapper)
solve/run_all.py        parallel solve of all 1024 leaves
solve/emu_bloom.py      Unicorn + stub-JNI emulation of Java_..._bloom -> flag
work/jadxout/           jadx decompilation of classes.dex
work/lib/arm64-v8a/libgarden.so
work/bloom.asm          r2 disassembly of the native lib
```

## 6. Reusable lessons

- A tiny APK whose only logic is a `native` method: the JNI body is the challenge. Read
  the JNI function-pointer offsets (`ldr x8,[x8,off]; blr x8`) to identify calls instead
  of guessing the (large) JNI index table.
- 1024 generated Java "leaf" classes are just constraint systems; parse them with a
  symbolic operator-overloading evaluator and solve each with z3 (all are sat).
- `(a|b)-(a&b)` is `a^b`; `(x^y)+2(x&y)` is `x+y` - jadx emits these instead of `^`/`+`.
- **Emulate** obfuscated native transforms (Unicorn) with stub JNI/libc rather than
  reversing them; it is faster and exact. Always run a negative control (wrong input) to
  prove the value comes from the intended path.
- Watch for the length-guard `if (bArr == null || bArr.length != 16)` when auto-parsing
  generated Java; it is not the real condition.

