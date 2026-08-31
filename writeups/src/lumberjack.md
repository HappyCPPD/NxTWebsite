# Lumberjack

**Event:** Kaspersky CTF 2026
**Category:** AI / ML
**Points:** 245 (89 on the scoreboard at solve time)
**Solves:** 143
**Flag:** `kaspersky{3d87a80c-9ab7-4c35-aeb4-f64bbae9bb44}`

---

## Challenge

A web service (`https://<instance-id>.kit.sasc.tf`) lets you `POST /upload` an
ONNX model containing a `TreeEnsembleClassifier`. The service compiles the
model to a native x86-64 binary and runs it. Visiting the returned URL executes
the binary and returns its stdout:

```
Predicted Class: X (probability: Y.YY)
```

The flag lives in the `FLAG` environment variable inside the sandbox that
runs the compiled binary.

## Root cause

The ONNX-to-C compiler backend translates each tree node's feature lookup
directly into a pointer-offset read:

```c
float val = features[node->feature_idx];
```

`feature_idx` comes straight from the untrusted `nodes_featureids` attribute
in the uploaded ONNX model and is never bounds-checked. Compiled, the access
becomes:

::: annotate
```asm title="tree_eval (compiled)"
mov    -0x8(%rbp), %rax
sub    $0x40, %rax
movss  (%rax), %xmm1
```
1. Load the `features` pointer from the stack frame.
2. Subtract 64 bytes: with `feature_idx = -16` this is `features + feature_idx * 4`, and nothing here checks the result stays in bounds.
3. Dereference straight off the end of the array.
:::

i.e. the effective address is `features + feature_idx * sizeof(float)`.
Supplying a **negative** `feature_idx` walks the read backwards off the start
of the `features` array and directly into other stack contents of `main()`.
Empirically, `feature_idx = -16` through `-5` (offsets `-64` to `-20` bytes
relative to `features`) land exactly on the bytes of the `FLAG` string that
`getenv("FLAG")` returns, four bytes (one `float`) at a time.

::: insight
This is a classic **out-of-bounds array read via attacker-controlled index**,
made into a clean oracle because the ONNX `TreeEnsembleClassifier` lets you
turn "is `features[idx] > threshold`?" into an observable output
(`probability > 0` vs `probability == 0`).
:::

## Building the oracle

::: steps
### Train a probe model
Train a trivial `sklearn.ensemble.RandomForestClassifier` with
`n_estimators=2, max_depth=1` (fixed `random_state=99` for reproducibility)
and export it with `skl2onnx` - this gives a minimal, valid
`TreeEnsembleClassifier` graph to mutate.

### Patch the ONNX attributes
For every internal (non-leaf) node, patch the ONNX attributes directly on
the loaded protobuf:
- `nodes_featureids` → the target OOB index (e.g. `-16`)
- `nodes_values` → the probe threshold
- `class_ids` → `[0, 1, 0, 1]`
- `class_weights` → `[0.0, 1.0, 0.0, 1.0]`

so that the reported `probability` is the fraction of the two trees whose
split evaluated `feature[idx] > threshold`.

### Query and parse
Upload the patched model, fetch the result page, and parse
`probability: ([\d.]+)`. `probability > 0` means `feature[idx] > threshold`.
:::

This gives a single boolean oracle per HTTP round trip: *is the leaked
float greater than a threshold I choose?*

## Recovering each 4-byte word

With a `>` oracle over IEEE-754 floats, binary search recovers the exact bit
pattern of `feature[idx]`, which - for the flag bytes - is just
`struct.unpack('<f', flag[i:i+4])`.

::: tabs
### Buggy: positive-only two-phase search
Search only positive magnitudes using a two-phase
scheme - binary search the exponent over powers of two (`2^-150 .. 2^130`),
then binary search the mantissa within the located exponent band. This works
perfectly as long as the target float is positive, which every in-bounds
flag-character word is (ASCII bytes have their sign bit clear when read as
the MSB of a little-endian float). It silently produces **garbage** the
moment the 4-byte window straddles the end of the flag string: the byte right
after the `NUL` terminator is uncontrolled adjacent stack/env data, and if its
high bit happens to be set, the reinterpreted float is *negative* - a value
the positive-only search can never bracket. Every query returns "false", and
the search collapses toward whatever tiny value was left at the search
boundary - plausible-looking but wrong bytes, no visible error.

This is exactly what happened at the last leaked word here: it decoded to
non-ASCII noise, and guessing "the flag must end in `}` right after this"
was **wrong** - the real bytes still had two more `};`-relevant characters
sitting right at that boundary.

### Fixed: full-range signed search
Binary search directly over the 32-bit
pattern using an order-preserving transform of IEEE-754 bits instead of
treating exponent/mantissa separately:

```python title="leak_robust.py"
def key_to_bits(key):
    # maps a uint32 "key" back to a float32 bit pattern such that
    # key is monotonic in the float's numeric value (handles sign correctly)
    if key & 0x80000000:
        return key - 0x80000000        # positive half: keys >= 0x80000000
    else:
        return (~key) & 0xFFFFFFFF     # negative half: keys <  0x80000000
```

Binary-searching `key` over the full `[0, 0xFFFFFFFF]` range and mapping each
midpoint back to a float threshold via `key_to_bits` handles positive *and*
negative floats uniformly (NaN thresholds are skipped/nudged since NaN
comparisons are never true). 32 iterations fully determine the bit pattern.
:::

::: spoiler Show the full exploit flow
1. Leak `feature_idx = -16 .. -6` (11 words = 44 bytes) with the simple
   positive-only searcher - safe, since all of these land squarely inside the
   flag string (`kaspersky{...}`, all printable ASCII, sign bit always 0).
2. Switch to the **full signed search** for the tail end (`feature_idx = -5`)
   to correctly read across the string's `NUL` terminator boundary without
   silently corrupting the last recovered characters.
3. Confirm the string terminates by leaking one word past that
   (`feature_idx = -4`) and observing non-ASCII/garbage - proof nothing more
   of the flag remains.
4. Concatenate all recovered bytes in order and decode as ASCII.
:::

## Flag

```
kaspersky{3d87a80c-9ab7-4c35-aeb4-f64bbae9bb44}
```

(Standard 36-character UUID inside `kaspersky{}`, 8-4-4-4-12 hex groups.)

## Lesson learned / pitfall to flag for next time

::: pitfall
Never assume a leak oracle only needs to cover the sign you've seen so far.
The first 44 bytes all being positive floats (printable ASCII) provided no
evidence the *next* word would be too - the moment the read window crosses a
string terminator, the trailing bytes are attacker-uncontrolled memory and
can carry a set sign bit. A byte-leak binary search over raw memory should
**always** cover the full signed range (or explicitly detect and fall back)
rather than assume a value domain based on what earlier reads happened to
return.
:::

## Files

- `simple.py`, original solver (positive-only two-phase search); good for
  bytes known to be inside the printable string, fast (10 + 32 iterations).
- `leak_robust.py`, full signed-range single-phase binary search using the
  `key_to_bits` order-preserving transform; use this for any word that might
  straddle the end of the leaked buffer.
- `SOLUTION.md`, notes from an earlier instance solve (its reported flag
  likely suffered from the same positive-only truncation bug described
  above - treat its exact flag value as unverified).
