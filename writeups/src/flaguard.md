# FlaGuard

**Event:** CryoVault CTF 2026
**Category:** rev
**Flag:** `isfcr{sh4d0w_cl455l04d3r_tr1ckery}`

---

A tiny Android app pitched as "the strictest flag-format validator around." The prompt's wording ("which flag it **actually** accepts") signals two candidate flags, decided by true runtime behaviour.

**Candidate 1 - the visible checker:** `FlagChecker.check()` runs a deterministic affine recurrence `i = ((i*131) + byte + P[k%6]) & 0xFFFF` checked against a 34-entry constant table - every term except the input byte is known, so each byte inverts directly, giving `isfcr{sh4d0w_cl455l04d3r_tr1ckery}` (34 bytes, validates against the visible checker).

**The intended (but broken) shadow mechanism:** `App.bind()` decrypts a second dex (`theme.pack`, AES-256-CBC, key/IV derived from a 128-byte key-shard carved out of `palette.webp` plus the app's own classes.dex hash) and attempts to splice it into the ClassLoader chain via `dalvik.system.InMemoryDexClassLoader`, replacing the app ClassLoader's `parent` so parent-first lookup would find a *hidden* `FlagChecker` before the real one.

**The deciding bug:** `App.bind()` does `bb = ByteBuffer.allocateDirect(dex.length); bb.put(dex);` and hands `bb` straight to the `InMemoryDexClassLoader` constructor - **without ever calling `bb.flip()`**. After `put()`, `position == limit == capacity`, so `remaining() == 0`; the loader sees an empty slice and contributes no classes at all. `bind()` still "succeeds" (no exception), but parent-first lookup misses on the inert shadow loader and falls through to the app's own `classes.dex` - the **visible** checker is what actually runs.

Reproducing the shadow dex's decryption for completeness recovers a decoy class with the *same fully-qualified name*, whose own inverted recurrence yields `isfcr{p4r3nt_f1rst_d3x_1s_s0_m34n}` - narrating the trick the author wanted you to fall for. Because the buffer is never prepared for reading, this class is never registered and this flag is never accepted.

```
isfcr{sh4d0w_cl455l04d3r_tr1ckery}
```
