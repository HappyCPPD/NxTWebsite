# PHANTOM-15

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{phantom15_6b4cf2a16a3ffc72c9420983dec02be1}`

---

An industrial pressure sensor was marked permanently offline; three 802.15.4 monitors (channels 15/20/25) recorded radio activity and a manufacturing lab held "qualification measurements." Goal: reconcile radio captures + lab measurements + service notes to recover the diagnostic record the gateway missed.

**Radio triage:** broadcast beacon/data frames every 79 ms carry a timing tick used to align the three monitors' clocks. Secured data frames come from two EUIs (key indices `0x2b`, `0x64`) and one unsecured sender whose unencrypted frames form a clean 20-frame counter (a "continuity" decoy, nothing hidden).

**CCM\* nonce/AAD:** the nonce is the *on-air* (little-endian) 64-bit source, not the human-readable EUI, concatenated with the frame counter and security level; AAD is the full 21-byte MAC header. Getting the on-wire byte order right (rather than the display order) is the key subtlety.

**Transport + Reed-Solomon:** decrypted payloads are `P15`-tagged RS(12,8) erasure shards over GF(2⁸) (poly `0x11d`), decoded with a systematic generator; the record format `DG15` carries EUI, epoch, fault code, samples, message IDs, a CRC32, and a BLAKE2s-128 - both independently validated with a synthetic round-trip self-test before trusting the real decode.

**Key recovery - the crux.** First-order CPA (`HW(Sbox(p⊕k))`) on the raw I/Q traces lands exactly at the Gaussian noise floor across every model, join, and preprocessing variant tried (model-free ANOVA, RandomForest, split-half stability - all chance-level). A positive-control injection proves the CPA code itself is correct, so the null is a genuine property of the raw data: **the traces are Gaussian noise plus a ~5-sample trigger spike that jitters uniformly over samples 49-64 and is input-independent** - a scope trigger, not AES activity.

**Resolution - jitter-aware alignment:** the AES leakage is tied to the *trigger*, not to absolute sample index - for input byte `i` it sits at a fixed offset `delta = 63 + 11·i` after each trace's own trigger. Aligning every trace to its own detected trigger peak before correlating recovers the leak cleanly (correlation jumps from the ~0.10 noise floor to ~0.20-0.24 for the true key byte, with peaks marching by 11 samples per byte).

```
key idx 0x2b (session 31): bb5136c65215e473f8973fdaf8d3845c
key idx 0x64 (session 32): cea97c91a3504ff1800e51e2aafb3c9b
CCM* validation: 40/41 secured frames decrypt with matching MIC
NOTE: gateway low16 dedupe collision: 4a31 prior, a17c4a31 new; RF valid; isfcr{phantom15_6b4cf2a16a3ffc72c9420983dec02be1}
```

The story closes cleanly: the gateway's replay filter flagged a false "duplicate application event" because the sensor's `full_msg_id`'s low 16 bits collided with an unrelated cached event - a low16 dedupe bug suppressed the real emergency diagnostic, and the recovered `DG15` note states exactly that.
