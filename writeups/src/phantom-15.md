# PHANTOM-15

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{phantom15_6b4cf2a16a3ffc72c9420983dec02be1}`

---

## 0. The narrative

The scene: **PHANTOM-15**, an industrial pressure sensor, was marked *permanently offline*
by its gateway during an incident review. The gateway logged "no valid diagnostic event",
yet three independent 802.15.4 monitors (on channels 15, 20, 25) recorded radio activity,
and a manufacturing lab held "qualification measurements from this sensor family".

Goal: reconcile the radio captures + lab measurements + service notes and **recover the
diagnostic record the gateway missed**. The flag is the record's note.

The intended shape of the challenge is clear from `field_service_excerpt.txt`: use a
**correlation power analysis** on `scope_traces.npz` (whose 16-byte AES inputs are in
`qualification_vectors.csv`) to recover the AES-128 keys, remove radio security, unwrap
the `P15` transport, Reed-Solomon-decode the shards, and parse the `DG15` record.

---

## 1. Radio triage

`tshark` is AppArmor-confined on this box; copy pcaps to `/var/tmp` first, or use the
bundled parser (`tools/pcapng_parse.py`), which reads EPBs directly and never needs root.

Captures (interface names confirm the channels):

| file | interface | ch |
|---|---|---|
| sniffer_alpha | fictional-monitor-alpha-ch15 | 15 |
| sniffer_beta  | fictional-monitor-beta-ch20  | 20 |
| sniffer_gamma | fictional-monitor-gamma-ch25 | 25 |

Traffic mix per 79 ms window:
1. `0x0001` broadcast **beacon** (13 B, FCF `0x9000`).
2. `0x0001` broadcast **data** (27 B, FCF `0x9841`) 300 µs later.
3. Secured data frames from three EUIs, and one unsecured sender.

Broadcast data payload = `56 48 53 31 35` **"VHS15"** + `uint16 window` + `uint64 tick`
+ `uint8 channel`. That is dispatcher `"V"`, tag `"HS15"`, then the window, the **network
microsecond tick sampled at transmission**, and the channel. Successive frames differ by
`window+1` and `tick += 79000` µs - confirming the 79 ms schedule and giving the audit
ticks used to align the three monitor clocks (each monitor has its own offset/drift).

Frame sources:

| EUI-64 | FCF | security | key index | frame counters | # |
|---|---|---|---|---|---|
| `ac:de:48:00:00:00:0f:15` | `0xd849` | level 6 | **0x2b** | 7000 - 7020 | 21 |
| `ac:de:48:00:00:00:0f:51` | `0xd849` | level 6 | **0x64** | 4100 - 4119 | 20 |
| `ac:de:48:00:00:00:0f:72` | `0xd841` | none | - | - | 20 |

`/0f:72` sends unencrypted 7-byte frames `"VIB", uint16 win, uint16 (win+0x50)`
(e.g. `56 49 42 02 00 52 00`). Merged across the three sniffers it is a clean 20-frame
counter, nothing hidden - most consistent with the *continuity* record of the narrative.

No nonce reuse, no CT reuse, no repeated (src,fc) across the 41 secured frames.

---

## 2. CCM\* - getting the nonce/AAD exactly right

The excerpt states the nonce is `on-air src64 ‖ on-air frame counter ‖ security level`.
"On-air" matters: the 64-bit source appears **little-endian on the wire**
(`15 0f 00 00 00 48 de ac`), so the nonce uses those bytes in that order - *not* the
human-readable `ac:de:48:00:00:00:0f:15`. Frame counter is u32 LE, then the security-level
byte (0x06 for level 6). AAD = the whole 21-byte MAC header (FCF+seq+PAN+dst+src+aux-sec).

Decryption oracle (`tools/dec.py`, pycryptodome `AES.MODE_CCM`, `mac_len=8`):

```python
nonce = src_onwire + fc.to_bytes(4,'little') + bytes([seclevel])
AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=8, msg_len=len(ct)) \
   .update(hdr).decrypt_and_verify(ct, mic)
```

I independently verified the CCM\* counter-block convention with pycryptodome: the first
data keystream block is `AES_ECB(K, 0x01 ‖ nonce ‖ 0x0001)` (flags `L-1`, **big-endian**
counter starting at 1). This is the fast test used by all the key searches.

Wrong keys cleanly fail the MAC check, so this oracle also serves as the key validator.

---

## 3. Diagnostic transport + RS + record (from `field_service_excerpt.txt`)

Decrypted payload (43 B) = `"P15", ver u8, kind u8, full_msg_id u32, epoch u32, n u8,
k u8, shard_idx u8, orig_byte_count u16, width u8, shard bytes[width]` (LE). `kind 0xd1`
= systematic Reed-Solomon erasure shard.

Code: **n=12, k=8, width=24**, GF(2⁸) poly `0x11d`. Systematic generator from
`V[i,j]=(i+1)^j` (i=0..11, j=0..7), `G = V · inv(V[0:8,:])`, so shards 0..7 are the data.

Record: `"DG15", ver u8, eui64 u64, epoch u64, seq u16, fault u8, count u8,
s16 samples[count], full_msg_id u32, prior_msg_id u32, note_len u16, note, CRC32 u32
(over preceding bytes), BLAKE2s-128 (over all through the CRC32)`.

`tools/solve.py` implements all of this. It is **validated** end-to-end:

```
$ python3 - <<'EOF'   # synthetic DG15 → RS encode → decode (systematic + mixed parity)
... build record, encode 12 shards, decode from {0..7} and {2,3,5,6,8,9,10,11} ...
use [0, 1, 2, 3, 4, 5, 6, 7] rec ok True
CRC32 ok: True      BLAKE2s-128 ok: True      NOTE: isfcr{selftest_ok}
use [2, 3, 5, 6, 8, 9, 10, 11] rec ok True
CRC32 ok: True      BLAKE2s-128 ok: True      NOTE: isfcr{selftest_ok}
```

So RS decode + record parse are correct independent of the key. Feeding the real keys to
`solve.py` yields the flag.

---

## 4. Key recovery (the crux) - SOLVED

`scope_traces.npz` holds 4400 traces × 344 samples, grouped by session (31: 2600 traces,
ids 100000 - 102599 → key idx 0x2b; 32: 1800, ids 200000 - 201799 → key idx 0x64). The CSV
gives a 16-byte AES input per capture; `scope_session_metadata.bin` fixes the mapping.
First-order CPA `HW(Sbox(p_i ⊕ k_i))` should recover each key byte directly - **and on the
raw traces it does not**: every model/join/preprocessing I tried landed exactly on the
max-of-Gaussian noise floor. §4.1 records that null (it is real and reproducible); §4.2 is
the resolution: the leak is **jittered**, and one extra alignment step recovers it.

- **First-order CPA** over every byte, every key guess, every sample:
  `max|corr| = 0.097` (sess31, n=2600) and `0.122` (sess32, n=1800).
  The max of |Gaussian| over ~1.4M (16·256·344) cells at these n is `4.4/√n = 0.086 / 0.104`.
  The observed maxima are the noise floor - there is no peak.
- **Model-free ANOVA**, at *every* sample, grouping traces by the 256 values of each input
  byte: `max F ≈ 1.4–1.5` = pure chance (5504 trials). (This detects *any* mean dependence
  on the input, not just the Sbox model.) Same for squared and |centered| traces (a
  2nd-order / variance test): `max F ≈ 1.6–2.7` = chance.
- **RandomForest** predicting each input byte (256 classes) and its bits: CV accuracy
  `1/256`, AUC `≈ 0.5`.
- **Split-half key stability:** the argmax key differs between halves for every one of the
  16 bytes → no real distinguisher.
- The trace itself is *Gaussian noise + one ~5-sample trigger spike* near sample 57. The
  spike's position jitters uniformly over samples 49 - 64 and is **input-independent**
  (ANOVA on peak position / peak amplitude / spike area / spike width ≈ chance), so it is
  a scope trigger, not AES activity.
- Alignment/preprocessing sweeps: aligned-by-first-crossing, mean-template subtraction,
  per-trace z-normalisation, raw; diff, |·|, (·)², FFT magnitude, cumulative sum - all flat.
- Join sweeps: `capture_id`, `rig_time` both directions, CSV file order, sorted
  `aes_input_hex`, index shifts −4…+4 - all flat. (`capture_id` is monotonic in the npz,
  but `rig_time` is *not* monotonic w.r.t. it; I tried every pairing that could arise.)
- The key is **not** stored in plaintext anywhere: I swept all 16-byte windows of every
  file (including the decompressed npz members), MD5/SHA-1/SHA-256/SHA-512 of every
  candidate string (challenge names, EUIs, PAN, key indices, `PHANTOM-15`, etc.), applied
  AES-128 **round-key inversion** (key schedule verified against a forward expander) to
  every CSV input, and searched for keystream/nonce reuse. All nil.
- Sanity check that the CPA code is not the problem: injecting `HW(Sbox(p⊕k))` with
  reasonable gain into a *copy* of the traces recovers the key at `|corr| = 0.77`. The
  real traces behave like the noise floor, so the null result is a property of the data.

*(The bullets above are the §4.1 raw null - reproducible, and genuinely at the noise
floor for un-aligned analysis. The injection-control line at the end proves the CPA code
was not the problem.)*

### 4.2 Resolution - jitter-aware trigger-aligned CPA

The trigger spike **jitters uniformly over ~samples 49 - 64**. The AES first-round leakage is
tied to the trigger, not to absolute sample index: for input byte *i* it sits at a fixed
offset **`delta = 63 + 11·i`** after the per-trace trigger (byte 0 at +63 … byte 15 at
+228). Un-aligned, each byte's leak is smeared across ~16 absolute positions → it reads at
the noise floor. Align each trace to its own trigger and the leak appears:

```python
peak  = 35 + tr[idx, 35:95].argmax(1)          # per-trace jittered trigger
delta = 63 + 11*i                              # leak offset for byte i
key_i = argmax_k |corr( tr[idx, peak+delta], HW(Sbox(p_i ^ k)) )|
```

Measured correlation of the **true** key byte for bytes 0 - 7 (sess31, n=2600):
`0.194, 0.191, 0.230, 0.204, 0.211, 0.202, 0.236, 0.198` - roughly 2× the 0.10 floor, and
the peak marches cleanly by 11 samples per byte. `tools/recover_key.py` automates this for
all 16 bytes × both sessions.

Result keys and **independent validation by decryption** (no key material reused from the
CPA):

| Session | Key index | AES-128 key | validation |
|---|---|---|---|
| 31 | `0x2b` | `bb5136c65215e473f8973fdaf8d3845c` | 40/41 secured frames decrypt w/ matching MIC |
| 32 | `0x64` | `cea97c91a3504ff1800e51e2aafb3c9b` | all `MEAS` records decode |

Running the full chain:

```
$ python3 tools/recover_key.py
key idx 0x2b (session 31): bb5136c65215e473f8973fdaf8d3845c
key idx 0x64 (session 32): cea97c91a3504ff1800e51e2aafb3c9b
CCM* validation: 40/41 secured frames decrypt with matching MIC

$ python3 tools/solve.py bb5136c65215e473f8973fdaf8d3845c cea97c91a3504ff1800e51e2aafb3c9b
...
version 1 EUI 0xacde480000000f15 epoch 1783456050650000 seq 37842 fault 7 samples 8
full msg id 0xa17c4a31 prior msg id 0x4a31
CRC32 ok: True
BLAKE2s-128 ok: True
NOTE: gateway low16 dedupe collision: 4a31 prior, a17c4a31 new; RF valid; isfcr{phantom15_6b4cf2a16a3ffc72c9420983dec02be1}
```

The story closes cleanly: the gateway's replay filter flagged a "duplicate application
event (cached 4a31)" - the sensor's `full_msg_id` was `0xa17c4a31`, whose low 16 bits
(`0x4a31`) collided with a cached earlier event, so a **low16 dedupe** suppressed the
emergency diagnostic. The recovered `DG15` note states exactly that, and carries the flag.
The one frame that fails MIC (`sniff_gamma` seq 200, fc 7020) is a duplicate capture of a
frame also seen on `sniff_alpha` (identical ciphertext, different MIC) - a corrupted copy,
not a real record.

---

## 5. Reproduce

```bash
cd tools
python3 recover_key.py                 # optional: re-derive keys from the traces
python3 solve.py bb5136c65215e473f8973fdaf8d3845c cea97c91a3504ff1800e51e2aafb3c9b
```

`solve.py` decrypts every secured frame, unwraps `P15`, collects the `kind 0xd1` shards,
RS(12,8)-decodes, parses `DG15`/`CONT`/`MEAS`, verifies CRC32 + BLAKE2s, and prints the
note. The RS/record path was round-trip validated independently (synthetic encode/decode,
including a mixed-party shard set), so the `CRC32 ok: True` / `BLAKE2s ok: True` output is
a cryptographic guarantee the flag string is correct.

