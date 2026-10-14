# Phantom Mesh

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{ph4nt0m_m3sh_h4rm0n1cs_un14sk_th3_tc_l1nk_k3y}`

---

## The scenario

An office smart-lighting mesh (vendor "Lumeta", proprietary *Lumeta Mesh Protocol* /
LMP) rides directly on IEEE 802.15.4 MAC payloads. Someone has added a rogue node that
broadcasts a short diagnostics report once a day. We are given:

* `mesh.pcap` - a capture of the mesh (PAN `0x1A2B`, coordinator short addr `0x0000`).
* `traces/iq.npz` - 2500 raw I/Q records (4 Ms/s, 2440 MHz, `complex64`, shape (2500,2500))
  captured off the coordinator's antenna via a directional coupler, each triggered at
  `tx_start()` of a **KEY_CONFIRM** transmission.
* `traces/nonces.csv` - the exact 16-byte KEY_CONFIRM nonce that went on the air during
  each I/Q record.
* `docs/` - the LMP wire format and the operator's SDR lab notebook.

Nobody has the network key. We must recover the rogue report and read the flag.

## Protocol crypto (from `docs/LMP-protocol.md`)

Every protected PDU is AES-CCM\* (key 128, nonce 13, MIC 4, L=2):

```
nonce = src_eui64 (8, big-endian) || frame_counter (4, little-endian) || sec_ctl(1)
aad   = sec_ctl(1) || frame_counter (4, little-endian) || src_eui64 (8, little-endian)
```

`sec_ctl = 0x05`. Key hierarchy:

* A single **fleet-wide TC Link Key** (provisioned at the factory, never leaves the device)
  protects `TRANSPORT_KEY` (0x11) and produces the `KEY_CONFIRM` (0x12) check tag.
* A per-site **NWK key** is delivered inside the `TRANSPORT_KEY` ciphertext and protects
  `SECURE_REPORT` (0x21), which carries ZCL-like attribute reports.

So the whole thing hinges on the TC Link Key.

## The side channel

The SDR notebook is the hint:

* "reference design review flagged a stability concern with the PA bias feed, but the
  production board ships without the recommended decoupling cap" - the power amplifier's
  envelope is not stable.
* "The LMP crypto stack runs in software on the main core; we have not seen Lumeta use the
  SoC's hardware AES peripheral" - software AES ⇒ data-dependent current draw.

The software AES current draw modulates the PA bias, which AM-modulates the transmitted
carrier. Because the I/Q records are aligned to the KEY_CONFIRM `tx_start`, each record's
**envelope magnitude** `|iq|` is a power trace of the AES that computed that frame's tag -
with the AES *plaintext (the nonce) known for all 2500 records*. That is a textbook setup
for **Correlation Power Analysis (CPA)**.

### Reading the data

`iq[i, :]` is a constant complex carrier (random phase per record) plus additive white
Gaussian noise (≈3.7 % per component). There is no carrier frequency offset (measured
phase advance ≈ 0) and no modulation structure - the leakage lives in the *magnitude*
envelope, at low SNR. The per-record constant itself carries nothing useful; all the signal
is in `|iq|` across the 2500 records.

### CPA on the first AES round

Model for key byte *j* and guess *g*: `HW(Sbox(nonce_j XOR g))` (Hamming weight of the
first-round SubBytes output). Correlate that per-record model against every sample of the
2 500 magnitude traces; the correct key byte produces a clear peak.

```python
sig = np.abs(iq); X = sig - sig.mean(0); X /= X.std(0)      # (N_traces, L_samples)
corr = hw @ X / N                                            # (256, L)
```

The recovered key:

```
TC Link Key = 7cf8b0b78be9f36a225c1e70692e1e1c
```

Corroboration: the per-byte leak peaks are spaced ~48 samples apart and move monotonically
with the byte index (bytes processed sequentially) - exactly what a software AES power
trace looks like. More decisively, the key reproduces **all 8** on-air KEY_CONFIRM tags
(`tag = AES-128-ECB(TC, nonce)[:8]`), 8/8.

### The trap that cost most of the time

`hw @ X.T` is *silently wrong here* because the trace matrix is square (2500 traces × 2500
samples): both orientations produce the same shape, so the correlation is computed against
the transposed axis and returns pure-noise z-scores (~4) that look plausible. The fix is
`hw @ X` (no transpose). A **positive control** (inject `0.02·HW(Sbox(nonce_j⊕known_j))`
at a known sample) is essential to catch this class of bug: after fixing the orientation the
injected key jumps to z≈50; before the fix it is undetectable.

## Decrypting the chain

1. **`TRANSPORT_KEY`** (seq 39) - AES-CCM\* under the TC Link Key. Its 16-byte ciphertext
   decrypts (MIC valid) to the **NWK key**:

   ```
   NWK Key = ffa0be732cd8f56eae8caa21359baf06
   ```

2. **`SECURE_REPORT`** (0x21) PDUs - AES-CCM\* under the NWK key. Decrypting all 96 frames,
   every node except one reports ordinary cluster/attribute values. Frame **seq 80** comes
   from a node not in the mesh inventory - short addr `0x1040`, EUI `4000aa25004b1200`
   (every legitimate node's EUI is `001Xaa25004b1200`) - reporting cluster `0xfc01`,
   attribute `0x0042`, value length 52:

   ```
   isfcr{ph4nt0m_m3sh_h4rm0n1cs_un14sk_th3_tc_l1nk_k3y}
   ```

## Reproduce

```
$ cd Phantom-Mesh
$ python3 solve.py
TC Link Key : 7cf8b0b78be9f36a225c1e70692e1e1c
KEY_CONFIRM  : 8/8 verified
NWK Key     : ffa0be732cd8f56eae8caa21359baf06
FLAG        : isfcr{ph4nt0m_m3sh_h4rm0n1cs_un14sk_th3_tc_l1nk_k3y}
```

Dependencies: `numpy`, `cryptography` (uses `AESCCM(tag_length=4)`, which matches CCM\*
for MIC>0). Everything else is stdlib.

