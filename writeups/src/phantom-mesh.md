# Phantom Mesh

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{ph4nt0m_m3sh_h4rm0n1cs_un14sk_th3_tc_l1nk_k3y}`

---

An office smart-lighting mesh (proprietary "Lumeta Mesh Protocol" over 802.15.4 MAC payloads) has a rogue node broadcasting a diagnostics report once a day. Given: `mesh.pcap`, `traces/iq.npz` (2500 raw I/Q records, 4 Ms/s, each triggered at a KEY_CONFIRM transmission), `traces/nonces.csv` (the exact nonce on-air for each I/Q record), and vendor docs.

**Protocol crypto:** every protected PDU is AES-CCM\* (key 128, nonce 13, MIC 4). A single fleet-wide **TC Link Key** protects `TRANSPORT_KEY` (which carries a per-site NWK key) and the `KEY_CONFIRM` check tag.

**The side channel:** the SDR lab notebook hints that the PA bias feed lacks a recommended decoupling cap, and the LMP crypto runs in software (no hardware AES peripheral) - software AES current draw modulates the PA bias, AM-modulating the transmitted carrier. Since the I/Q captures are aligned to KEY_CONFIRM `tx_start` with known plaintext (the nonce), this is textbook **Correlation Power Analysis**: each record's envelope magnitude `|iq|` is a power trace of the AES that computed that frame's tag.

**CPA on round 1:** model `HW(Sbox(nonce_j XOR g))`, correlated against every sample of the magnitude traces. The recovered TC Link Key is `7cf8b0b78be9f36a225c1e70692e1e1c`, corroborated by per-byte leak peaks spaced ~48 samples apart moving monotonically with byte index (sequential software AES byte processing), and by reproducing all 8 on-air KEY_CONFIRM tags.

**The trap:** `hw @ X.T` is silently wrong on a square trace matrix (2500×2500) because both orientations have the same shape - the correlation computes against the transposed axis and returns plausible-looking noise-floor z-scores (~4). The fix is `hw @ X` (no transpose); a positive control (inject a known-key correlation at a known sample) is essential to catch this - after the fix the injected key jumps to z≈50.

**Decrypting the chain:** `TRANSPORT_KEY` decrypts under the TC Link Key to reveal the NWK key (`ffa0be732cd8f56eae8caa21359baf06`). Decrypting all `SECURE_REPORT` frames under the NWK key, one frame comes from a node not in the mesh inventory (EUI pattern mismatch), reporting a vendor-specific cluster/attribute:

```
isfcr{ph4nt0m_m3sh_h4rm0n1cs_un14sk_th3_tc_l1nk_k3y}
```
