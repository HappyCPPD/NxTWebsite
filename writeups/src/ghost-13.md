# GHOST-13

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{ghost13_dc8f84a256fa64108b6c75a151a1474d}`

---

A line controller survived a power failure; the maintenance gateway received "two diagnostic writes that should never have looked alike" - the giveaway for **ECDSA nonce reuse**. The solve chains four artifacts: `plc_program.bin` → active config, `plc_firmware.bin` → factory constants + pubkey, `plc_traffic.pcap` → two reused-nonce ECDSA signatures → signing scalar, `alarm_buzzer.wav` → DTMF keypad digits, finally unsealing `maintenance_update.ota`.

**Stage 1 - active configuration:** 8 config slots each paired with a commit journal; a slot is activated only if it has a valid matching journal (CRC + commit word valid on both). Two journals are deliberately invalid. Sequence numbers wrap (`65533..4`), requiring **16-bit serial-number arithmetic** rather than raw comparison to find the highest valid journal - landing on active slot 5.

**Stage 2 - firmware constants:** a section directory in the firmware image yields a 32-byte factory constant and a P-256 public key (`PUBK` section); a retired v1 recovery key section is unused.

**Stage 3 - signing scalar:** TCP-reassembled Modbus/TCP FC16 writes carry custom `G13C` fragments (validated by CRC16 + expected register address) that reassemble into padded `G13F` frames, decrypted with AES-256-CTR under a link key derived from the factory constant and committed ID/salt. Two of the three frames (`0x41`, `0x42`) **share the same ECDSA nonce `r`** - textbook nonce-reuse key recovery:

```
k = (z1 - z2) / (s1 - s2)  mod n
d = (s1*k - z1) / r        mod n
```

recovering the signing scalar `d`, verified via `d·G == Q`.

**Stage 4 - keypad digits:** a Goertzel DTMF decoder on the 8kHz WAV finds two 8-digit groups separated by a service-ready tone; adding the committed `keypad_trim` (mod 10) to the diagnostic wire-code digits gives the real keypad digits.

**Stage 5 - the sealed update:** apply a sparse binary delta to a factory image (verified against embedded CRC32s and a SHA-256 of the target), then derive an HKDF-SHA256 key from the recovered ECDSA scalar, committed ID/salt, image KDF constant, keypad digits, and hashes of the image/manifest/delta - decrypting an AES-256-GCM blob to:

```json
{"diagnostic":"power-restoration","flag":"isfcr{ghost13_dc8f84a256fa64108b6c75a151a1474d}"}
```

Key takeaways: serial-number (wraparound-aware) arithmetic is needed to pick the newest journal; ECDSA nonce reuse across two signatures leaks the private scalar instantly; erasure coding (XOR parity, used elsewhere in the fragment reassembly) lets dropped fragments be rebuilt; every hash/CRC checkpoint in the chain catches a wrong branch before it wastes time.
