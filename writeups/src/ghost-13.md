# GHOST-13

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{ghost13_dc8f84a256fa64108b6c75a151a1474d}`

---

## Overview

The GHOST-13 line controller survived a brief power failure and, on restart, its
maintenance gateway received *"two diagnostic writes that should never have looked
alike."* We are given a full plant snapshot and must reconstruct the active
configuration + reboot sequence, then recover the diagnostic secret sealed in the
maintenance update.

The solve is a chain where every artifact feeds the next:

```
plc_program.bin ──┐ (committed_ID, committed_salt, keypad_trim)
plc_firmware.bin ─┤ (factory constant, P-256 pubkey, target KDF constant)
plc_traffic.pcap ─┤ (two ECDSA sigs w/ reused nonce → signing scalar)
alarm_buzzer.wav ─┤ (DTMF wire code → keypad digits)
                  └─► maintenance_update.ota  →  HKDF + AES-256-GCM  →  FLAG
```

The hint *"two diagnostic writes that should never have looked alike"* is the giveaway
for the core vulnerability: **ECDSA nonce reuse**.

---

## Stage 1 - Active configuration (`plc_program.bin`, G13L)

The IEC program image is a header + 8 × 128-byte `G13P` config slots + 8 × 64-byte
`G13J` commit journals.

Per the field-service excerpt, a slot holds `sequence:u16, epoch:u16` @4, `ID[16]` @8,
`salt[16]` @24, `keypad_trim[8]` @84, `CRC32(bytes 0..119)` @120, and a commit word @124:
`CRC ^ 0x13c0ffee ^ (sequence<<16 | epoch)`.

A journal binds `journal_sequence, slot_index, slot_sequence, epoch, slot_CRC` @4..15,
with `CRC32(bytes 0..55)` @56 and commit @60: `CRC ^ 0xa91f0eed ^ (jseq<<16 | jseq)`.

**Finding the active slot:**
- A slot is *activated* only if it has a **valid matching journal** (CRC + commit valid on
  both, and the journal's bound fields equal the slot's).
- Journals 6 (bad CRC) and 7 (bad commit) are invalid → slots 6 & 7 not activated.
- The sequences wrap (`65533, 65534, 65535, 0, 1, 2, 3, 4`), so **16-bit serial-number
  arithmetic** gives the ordering. The highest valid activated journal is `jseq = 2`.

→ **Active slot = index 5:**

| field | value |
|---|---|
| `committed_ID` | `75f83e16b7969d3985c35154de9fcb10` |
| `committed_salt` | `ac0c0f86d58bdde419cd50a98450c012` |
| `keypad_trim` | `[9, 9, 3, 2, 9, 9, 9, 4]` |

The reboot sequence in `uart_log.txt` corroborates this: watchdog exception 0x06 → CPU
brownout → journal frontier restored after 16-bit rollover.

---

## Stage 2 - Firmware constants (`plc_firmware.bin`, G13W)

64-byte header + a directory of 24-byte section entries
(`tag[4], offset, length, crc32, aux, flags`, little-endian). Valid sections:

- **VMBC** - signing VM program (unused for the flag path)
- **KDFD** - `G13K` + a **32-byte factory constant**, then label strings
- **PUBK** - `P256` + big-endian `Qx`, `Qy`
- **RECV** - retired v1 recovery key (unused)

```
factory_constant = bc2163b48216acbd4b0969e34996579006014c0e5f9088d33ef104dc6bbaab74
Qx = f297360fc8d87390336e36476e024ba73a90aa4119ee085e69a2d8e750f10ad9
Qy = 0c83ccda933401ceef4543b31a57bfc0b26154d2a272d2cad401ca81f4675e48
```

---

## Stage 3 - Recover the signing scalar (`plc_traffic.pcap`)

**Reassembly path:** TCP reassemble → Modbus/TCP **FC16** (write multiple registers) →
`G13C` fragments → padded `G13F` frame.

Each `G13C` fragment:
`magic[4], stream_id:u16, index:u8, data_count:u8, frame_len:u16, parity:u8, reserved:u8,
payload[40], CRC16/CCITT-FALSE:u16`. Register address = `0x4200 + 20*index` (data) or
`0x4300` (parity index 3).

- Validated every fragment by CRC16 **and** expected register address (drops the damaged
  fragment and retransmissions).
- Data slices 0..2 are 40-byte pieces; index 3 is their bytewise XOR parity. Streams 0x41
  and 0x42 were each missing one slice → **restored via XOR parity**.
- Three `G13F` frames recovered (streams 0x41, 0x42, 0x43).

**Decrypt each frame** (AES-256-CTR, IV = `G13F_header[10:26]`):

```
link_key = SHA256("G13/link/v2" || factory_constant || committed_ID || committed_salt)
body     = state[24] || signature_r[32] || signature_s[32]
```

**Signed message / hash** per frame:

```
msg = "G13/sign/v2" || G13F_header[26] || state[24] || committed_ID || committed_salt[0:8]
z   = SHA256(msg)
```

**Nonce reuse:** frames **0x41 and 0x42 share the same `r`**. With one reused nonce `k`:

```
k = (z1 - z2) / (s1 - s2)         mod n
d = (s1*k - z1) / r               mod n
```

→ `d = 2f1945b86a823a5bffb808c0f5edc9bd981fb15481696d7c29bde45fb8e1a4cb`

Verified: `d·G == (Qx, Qy)` on P-256. ✓

---

## Stage 4 - Keypad digits (`alarm_buzzer.wav`)

8 kHz mono PCM. A Goertzel DTMF decoder finds two 8-key groups separated by a 440 Hz
service-ready tone:

- Group 1 (power-on self-check): `7 0 3 7 2 7 2 0`
- Group 2 (**diagnostic wire code**): `6 4 6 5 8 0 0 3`

Add each `committed keypad_trim` byte mod 10 to the corresponding wire digit:

```
wire : 6 4 6 5 8 0 0 3
trim : 9 9 3 2 9 9 9 4
sum%10:5 3 9 7 7 9 9 7   →  keypad_digits = "53977997"
```

---

## Stage 5 - Open the sealed update (`maintenance_update.ota`, G13U v4)

Layout: 64-byte header, JSON manifest (163 B), `G13X` v2 sparse delta (388 B), then
AES-256-GCM ciphertext + 16-byte tag (111 B total). Header CRC32 verified.

**Build the target image:** apply the `G13X` sparse delta (6 hunks) to a copy of the
factory image. Verified against the delta's `old_crc32/target_crc32`, the header's
`SHA256(target)[0:16]`, and the delta trailing CRC32. ✓
(The delta also rewrites KDFD, so the target's KDF constant differs from the factory's.)

**Derive the GCM key** with HKDF-SHA256:

```
IKM  = recovered_scalar_be32 || committed_ID || committed_salt
salt = SHA256(target_image_KDF_constant || committed_salt)
info = "G13/diagnostic/v4" || committed_ID || firmware_version_le16(=0x0003)
       || keypad_digits_ascii || SHA256(full_target_image)
       || SHA256(raw_manifest) || SHA256(raw_delta)

nonce = keypad_digits_ascii (8) || header[12:16] (4-byte suffix)
AAD   = header[0:60] || raw_manifest || raw_delta
```

Decrypt + verify → plaintext = `G13D` + zlib-compressed JSON:

```json
{"diagnostic":"power-restoration","flag":"isfcr{ghost13_dc8f84a256fa64108b6c75a151a1474d}"}
```

---

## Flag

```
isfcr{ghost13_dc8f84a256fa64108b6c75a151a1474d}
```

## Key takeaways
- **Serial-number arithmetic** is needed to pick the newest wrapped sequence, not raw `>`.
- **ECDSA nonce reuse** (same `r`) across two signatures leaks the private scalar instantly.
- Erasure coding (XOR parity) lets you rebuild a dropped fragment.
- Every hash/CRC in the chain is a checkpoint - validating them early catches the damaged
  fragment, the un-activated slots, and a wrong target image before they waste your time.

