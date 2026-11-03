# The Quiet Divide

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{c8c46fdbd6e5e4eacabfba53a156ff9ab10567f2}`

---

**Category:** Network · `the-quiet-divide.zip` → `the-quiet-divide.pcap`
(110 248 pkts / 152 MB / ~98.8 s; pcap sha256 `20745719…`)

## Chain
1. **Triage** - `http` + `quic` + a little `dns`. The real payload is an
   "archive vault" HTTP API plus **two QUIC v1 sessions** (udp/4433, udp/4434).
2. **Keylogs from escrow shares** - `POST /v3/escrow` bodies carry two diagnostic
   shares (slot A / slot B, 760 B each). `shareA XOR shareB == the escrowed TLS
   keylog` (sha256 matches `keylog_sha256`) → two keylog files.
3. **Decrypt the QUIC sessions** with `tshark -o tls.keylog_file:…`. Payloads are
   `mb-quic-observation/3` objects (signed by `ARCH-14` resp. `REC-14`).
4. **Reference implementation** - `GET /v10/sdk` returns `text/x-python`: the
   interop lib (`evidence_components`, `archive_key`, `decrypt_archive`,
   `unmask_fragment`, `transaction_material_commit`, `final_key`, `seal_aad`,
   `decrypt_seal`).
5. **Reassemble the codec** - ranged `GET`s rebuild the `pulse-codec_7.7.0` ELF
   (sha matches `/v2/manifest`). A `PLS2` frame = the udp/9002 payload from
   `ARCH-14`; `decode_pls2()` → `seq 10450910 / queue 23 / load 71`.
6. **Archive key** -

   ```
   evidence = sha256(canon(custody_records))
            || hmac(chain, "MB10/FULL/ELF||fw")
            || sig(attestation) || sig(quic_observation)
            || sha256("MB10/CODEC/STATE" || canon(state) || frame)
   custody_records = /v8/audit FULL events (event_sha256 + signatures)
   archive_key = HKDF(evidence, salt=archive_salt_hex, b"MIRRORBREAK/10/RECORD-VAULT")
   ```
   decrypts all three `AVLT10` candidates to SQLite (`mb-corpus/10`, AAD commit =
   terminal event).
7. **Pick the winner** - `transfer.release_checkpoint == witnessed
   checkpoint_sha256` **and** `case_commit == terminal_event_sha256`;
   `material = concat(unmask_fragment(codec, tx_id, ord, payload))`;
   `transaction_material_commit(material,…) == receipts.fragment_commit`. All
   three archives had a structurally-valid candidate; only one material opens the
   independent witness (AES-256-GCM committee seal):

   ```
   archive 5a2c8adef3c0846a2d0fb62d00844c64 , tx 6dd9ec588c9914ca95df44b2
   ```
8. **Final key** -

   ```
   final_key = HKDF(material || evidence || W0-checkpoint-signature,
                    salt=salt_hex, b"MIRRORBREAK/10/PRODUCTION-CASE")
   decrypt_seal(b64_ciphertext, final_key, nonce_hex, body) -> hiCTF{…}
   ```

## Repro
```bash
python3 solve_quiet_divide.py        # needs tshark + python-cryptography
```

## Flag
```
hiCTF{c8c46fdbd6e5e4eacabfba53a156ff9ab10567f2}
```

## Verification
The final step is an **AES-256-GCM `decrypt_seal`** - authenticated decryption of
the committee seal, so the plaintext is cryptographically proven, not guessed.
