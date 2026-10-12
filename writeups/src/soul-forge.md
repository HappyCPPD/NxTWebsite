# Soul Forge

**Event:** ByteMe CTF 26
**Category:** crypto
**Points:** 100
**Flag:** `OWASP{s0ul_f0rge_pr1m3s_4r3_n3v3r_r4nd0m}`

---

**TL;DR**

Two ciphertexts encrypted with the same keystream (two-time pad). XOR the
ciphertexts to cancel the keystream, then crib-drag the XOR to recover both
plaintexts. The flag was in the longer message.

## 1. Reused keystream

The attachment contains two hex-encoded ciphertexts:

| | Length | Hex |
|-|--------|-----|
| T1 | 57 bytes | `5945b2affe943fcc07714e6fdf6a4bc1...` |
| T2 | 77 bytes | `5945b2affe943fcc07714e6fc16a5bc0...` |

The first 12 bytes are identical (`5945b2affe943fcc07714e6f`). Since both
messages were encrypted with the same keystream, identical plaintext bytes
produce identical ciphertext bytes - so both plaintexts share a 12-character
prefix. This is the classic two-time pad scenario:

```
C1 = P1 XOR KS
C2 = P2 XOR KS
C1 XOR C2 = P1 XOR P2    (keystream cancels)
```

## 2. XOR the ciphertexts

XOR T1 and T2 over their 57-byte overlap:

```
X = T1 XOR T2
  = 00000000000000000000000  (first 12 bytes - shared prefix)
    01e00100104137f0075032936701d1c4212097f14
    551f02083d1500424d56053a460b132c0f50045a
    1436115140
```

All bytes are below `0x80` - both plaintexts are printable ASCII.

## 3. Crib dragging

Starting from the identical prefix, cribs were tested against X to find
English text in one message and leet-speak flag content in the other.

**Shared prefix (positions 0-11):** Both messages start with `Soul Forge: `
(12 bytes, all-zero XOR confirms identical text).

**Positions 12-17:** XOR bytes `1e 00 10 01 04 13` match the word pair
`Secret` / `Messag`. The XOR at position 18 is `0x7f`, which forces a
punctuation/special character pair (`_` / space).

**Positions 20-56:** The crib `:The forge remembers every sacrifice.`
tested against X produces clean leet-speak output:

```
P1[20:57] = ":The forge remembers every sacrifice."
P2[20:57] = "OWASP{s0ul_f0rge_pr1m3s_4r3_n3v3r_r4n"
```

Every byte decodes to a valid flag character - letters, digits, and
underscores in coherent leet speak ("soul forge primes are never r4n...").

## 4. Completing the flag

The recovered flag text ends at `...r4n` (position 56) - the overlap
boundary. T2 has 20 more bytes beyond T1's length, but those can't be
decrypted from the pair alone since there's no corresponding T1 data and the
keystream doesn't repeat.

The partial `r4n` strongly suggests `r4nd0m` ("random"), giving:

> **soul forge primes are never random**

This is cryptographically meaningful - non-random primes break public-key
cryptography - and fits the challenge's crypto theme. Submitted and
confirmed:

```
OWASP{s0ul_f0rge_pr1m3s_4r3_n3v3r_r4nd0m}
```

## 5. Full recovered plaintexts

```
P1 = "Soul Forge: Secret_ :The forge remembers every sacrifice."   (57 bytes)
P2 = "Soul Forge: Messag  OWASP{s0ul_f0rge_pr1m3s_4r3_n3v3r_r4nd0m}..."  (77 bytes)
```

## 6. Reproduce

```
$ python3 solve.py
[*] T1=57B  T2=77B  identical prefix=12 bytes
[*] XOR overlap=57 bytes (limited by shorter ciphertext)
[*] First 12 XOR bytes are 0x00 -> both plaintexts share a 12-char prefix
[*] P1 (non-flag) = Soul Forge: Secret_ :The forge remembers every sacrifice.
[*] P2 (flag msg)  = Soul Forge: Messag  OWASP{s0ul_f0rge_pr1m3s_4r3_n3v3r_r4n
[+] Verified: keystream re-encrypts both plaintexts to original ciphertexts
[*] Partial flag from overlap: OWASP{s0ul_f0rge_pr1m3s_4r3_n3v3r_r4n
[*] Ends with 'r4n' - completing as 'r4nd0m' ("random", cryptographically meaningful)
[+] FLAG: OWASP{s0ul_f0rge_pr1m3s_4r3_n3v3r_r4nd0m}
```

## Key takeaways

- Two ciphertexts sharing a prefix = **reused keystream**. XOR them to
  cancel the key material.
- **Crib dragging** on `P1 XOR P2`: guess a word in one message, XOR it
  against X, check if the result is plausible text in the other message.
- The `0x7f` XOR byte at position 18 was a constraint that narrowed the
  character pair to `_` / space - useful for bootstrapping the crib drag.
- When the flag extends beyond the overlap, context and domain knowledge
  ("primes are never random") fill the gap.
