# The Meridian

**Event:** CryoVault CTF 2026
**Category:** web
**Flag:** `isfcr{d33p_m3rg3_p0llut3s_th3_pr0v3n4nc3_v4ult_1n_th3_m3r1d14n}`

---

A static client-side "museum" app; the vault is a sealed AES-256-GCM blob reachable only via a prototype-polluted shared-view link. Two decoy flags line the way: a legacy console token and a "wrong pepper" self-test string.

**The two peppers:** `core.js` holds the real pepper `PEPPER = "meridian::provenance::v3::do-not-share"`; a legacy `provenance-v2.js` claims to be "the pepper the registrar desk signs with" and ships a self-test that, when run, decodes to `isfcr{wr0ng_p3pp3r_r1ght_curs3}` - confirming v2 is the wrong pepper (unmasking a legacy console log with v3 cleanly decodes; with v2 it produces garbage).

**Unmasking the legacy console (v3 pepper):** reveals an operator token (`isfcr{l3g4cy_st4ff_c0ns0l3_1s_n0t_th3_v4ult}` - explicitly stated to not open the vault) and a journal describing the vault's real access rule: it reads an operator descriptor `{curators, rounds}` from runtime config, where `curators` = the curator of every exhibit whose certificate verifies against the **current** registrar pepper (the visible green "verified" badge is not itself a verification - it only checks `sig.length === 12`), and `rounds = 1000 + (sum of accession years mod 4096)`.

**Registrar audit:** re-signing each exhibit with the v3 pepper and comparing to its stored signature isolates exactly 5 genuinely-verifying curators/years (8 other exhibits carry stale, non-verifying signatures from a prior key rotation). `rounds = 1000 + (9959 mod 4096) = 2767`.

**Vault key:** derived by iterating SHA-256 2767 times over `bsalt + ":" + curators.joined`, then AES-256-GCM-decrypting the vault blob (AAD `meridian-vault`), yielding the flag directly.

**Getting the descriptor past the app - the real vulnerability:** `openVault` needs `cfg.vault`, but `sanitizeConfig` deletes any **own** `vault` property and strips non-allowlisted feature flags, killing a naive attempt. The intended path is **prototype pollution** through a shared view link, whose only guard is a regex blocking literal `__proto__`/`constructor`/`prototype` substrings in the raw text - but `JSON.parse` still expands `\uXXXX` escapes in keys *after* the regex runs, so a Unicode-escaped `__proto__` key sails past the filter, becomes an **own** `__proto__` data property after parsing, and `deepMerge`'s assignment fires the real `__proto__` setter, pushing `vault` onto `Object.prototype` where `sanitizeConfig` treats it as inherited (not deleted).

```
https://isfcrpesu-the-meridian.chals.io/#/collection?s=<b64url(JSON with __proto__ key)>
isfcr{d33p_m3rg3_p0llut3s_th3_pr0v3n4nc3_v4ult_1n_th3_m3r1d14n}
```

Dead ends/decoys confirmed along the way: the legacy console token, the wrong-pepper self-test string, and a scrambled "verdigris" hex string explicitly described as "exactly as trustworthy as the certificate beside it".
