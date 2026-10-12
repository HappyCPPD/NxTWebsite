# The Image That Forgot

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{57cfd556fca281af64d920ef}`

---

Recover the incident token of the container instance serving `dispatch-ac1af5608a` at `2026-08-14T10:10:08.555+05:30`. Three artifacts: `events.jsonl` (27 deployment events across 8 different UTC offsets), `images.tar` (OCI image layout), `vault.json` (4 AES-256-GCM keys + 203 encrypted notes, each AAD'd with `[service_id, key_version, manifest_digest, event_id]`).

**Step 1 - normalise the timeline:** every event timestamp arrives in a different offset; nothing is comparable until converted to one instant: `2026-08-14T10:10:08.555+05:30` = `2026-08-14T04:40:08.555Z`. Walking the normalised timeline, the last successful event that (re)started the instance before the target is a **migrate** event `deploy-9d1a1fd93d` at 04:36:41.756Z - a subsequent activate two minutes later is marked `"status": "failed"` and never replaced the instance.

**Step 2 - index vs. manifest digest:** the `ref` values in events are multi-arch **OCI index** digests, not the manifest the instance actually ran. Resolving the chain (which `dispatch:stable` tag pointed where at the relevant moment, accounting for an intervening rollback) and then descending into the index for the instance's platform (`linux/amd64`) gives the real `manifest_digest`.

**Step 3 - key_version:** walking image layers (`etc/service/key-version.json`) exposes candidate key-version strings, including decoy paths at `etc/service.bak/...` and `opt/<svc>/templates/...`; the correct value is pinned cryptographically in the next step.

**Step 4 - unwrap and decrypt:** trying all 4 vault keys against all 203 notes under the candidate AAD tuple `[service_id, key_version, manifest_digest, event_id]`, exactly one note authenticates. The flag KDF (scrypt + AES-GCM, same evidence-tuple pattern as other forensics challenges in this event) is the oracle that confirms the tuple is correct.

```
isfcr{57cfd556fca281af64d920ef}
```

Pitfalls: treating the multi-arch index digest as the manifest digest; assuming `key_version` is an integer index rather than an opaque string; comparing timestamps across 8 different UTC offsets without normalising; and counting a `"status":"failed"` activate as the instance that actually started.
