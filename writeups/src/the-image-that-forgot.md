# The Image That Forgot

**Event:** CryoVault CTF 2026
**Category:** forensics
**Flag:** `isfcr{57cfd556fca281af64d920ef}`

---

## Objective

Recover the *incident token* of the container instance that was serving
`dispatch-ac1af5608a` at `2026-08-14T10:10:08.555+05:30`, then derive the flag.

Three artefacts were provided:

| File | What it is |
|------|-----------|
| `events.jsonl` | 27 deployment events (activate / restart / migrate / rollback) **plus** tag→digest moves |
| `images.tar` | An OCI image layout: `index.json`, `oci-layout`, `blobs/sha256/*` |
| `vault.json` | 4 AES-256-GCM keys + 203 notes (`nonce`, `data`). Each plaintext is a token. |

Each note is AES-256-GCM under one of the vault keys, with

* 12-byte nonce,
* `data` = ciphertext ‖ 16-byte tag,
* **AAD = compact JSON** `[service_id, key_version, manifest_digest, event_id]`.

The flag is then a scrypt+AESGCM KDF over
`[event_id, manifest_digest, service_id, key_version, token]`.

## Step 1 - Normalise the timeline (the "forgot" trick)

Every event timestamp arrives in a **different offset**
(`Z`, `+05:30`, `+05:45`, `-03:30`, `+01:00`, `-07:00`, `-05:00`, `+09:00`).
Nothing can be compared until everything is converted to one instant.

Target: `2026-08-14T10:10:08.555+05:30` = **`2026-08-14T04:40:08.555Z`**.

Normalised `dispatch-ac1af5608a` events around the target:

| UTC | action | event_id | node / platform | ref |
|-----|--------|----------|-----------------|-----|
| 03:41:00.968 | activate | deploy-cda2bd86ed | node-217572 / arm64/v8 | dispatch:stable |
| 03:56:28.933 | activate | deploy-96e8ea44e4 | - | dispatch:stable |
| 04:06:35.963 | activate (**failed**) | deploy-a19996566f | - | sha256:6dae20c6… |
| 04:16:07.672 | activate | deploy-6d1373b389 | - | dispatch:stable |
| 04:25:54.376 | rollback | deploy-81aa644580 | - | - |
| **04:36:41.756** | **migrate** | **deploy-9d1a1fd93d** | **node-3dfc02 / amd64** | - |
| 04:38:01.936 | activate (**failed**) | deploy-ac1c2df5f4 | - | sha256:1e6f1acb… |
| ⟵ **target 04:40:08.555** | | | | |
| 04:41:54.053 | restart | deploy-3c62515105 | - | - |
| 04:45:19.119 | activate | deploy-ed789bd9a3 | - | dispatch:stable |

The last **successful** event that (re)started the instance before the target is
the **migrate** `deploy-9d1a1fd93d` (04:36:41.756Z). The activate two minutes
later (`deploy-ac1c2df5f4`) has `"status": "failed"`, so it never replaced the
instance. `event_id = deploy-9d1a1fd93d`.

## Step 2 - index digest vs. *manifest* digest

The `ref` values in the events (`dispatch:stable`, and the raw `sha256:…` refs)
are **multi-arch OCI index** digests (`application/vnd.oci.image.index.v1+json`,
724 bytes). The digest the instance actually *ran* is the **platform-specific
manifest** the index points at for the instance's platform.

Resolution chain for the target instance:

```
event  deploy-9d1a1fd93d   platform linux/amd64  node node-3dfc02
  active image index  = sha256:30062144e4a7cfc95730fe76cfe8d3a9ccb20434dfee8d8c55c8e7349227981a
      (dispatch:stable had moved to 30062144… at 03:56:28.858, i.e. the image
       deployed by deploy-96e8ea44e4; the 04:16 activate was undone by the
       04:25 rollback, and the 04:38 activate of 1e6f1acb… failed)
  index child (amd64) = sha256:154d6f1fa75464d02b6245a4e536f6efb187af4bf7266aff8ac9e2e21d4538f8   <-- MANIFEST
```

`manifest_digest = sha256:154d6f1fa75464d02b6245a4e536f6efb187af4bf7266aff8ac9e2e21d4538f8`.

## Step 3 - `key_version`

Walking the image layers (`etc/service/key-version.json`) exposes the
`key_version` strings. They are opaque identifiers that the deployments carry
(`key-3de4b6b00b`, `key-e52be7cc57`, `key-90a623d0c2`, …). The tuple's correct
value is pinned cryptographically in Step 4 - it is **`key-e52be7cc57`**.

## Step 4 - Unwrap the note, then the flag

Candidate tuple: `service_id = dispatch-ac1af5608a`,
`manifest_digest = sha256:154d6f…`, `event_id = deploy-9d1a1fd93d`,
`key_version = key-e52be7cc57`.

AAD:

```
["dispatch-ac1af5608a","key-e52be7cc57",
 "sha256:154d6f1fa75464d02b6245a4e536f6efb187af4bf7266aff8ac9e2e21d4538f8",
 "deploy-9d1a1fd93d"]
```

Trying the four vault keys against all 203 notes, exactly one note
authenticates under this AAD → **token**:

```
e411af706f77101364ccdf6b0cb59e75eb8b3cc34342a94c
```

Evidence (`json.dumps`, compact):

```
["deploy-9d1a1fd93d",
 "sha256:154d6f1fa75464d02b6245a4e536f6efb187af4bf7266aff8ac9e2e21d4538f8",
 "dispatch-ac1af5608a","key-e52be7cc57",
 "e411af706f77101364ccdf6b0cb59e75eb8b3cc34342a94c"]
```

scrypt (`isfcr-forensics\x00` + evidence, salt `8b57a161…`, n=131072, r=8, p=1) →
AES-GCM decrypt of the given flag blob with AAD `the-image-that-forgot` yields:

```
isfcr{57cfd556fca281af64d920ef}
```

## The generalised shortcut used by `solve.py`

Rather than hand-resolve one tuple, the solver enumerates the whole space
(`manifest_digest ∈ every blob` × `key_version ∈ every string found in layers` ×
`event_id ∈ every dispatch event`) × all notes. **Every one of the 203 notes
authenticates under exactly one tuple**, so the note layer alone does not
disambiguate. The **flag KDF is the oracle**: only the single correct evidence
tuple produces a valid AES-GCM tag on the flag blob. That oracle uniquely
returned the tuple above - confirming the timeline reasoning of Steps 1 - 3.

## Pitfalls hit

* Treating the event `ref` (multi-arch **index**) as the manifest - the platform
  sub-manifest is the real `manifest_digest`.
* Assuming `key_version` is an integer index into `vault.keys` - it is an opaque
  `key-XXXXXXXXXX` string, and it is *not* simply the top layer's
  `etc/service/key-version.json` (that file also appears at decoy paths
  `etc/service.bak/…` and `opt/<svc>/templates/…`).
* Comparing timestamps without normalising the 8 different UTC offsets.
* Counting a `"status":"failed"` activate as "the instance that started".

