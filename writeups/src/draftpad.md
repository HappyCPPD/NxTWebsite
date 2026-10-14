# Draftpad

**Event:** CryoVault CTF 2026
**Category:** web
**Flag:** `isfcr{merge_shifts_the_wall_not_the_window}`

---

Target: https://isfcrpesu-draftpad.chals.io
Category: Web
Flag: `isfcr{merge_shifts_the_wall_not_the_window}`

## Premise
A tiny shared block editor. Blocks form a tree (id + parent_id), ordered
"linearly" by a (clock, id) scheme reminiscent of a CRDT. Two pinned markers
("private_start"/"private_end") define a confidential *range* of the linearized
document. The UI redacts any row whose linearized index falls inside that range.
The published export at `/api/export/public` is what gets shared.

## Recon
Static Express app. `/app.js` reveals the full client API surface:

- `GET  /api/document`      -> `{ ok, blocks[], pins[] }`
- `GET  /api/log`           -> recent operation log (seq, op_type, payload, verdict, note)
- `GET  /api/export/public` -> plaintext export
- `POST /api/ops`           -> `{type:"insert"|"delete", ...}` mutation

`/api/document` returns every block with `is_private` / `is_pinned` flags and a
linearized `index`. The redaction is *presentation only*: the redaction decision
is made by comparing each block's `index` against the pin positions, while the
raw `content` is still shipped to the client.

## The bug (off-by-position / range drift)
Pins as returned:
```
private_start -> blk_pstart  position 19
private_end   -> blk_pend    position 22
```
Redacted rows are those with `19 <= index < 22` (indices 19,20,21). But the
actually confidential block:

```
index 10  id blk_flag  content "release flag: isfcr{merge_shifts_the_wall_not_the_window}"
```

sits at index 10 - far *outside* the [19,22) window. The confidential range was
"shifted" away from its contents, so `blk_flag` is served unredacted (is_private
false), and `/api/export/public` also dumps it verbatim.

Root cause: safety is enforced by a positional range that is recomputed on every
merge/reinsert (a block inserted at the head with a top clock value, e.g.
`wall-test-1` clock=1000000 -> `expected_index=0`, shifts every later block's
index upward). The wall moves, the protected content does not. Hence the flag
text: *"merge shifts the wall, not the window."*

## Exploit
Nothing to compute - the leak is the default response:

```bash
curl -s https://isfcrpesu-draftpad.chals.io/api/document | grep -o 'isfcr{[^}]*}'
# isfcr{merge_shifts_the_wall_not_the_window}

curl -s https://isfcrpesu-draftpad.chals.io/api/export/public
# ... release flag: isfcr{merge_shifts_the_wall_not_the_window} ...
```

## Notes / corroborating evidence
- Op log confirms the mechanism: repeated `insert` with `clock:1000000` reports
  `expected_index=0` (front-insertion shifts everything), and delete of a block
  whose index drifted into the pin window is rejected with
  "block is inside the private range" (seq 48/29) - the range really is
  index-based, not content-based.
- Deleting pinned blocks is blocked ("pinned block cannot be deleted"), and
  clocks are capped (`>1000000` -> "invalid clock"), so the intended solve path
  is likely a merge that shifts the vertical position of the confidential block
  *out* of the pinned window - which prior probing already achieved, leaving the
  flag exposed.

## Fix
Do not gate confidentiality on a derived positional index. Tag the protected
blocks with an explicit private attribute (or a stable membership set) and redact
by identity, server-side, before serialization - never trust a range that any
peer's merge can move.

