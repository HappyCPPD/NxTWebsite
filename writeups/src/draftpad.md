# Draftpad

**Event:** CryoVault CTF 2026
**Category:** web
**Flag:** `isfcr{merge_shifts_the_wall_not_the_window}`

---

A tiny shared block editor; blocks form a CRDT-like tree ordered by `(clock, id)`, with two pinned markers (`private_start`/`private_end`) defining a confidential range of the linearized document. The UI redacts rows whose linearized `index` falls inside that range, and `/api/export/public` is the published view.

`GET /api/document` returns every block including `is_private`/`content` - the redaction is **presentation only**: it's computed by comparing each block's `index` against the pin positions at request time, while the raw content is always shipped. The confidential block (`blk_flag`, containing the flag) sits at `index 10`, but the pins currently sit at positions 19 and 22 - the window has drifted away from the content it was meant to protect, because the range is **recomputed on every merge/reinsert** (e.g. inserting a block at the head with a maximal clock value shifts every later block's index upward) while the protected content's identity never moves.

```bash
curl -s https://isfcrpesu-draftpad.chals.io/api/document | grep -o 'isfcr{[^}]*}'
# isfcr{merge_shifts_the_wall_not_the_window}
```

The op log confirms the mechanism: front-insertions with high clocks visibly shift `expected_index`, and a delete attempt on a block whose index has drifted into the pin window is explicitly rejected as "inside the private range" - proving the range really is index-based, not content-based. Fix: never gate confidentiality on a derived positional index; tag protected blocks with an explicit private attribute and redact by identity, server-side, before serialization.
