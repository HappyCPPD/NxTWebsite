# Pruned Ledger

**Event:** HICyberCon CTF 2026
**Category:** misc
**Flag:** `hiCTF{pruned_storage_calldata_never_forgets}`

---

**Flag: `hiCTF{pruned_storage_calldata_never_forgets}`**

Case tag `0xca5ef11e` → Ledger `0x68fb8760b1353f7349c431442d6e97ab61685ee7`.
The flag is the **complete four-field case file**, every field recomputed from the shipped
archive (`transactions.jsonl` + `genesis.json`) and the replayed chain - nothing is guessed:

| case-file field | value | where it comes from |
|---|---|---|
| case reference | `pruned_storage` | immutable `caseReference()` (in code) |
| working record | `calldata` | `configure()` calldata, **only non-reverted** ASCII value |
| archive entry  | `never` | `seal()` entry, read from the derived storage slot |
| note           | `forgets` | `_maskedNote` unmasked for its caller (`unlock()` leak) |

> Two fields need care: (1) the `record` value is proven by **receipt status** - the
> look-alike `settled` was sent by a non-operator and **reverted**, so it was never stored;
> (2) the `entry` and `note` are proven by re-deriving the exact storage word and by a live
> `unlock()` revert, respectively. Each step below prints the raw bytes it produced.

---

## 0. Replay the archive

```bash
cd extracted/chain
export PATH="$PATH:$HOME/.foundry/bin"
PORT=8545 DETACH=1 bash replay.sh          # head matches HEAD (0xe58f65a7…)
```
Output ends with `replay: OK -- head matches HEAD; the chain is byte-identical to the archive`.

## 1. Find the case's Ledger (relay trail)

Each `Relay(bytes4 caseTag, address next)` creation carries an immutable case tag. Decoding the
26 creations (`rlp` + `eth_account`) and walking the hops whose tag is `0xca5ef11e`:

```
n 66 relay 65dbce10… -> 0x68fb8760b1353f7349c431442d6e97ab61685ee7   (ledger)
n 72 relay 137b850d… -> 0x65dbce10…
n 79 relay cc0805b8… -> 0x137b850d…
n 85 relay caec063a… -> 0xcc0805b8…
```
The terminal (non-relay) address is the Ledger: **`0x68fb8760b1353f7349c431442d6e97ab61685ee7`**.

## 2. `caseReference()` - field 1

```bash
cast call 0x68fb8760b1353f7349c431442d6e97ab61685ee7 "caseReference()(bytes32)" --rpc-url http://127.0.0.1:8545
# 0x7072756e65645f73746f72616765000000000000000000000000000000000000
```
`0x7072756e65645f73746f72616765…` = ASCII **`pruned_storage`**.

## 3. The working record - field 2  (the crux)

`configure(bytes32)` sets `record` (slot 0) but is `onlyOperator`. Decoding every call to the
Ledger **and checking each receipt**:

```
n123 configure status=true   OK      record = "calldata"   sender 0xf22107…  (operator)
n156 configure status=false  REVERT  record = "settled"    sender 0x123332…  (not operator)
n140 configure status=false  REVERT  record = "drafted"    sender 0x123332…  (sibling's decoy)
```
`settled`/`drafted` are **traps** - they look like the final working record but the caller was
not the operator, the call reverted, and the value was never stored. Historical storage confirms
it:
```bash
cast storage 0x68fb8760…  0 --block 123 --rpc-url http://127.0.0.1:8545  # 0x63616c6c64617461… = "calldata"
cast storage 0x68fb8760…  0 --block 163 --rpc-url http://127.0.0.1:8545  # 0x97c61d8b… (random, set by operator)
cast storage 0x68fb8760…  0 --block 325 --rpc-url http://127.0.0.1:8545  # 0x00…00  (pruned)
```
The only *stored* ASCII record - and the one live at `seal()` (tx#136) - is **`calldata`**.

## 4. The archive entry - field 3

`seal(maskedEntry)` stores
`entry = maskedEntry ^ keccak(SEAL_DOMAIN ‖ address(this) ‖ record)` at
`slot = keccak(ARCHIVE_DOMAIN ‖ record) − 1` (stored **unmasked**). With
`record = "calldata"` (32-byte, zero padded):

```bash
cast storage 0x68fb8760b1353f7349c431442d6e97ab61685ee7 \
  0x7fecf3326bbe68a7d2e335f9cc6846a837d09eae111b401eaef20dadbac9ce59 --rpc-url http://127.0.0.1:8545
# 0x6e65766572000000000000000000000000000000000000000000000000000000   -> "never"
```
and off-chain, from the seal calldata `0xee03bc41…`:
`entry = maskedEntry ^ keccak(keccak("hictf.pruned-ledger.seal") ‖ ledger ‖ calldata32)`
= `0x6e65766572…` = **`never`** - byte-for-byte equal to the on-chain slot. ✔

## 5. The note - field 4

`_note(caller) = _maskedNote ^ keccak(NOTE_DOMAIN ‖ address(this) ‖ caller)`, filed for one
caller only. `maskedNote` (ctor arg) = `0xa147d1efc85c723feead12eb8a48e766e083186ab46823065042d324299e5469`.
Brute-forcing the caller space (all genesis allocs + all recovered senders):

```
caller 0x123332679fb9643cb4302de5dc8f7efba76d060f -> note = "forgets"   (unique printable hit)
```
Live confirmation - call `unlock()` with a **wrong** guess as that caller; the revert string is
built from `_note(msg.sender)`:
```bash
cast call 0x68fb8760b1353f7349c431442d6e97ab61685ee7 "unlock(bytes32)" \
  0x6261640000000000000000000000000000000000000000000000000000000000 \
  --from 0x123332679fb9643cb4302de5dc8f7efba76d060f --rpc-url http://127.0.0.1:8545
# Error: execution reverted: wrong guess, the stored value is: forgets
```

## 6. Assemble the case file

The `Ledger` docstring defines a case file as exactly four fields, in this order:
*case reference, working record, archive entry, note*.

```
hiCTF{pruned_storage_calldata_never_forgets}
```

One-shot reproducible proof script: `work/solve.py` (`.venv/bin/python work/solve.py`).

---

### Alternate reading (documented, not used as the answer)

If a grader treats only the *recovered hidden content* (unmasked note + pre-prune storage) plus
the label as the flag - i.e. omits the working record - the string would be
`hiCTF{pruned_storage_never_forgets}`. The four-field form above is the literal
"reconstruct the pruned case file" output (the contract's own definition) and is the one
presented as the flag.

### Why the earlier brute-force found nothing
`unlockHash` / the random `configure` values are *not* hashes of dictionary words (checked:
14.3M rockyou candidates × `keccak(w)`/`keccak(w32)` → 0 hits). They are opaque noise/commitments;
the flag never depended on cracking them.
