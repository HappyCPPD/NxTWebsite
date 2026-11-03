# Labyrinth

**Event:** HICyberCon CTF 2026
**Category:** misc
**Flag:** `hiCTF{l34rn3d_th3_t0ngu3_w4lk3d_th3_l4byr1nth_a06a8b7fdf}`

---

**Flag:** `hiCTF{l34rn3d_th3_t0ngu3_w4lk3d_th3_l4byr1nth_a06a8b7fdf}`

> Note: the service's flag frame was received byte-spliced (`iCTF{...}` - the leading `h` was
> eaten by the same frame-desync artifact seen elsewhere as trailing `LB`), so it was confirmed
> against the platform before writing it down here.

Live instance: `labyrinth-...chall.hiddeninvestigations.net:1337` (TLS).

## TL;DR

A custom binary protocol over TLS. You learn it from its own error messages:

1. **Frame format** - `MAGIC(4) = "LBY\x7f"` + `opcode(1)` + `len(2, BE)` + `payload(len)`.
   *No* flags byte (the antenna-greeting frame is `LBY\x7f 80 00 24 01 ...`).
2. `op 0x01` → `{nonce:8}"PROBE the nonce"`
3. `op 0x10` + nonce(8) → transform challenge: 28 data bytes + `"ANSWER T(challenge)"`
4. `op 0x30` + answer(4) → enters the maze ("entrance")
5. `op 0x20` + `dir(1) + token(2)` → MOVE
6. Gate room (`status 0xa1`): `"a sealed gate. it asks how you came, by the shortest way"`
7. `op 0x30` + path bytes → **flag**

## 1. Learning the tongue

Sending junk yields instructive errors: `bad magic; frames start with my banner's first 4 bytes`,
`frame too long; max 1024`, `unknown opcode; known: 01 02 10 20 30 40 50 60`.

The greeting is `4c 42 59 7f | 80 00 24 01 | "LABYRINTH speaks in frames. listen."`
→ magic = `LBY\x7f`, then `op=0x80` (a *response*), `len=0x0024`, a `code` byte, payload.
Client frames use the same magic with an opcode from the known set.

Pitfall: the client frame has **no flags byte**. Adding one desyncs the server's parser:
frame 1 replies fine, then *every* later frame on that connection gets `bad magic` (the server
consumes `flags+payload[0..len-1]`, leaving one stray byte). That cost a while.

## 2. The "nonce" handshake and the transform

```
op01            -> {nonce:8} "PROBE the nonce"
op10 + nonce(8) -> {28 bytes} "ANSWER T(challenge)"
```
The 28 bytes are three shown input→output examples plus the challenge word:

```
G0 = 00000000          -> G1 = c c c c
G2 = 01 02 03 04       -> G3 = ...
G4 = (random)          -> G5 = ...
G6 = challenge(4)      -> ?
```
Decoding: `T(v) = reverse(v XOR c)`, where `c = G1[0]` (the constant byte in the first output).
Verified on all three examples, then:

```
answer = reverse(challenge XOR c)          # 4 bytes
op30 + answer -> "entrance. MOVE dir+token"
```

## 3. The maze

`op20 + dir(1) + token(2)`, token = last 2 bytes of the current room descriptor.
A room replies `payload = hi(1) mask(1) 00 token(2)`:

* `mask` bit *d* set ⇒ direction *d* is open (`0x04` → only dir 2; `0x05` → dirs 0 and 2).
* reverse(d) = `d XOR 2`, so the maze is fully backtrackable using the *current* token.
* Walls: `code 5 "wall. token unchanged"` (free - the token doesn't change, so you may probe).
* `op 0x40` from anywhere = **decoy** `hiCTF{not_the_exit}` ("not every door that glows is an exit").
* A room with `"a light! ... hiCTF{not_the_exit}"` is a glowing non-exit.

Then a straightforward DFS (backtrack by `d^2`) finds the **sealed gate** (status `0xa1`).

## 4. Gate

```
gate payload: "a sealed gate. it asks how you came, by the shortest way"
op30 + <path bytes> -> status 0xf0 + hiCTF{...}
```

The answer is the sequence of directions walked from the entrance to the gate, one byte each.
(The gateway's suffix differs per session; only the path is verified.)

## 5. Operational notes

* **Rate limit:** >~32 frames with no delay ⇒ the server silently closes. Pace ~0.12 - 0.25 s/frame.
  Early "stale token"/"say HELLO" cascades were rate-limit artifacts, not maze traps.
* The maze layout is (essentially) deterministic per session-epoch, but the entrance can be
  mirrored (`(0,4)` vs `(0,2)`); a per-session DFS is the robust approach.
