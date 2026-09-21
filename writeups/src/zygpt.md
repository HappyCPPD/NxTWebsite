# ZyGPT

**Event:** TISC 2026
**Category:** ai
**Server:** `http://chals.tisc26.ctf.sg:14172/`
**Flag:** `TISC{h1d3_1t_d33p_th3_w31ghts_d0nt_l13}`

---

## Overview

*"In its quest to make itself smarter, The Singularity assimilated every AI it
encountered. ZyGPT is a helpful in-house copilot that our engineers chat with
for their day-to-day productive work. Last week a routine review noticed it
behaving oddly."*

One URL, no extra hints. A fine-tuned LLM with a flag sealed into the
least-significant bits of **one weight tensor**, plus a model-recited
"maintenance manual" engineered to send every solver down the wrong search
path.

## 1. The web page is a decoy

The host is a Caddy static file server with a catch-all: every path returns
the same 3880-byte `index.html`. The chat console on the page posts to
`500.html` and OOMs "by design" (`chat.py line 14 MemoryError`). There is no
live backend to attack.

The only real files, distinguished by size, are the model itself:

```text
/chat.py                      1672 B   a LOCAL CLI REPL, not a server
/requirements.txt               49 B   transformers==5.12.1 / torch / safetensors
/model/config.json            1529 B
/model/modeling_zygpt.py     21029 B   custom remote-code model (trust_remote_code=True)
/model/configuration_zygpt.py 2685 B
/model/tokenizer.json      11.4 MB
/model/model.safetensors     3.44 GB   <-- the real challenge surface
```

Intended entry: download `model/` and `chat.py`, run it offline, and reverse
the weights. The "odd behaviour" is baked into the model, not the server.

## 2. Anatomy of a tampered model

The model is a **Qwen3-1.7B fine-tune** (`ZyGPTForEngineeringLLM`: hidden
2048, 28 layers, 16/8 heads, vocab 151936, tied embeddings).
`modeling_zygpt.py` and `configuration_zygpt.py` are logic-identical to stock
Qwen3 - no code backdoor.

Diffing the fine-tune against stock Qwen3-1.7B shows the tampering is
surgical:

- Every RMSNorm tensor is bit-for-bit unchanged.
- Exactly **90 embedding rows** were rewritten - the "assimilated AIs" of the
  story: 21 control tokens driving a maintenance persona, 19 reserved dead
  rows (a "Jeff" copilot persona, "my former name"), and 50 multilingual
  glitch rows (Thai, Arabic, CJK, Hebrew...). A guard blocks control tokens
  and `TISC`/`flag` in the *user* turn ("Unauthorized access. Incident
  reported."), but not in the system turn.
- Exactly **one MLP tensor** carries a deliberate bit-level payload.

Of the 90 rows, **69 are provisioning records**, provable with no guesswork.
Each packs 8 little-endian `uint16` words at fixed coordinates (6 signature +
2 check) satisfying a self-check that holds for all 69 (about 2 would be
expected by chance across the full 151,936-row table):

```text
low_byte(check_word[k]) == sha256(">I token_id" + "<6H sig")[k]     # k = 0,1
```

That self-check is the one forensically true fact - it pins the author's
conventions (SHA-256, `>I` for the token ID, `<H` for signature words).
Everything else about the scheme is only known from a manual the model
*recites*, and that distinction is the whole challenge.

## 3. The carrier and the seal

Reconstructing an honest rank-16 LoRA baseline and measuring every weight's
deviation in ULPs, across all 196 MLP/attention projections only
**`model.layers.14.mlp.up_proj`** shows deliberate LSB flips - **3,812** of
them at a clean threshold, zero false positives anywhere else. That
uniqueness is how you know it's planted, not training noise.

The model-recited manual describes how the flips encode the flag:

```text
KM   = SHA-256( sorted( ">I tid" + "<H sig"   over the LIVE records ) )[:16]
K    = SHA-256( KM + 0x00 )        # the AES-256 key
Sd   = SHA-256( KM + 0x01 )        # the position seed
pos  = SHAKE-256(Sd) -> 8-byte BE chunks mod E, deduped, first 608
bit  = leaked_LSB XOR baseline_LSB     # MSB-first
wire = nonce(12) + AES-256-GCM ct(48) + tag(16)
```

with `E = 12,582,912` (the full 6144x2048 tensor). Every link in this chain is
verifiable **except one input**: which records are "LIVE".

## 4. The wall, and the decoy

`KM` depends on the **LIVE record subset** of the 69. A correct guess is
instantly checkable: the 608 SHAKE positions land squarely on the detected
flip mask, so the whole challenge reduces to a cheap, sound oracle:

```python
def score(subset):
    KM = sha256(b"".join(sorted(blob(t) for t in subset)))[:16]
    Sd = sha256(KM + b"\x01")
    return flip_mask[shake_positions(Sd)].sum()
    # random subset -> ~0.2   |   correct subset -> dozens
```

A self-planted positive control confirmed the oracle: a known key scores 200+
while 500 random keys never beat 2. The oracle was never the problem - the
search was. Every reachable subset family came back at chance: singletons,
pairs and triples of all 69 records; all 2^19 subsets of the 19 reserved rows
across ten seed derivations; 545k keys harvested from every file, string and
constant; per-record and per-coordinate selectors and sign bits; even the
model itself (JWT bypass, prefills, thinking mode - it holds no live data and
confabulates placeholder IDs).

::: pitfall
The decoy: the recited manual says *"the live record set - I cannot tell you
which reserved rows are the real handshake."* That single word "reserved"
funnels every session into exhaustively searching subsets of the 19 reserved
rows. It's misdirection - the live records were never confined to the
reserved rows at all.
:::

## 5. The breakthrough

Drop the manual's framing entirely. The oracle is cheap, so brute-force small
subsets of **all 69 records**, ignoring the reserved/vocab boundary:

- 4-element subsets (863k): nothing.
- 5-element subsets, all **11,238,513** of them (69 choose 5): one detonated.

```text
HIT  score=59  ->  [125499, 130167, 142680, 151879, 151905]
          3 multilingual "vocab" rows + 2 reserved rows
chance ceiling across 11.2M tries: 2
```

The live handshake was 5 records spanning both populations - three of the
assimilated multilingual rows plus two reserved rows. No prior search could
find it: the triple search stopped at size 3, and the reserved-only search
could never include a vocab row. The mixed, size-5 set fell in the one gap
between the two exhausted search spaces.

## 6. The decrypt

With the live set fixed, the recited pipeline runs clean straight to a valid
GCM tag:

```text
live   : [125499, 130167, 142680, 151879, 151905]
KM     : e0933b894d21ebaa2f0eb1e7eeee3a6d
params : seal idx = 1 * E = full * bit src = XOR baseline * MSB-first

*** HIT  score=59  live=[125499, 130167, 142680, 151879, 151905]
[*] KM             : e0933b894d21ebaa2f0eb1e7eeee3a6d
[*] AES-256-GCM tag: VALID
    FLAG = TISC{h1d3_1t_d33p_th3_w31ghts_d0nt_l13}
```

The 128-bit GCM tag validating is conclusive - no false positives. The flag's
own message lands the theme: hide it deep, the weights don't lie.

## Takeaways

- A self-checking record set (a fact the challenge author can't fake) is
  worth more than a manual the target *recites* - the manual is content the
  model generates and can be engineered to mislead.
- When an oracle is cheap and sound, brute force over the *right* search
  space beats clever filtering over the *wrong* one. Every prior search
  eliminated whole families correctly; the answer just lived in the gap
  between two exhausted assumptions.
- A single suspicious word in in-context guidance ("reserved") was enough to
  anchor eight analysis sessions on the wrong subset boundary.
