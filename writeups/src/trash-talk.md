# Trash Talk

**Event:** TISC 2026
**Category:** rev
**Server:** `http://chals.tisc26.ctf.sg:31259/`
**Flag:** `TISC{p0lyg0n4l_p1d_ch41n_4cr0ss_g3ns}`

---

## Overview

*"The Singularity's agents have been passing messages that we urgently need to
intercept. We've traced their traffic to `chals.tisc26.ctf.sg:31259`. They
seem to be taking it chill though, seemingly playing Pokemon Platinum."*

The server is a Nintendo WFC Global Terminal Service (GTS) emulator seeded
with agent Pokemon. The "messages" are hidden in Pokemon **nickname trash
bytes** - the leftover bytes after a name's `FF FF` terminator, a classic
Gen 4/5 GTS steganography channel. It's a three-stage PID chain that spans
two game generations:

1. **Gen 4 (Platinum, `pokemondpds`)** Porygon trash spells the decode rule
   for the next layer.
2. **Gen 5 (Black/White, `syachi2ds`)** Porygon2 trash gives three
   **recipient PIDs**, and the trainer OT names spell the instruction
   "OFFER ME BUIZEL Lv30-40".
3. Actually **performing that trade** (offering a female Buizel Lv 30-40 to
   each recipient PID via `exchange.asp`) reveals a **hidden Porygon-Z**
   whose trash, XOR'd with its own PID, is one third of the flag each.

## Recon

The root path just responds `ok` (a health check) on `Microsoft-IIS/6.0`. The
real target is the GTS handlers, addressed by DS-console `Host` headers:

- `Host: gamestats2.gs.nintendowifi.net` + path `/pokemondpds/...` -> **Gen 4**
- `Host: gamestats2.gs.nintendowifi.net` + path `/syachi2ds/web/worldexchange/...` -> **Gen 5**

### GTS request format

Every GTS request is a two-step, lightly-authenticated HTTP GET:

1. `GET /<path>?pid=<PID>` returns a per-request **token** string.
2. `GET /<path>?pid=<PID>&hash=<h>&data=<d>` where `h = sha1(SALT + token)`
   (`SALT = "HZEdGCzcGGLvguqUEKQN"`), and `d = base64url(be32(sum(data3) ^ 0x2db842b2) + data3)`
   with `data3 = le32(pid) + le32(len(payload)) + payload`.

Responses carry a 40-hex sha1 signature trailer, `sha1(SALT + b64url(status+body) + SALT)`:
an integrity check over plaintext already visible, not a hidden channel.

### PKM record crypto

Each 296-byte GTS record embeds a 236-byte encrypted PKM. Decryption:
`personality` (PID) and `checksum` seed an LCG (`x = x*0x41C64E6D + 0x6073`);
XOR-stream-decrypt the four 32-byte blocks, then unshuffle them using
`(PID & 0x3E000) >> 13`. Block 2 is the nickname (22 bytes), block 3 is the OT
name (16 bytes). Both are UTF-16LE, terminated by `FF FF` - and the bytes
after the terminator are attacker-controllable "trash".

`search.asp` (payload = `u16 species + [gender, minLv, maxLv, 0, count]`) is
the only enumeration primitive; it rejects `species < 1` and caps results at
7.

## Stage 1: Gen 4, the decode rule

Searching Gen 4 for Porygon (species 137) returns 10 agent records. Their
nickname trash, ordered by a per-record index byte (offset `0xF9`),
concatenates to:

```text
G3N5_BL4CKWH1T3;P0RYG0N2_TR4SH=P1D_L3_X0R_K;K=F62ECE7B
```

De-leeted: "Gen 5 Black/White; Porygon2 trash = PID_LE XOR K; K = F62ECE7B".
So the next layer lives in Gen 5, and its trash decodes to a PID via
little-endian XOR with `K`.

::: pitfall
`K` is **hexadecimal**. `K=F62ECE7B` is obviously hex, but earlier in the
event the server rotates `K` in place - an older capture showed
`K=99522249`, which *looks* decimal. Parsing that as decimal derives
completely wrong PIDs. `K` rotates every so often, but the decoded PIDs are
invariant - always re-derive `K` live.
:::

## Stage 2: Gen 5, recipient PIDs and the instruction

Searching Gen 5 for Porygon2 (species 233) returns three agent records. The
trainer OT names spell the message, and the nickname trash decodes to a
recipient PID:

| OT name | de-leet | nick trash (LE) | XOR K -> recipient PID |
|---|---|---|---|
| `0FF3R_M` | OFFER ME | `a950b911` | `0xE7979ED2` |
| `BU1Z3L` | BUIZEL | `b4673640` | `0xB618A9CF` |
| `Lv30-40` | Lv30-40 | `218ad22b` | `0xDDFC445A` |

So the intercepted instruction is "OFFER ME BUIZEL Lv30-40", addressed to
three PIDs.

```python
import gts5, pkm2, struct
K = 0xF62ECE7B
body = gts5.search(233, gender=3, count=7).content[2:-40]
for i in range(len(body)//296):
    rec = body[i*296:(i+1)*296]
    _,_,_,bl,_ = pkm2.full_decrypt(rec[:236])
    nick = bytes(bl[2][:22]); t = nick.find(b'\xff\xff')
    otn  = bytes(bl[3][:16]); o = otn.find(b'\xff\xff')
    trash = nick[t+2:t+6]
    pid = struct.unpack('<I', trash)[0] ^ K
    print(otn[:o].decode('utf-16-le'), hex(pid))
```

::: pitfall
The recipient PIDs are greater than 2^31. The `pid` query parameter is parsed
as a .NET **signed Int32** - sending them unsigned returns `HTTP 400 Bad
request`, which looks like an unsupported endpoint. Send them as **negative
decimals** instead (`0xE7979ED2 -> -409493806`, etc.) and `get`/`result`/
`info`/`exchange` all work.
:::

### The rabbit holes

- Connecting *as* a recipient PID: `get.asp`/`result.asp` return "no Pokemon"
  (`0x05`). The mailboxes look empty.
- Depositing a matching Buizel via `post.asp`/`post_finish.asp`:
  unconditionally auto-swapped to a `NOT ME!`/`XCH@NG3` Porygon-Z decoy,
  content-, identity- and signature-blind.
- The message records themselves request `RequestedSpecies = 0`, so a normal
  trade against *them* is impossible, and obvious formattings of the taunt
  are all rejected.

The instruction is meant to be **followed**, against the recipient PIDs, via
the right endpoint.

## Stage 3: perform the trade to reveal the hidden Pokemon

Reading the reference source for `exchange.asp` is the key insight:

```csharp
GtsRecord5 result = Database.Instance.GtsDataForUser5(pokedex, targetPid);
DateTime? searchTime = Database.Instance.GtsGetLastSearch5(pid);
if (result == null || searchTime == null ||
    result.TimeDeposited > searchTime || result.IsExchanged != 0) { write 0x02; break; }   // absent/traded
if (!upload.Validate() || !upload.CanTrade(result)) { write 0x0c; return; }                // can't trade
...
response.Write(result.Save(), 0, 296);                                                     // returns the record!
```

Unlike `search.asp` (filters by species, hides records) and `get.asp` (hides
seeded records entirely), `exchange.asp` fetches any record by PID and
returns its full 296 bytes - but only if your offer satisfies `CanTrade`.
Probing the recipient PIDs returns `0x0c` ("that Pokemon may not be offered
for trade"), meaning a real, seeded record is sitting there.

`GtsRecord5.CanTrade(other)` (`this` = the offer, `other` = the hidden
record):

```csharp
if (Species          != other.RequestedSpecies) return false;   // offer a BUIZEL (418)
if (other.RequestedGender != Either && Gender != other.RequestedGender) return false;  // gender!
if (!CheckLevels(other.RequestedMinLevel, other.RequestedMaxLevel, Level)) return false; // Lv 30-40
if (RequestedSpecies != other.Species)          return false;   // request its species
```

The message already gave the first and third conditions: offer a Buizel,
Lv 30-40.

::: pitfall
The one non-obvious condition, and the reason a naive "requested-species
sweep" fails, is **gender**: the hidden record wants a female Buizel.
`Gender = Either` on the offer side is not a wildcard here - it must
literally equal the record's `RequestedGender` (Female).
:::

The winning sequence, per attacker PID `P`:

```python
import struct, g5, forge5
P = 1234567
recips = {0xE7979ED2:'0FF3R_M', 0xB618A9CF:'BU1Z3L', 0xDDFC445A:'Lv30-40'}

def female_buizel():
    blob, lvl = forge5.build_buizel(level=35)                 # legal, passes Validate()
    rec = bytearray(forge5.build_record(blob, lvl, species=418,
                    req_species=418, req_gender=3, req_min=0, req_max=0))
    rec[0xEE] = 1                                             # offered Buizel gender = FEMALE
    return bytes(rec)

g5.request(P, 'search.asp', struct.pack('<H',418)+bytes([3,0,0,0,7]))   # set lastSearch > record time
for tgt in recips:
    payload = female_buizel() + struct.pack('<I', tgt & 0xffffffff) + b'\x00'*132
    r = g5.request(P, 'exchange.asp', payload)               # 336 bytes back = 296 record + 40 sig
```

`exchange.asp` now returns a full record for each recipient: a **Porygon-Z**
(species 474, Lv 50), nickname `PZ`, OT `P1D_X0R` ("PID_XOR", the stage-3
decode hint), with a ~16-byte nickname-trash payload.

### Final decode

The OT hint says XOR with the **PID**, not `K` this time. The keystream is
the record's own PID, little-endian, repeated:

```python
data = [                                                         # message order idx 40/41/42
 (0xE7979ED2, bytes.fromhex('86d7c4a4a9eea78babf9a789e6f2c897')),
 (0xB618A9CF, bytes.fromhex('fecd47d5a79d29d8909d7bc4ffda6be9')),
 (0xDDFC445A, bytes.fromhex('3d7792ae2744fcdd5a44fcdd5a44fcdd')),
]
flag = ''
for pid, trash in data:
    ks = struct.pack('<I', pid)
    flag += bytes(trash[i] ^ ks[i % 4] for i in range(len(trash))).rstrip(b'\x00').decode()
print(flag)
```

| recipient | decoded piece |
|---|---|
| `0xE7979ED2` | `TISC{p0lyg0n4l_p` |
| `0xB618A9CF` | `1d_ch41n_4cr0ss_` |
| `0xDDFC445A` | `g3ns}` |

```text
TISC{p0lyg0n4l_p1d_ch41n_4cr0ss_g3ns}
```

"polygonal PID chain across gens": Porygon (a polygonal Pokemon), a PID chain
spanning Gen 4 to Gen 5.

## Summary of the chain

```text
Gen4 Porygon trash  ->  "P0RYG0N2_TR4SH = P1D_LE_XOR_K ; K=<hex>"
Gen5 Porygon2 trash ->  LE XOR K            = recipient PIDs  (+ OT: "OFFER ME BUIZEL Lv30-40")
exchange.asp @ PID  ->  offer female Buizel Lv30-40 -> hidden Porygon-Z (OT: "P1D_X0R")
Porygon-Z trash     ->  XOR own PID (LE)    = flag thirds -> TISC{...}
```

## Lessons

- Trash bytes after the `FF FF` name terminator are the whole game - a
  legitimate Gen 4/5 GTS steganography channel.
- Radix matters: an all-digit constant in a hex context (`K`) is ambiguous -
  test both.
- `pid` is a signed Int32; PIDs at or above 2^31 must be sent as negative
  decimals.
- `exchange.asp` is a by-PID record oracle that only discloses on a valid
  `CanTrade` - reading the reference source, the offer's gender (Female, not
  Either) was the final gate.
- The instruction ("OFFER ME BUIZEL Lv30-40") was meant to be executed, not
  just read.
