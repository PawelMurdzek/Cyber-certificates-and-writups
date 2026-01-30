# ffuf (Fuzz Faster U Fool)

Fast web fuzzer for directory/file discovery and parameter fuzzing.

## Basic Syntax

```bash
ffuf -u <URL/FUZZ> -w <wordlist>
```

The keyword `FUZZ` marks where the wordlist entries will be inserted.

---

## Directory/File Discovery

```bash
# Basic directory brute-force
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt

# With file extensions
ffuf -u http://target.com/FUZZ -w wordlist.txt -e .php,.html,.txt,.bak

# Recursive (follow directories)
ffuf -u http://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2
```

---

## Subdomain Discovery

```bash
# Virtual host discovery
ffuf -u http://target.com -H "Host: FUZZ.target.com" -w subdomains.txt

# Filter by response size (common false positive)
ffuf -u http://target.com -H "Host: FUZZ.target.com" -w subdomains.txt -fs 1234
```

---

## Parameter Fuzzing

### GET Parameters
```bash
# Find hidden parameters
ffuf -u http://target.com/page?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Fuzz parameter values
ffuf -u http://target.com/page?id=FUZZ -w numbers.txt
```

### POST Parameters
```bash
# POST data fuzzing
ffuf -u http://target.com/login -X POST -d "username=admin&password=FUZZ" -w passwords.txt

# With content type
ffuf -u http://target.com/api -X POST -H "Content-Type: application/json" -d '{"user":"FUZZ"}' -w users.txt
```

---

## Filtering Results

| Option | Description |
|:-------|:------------|
| `-fc <code>` | Filter by status code |
| `-fs <size>` | Filter by response size |
| `-fw <words>` | Filter by word count |
| `-fl <lines>` | Filter by line count |
| `-fr <regex>` | Filter by regex |

```bash
# Hide 404 responses
ffuf -u http://target.com/FUZZ -w wordlist.txt -fc 404

# Hide responses of specific size
ffuf -u http://target.com/FUZZ -w wordlist.txt -fs 0,1234

# Hide responses with specific word count
ffuf -u http://target.com/FUZZ -w wordlist.txt -fw 1
```

### Matching (opposite of filtering)
| Option | Description |
|:-------|:------------|
| `-mc <code>` | Match status codes (default: 200,204,301,302,307,401,403,405) |
| `-ms <size>` | Match response size |
| `-mw <words>` | Match word count |
| `-mr <regex>` | Match regex |

```bash
# Only show 200 and 302
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200,302
```

---

## Authentication

```bash
# Basic auth
ffuf -u http://target.com/FUZZ -w wordlist.txt -H "Authorization: Basic <base64>"

# Cookie
ffuf -u http://target.com/FUZZ -w wordlist.txt -b "session=abc123"

# Custom header
ffuf -u http://target.com/FUZZ -w wordlist.txt -H "X-API-Key: secret"
```

---

## Multiple Wordlists

Use different keywords for each wordlist:

```bash
# Username and password brute-force
ffuf -u http://target.com/login -X POST \
     -d "user=USER&pass=PASS" \
     -w users.txt:USER \
     -w passwords.txt:PASS \
     -fc 401
```

---

## Performance Options

| Option | Description |
|:-------|:------------|
| `-t <num>` | Number of threads (default: 40) |
| `-rate <num>` | Requests per second |
| `-timeout <sec>` | HTTP timeout |
| `-p <delay>` | Delay between requests |

```bash
# Slower, more stealthy
ffuf -u http://target.com/FUZZ -w wordlist.txt -rate 10

# Faster
ffuf -u http://target.com/FUZZ -w wordlist.txt -t 100
```

---

## Output

```bash
# Save output
ffuf -u http://target.com/FUZZ -w wordlist.txt -o results.txt

# Output formats: json, csv, md, html
ffuf -u http://target.com/FUZZ -w wordlist.txt -o results.json -of json
```

---

## Common Wordlists

| Path | Content |
|:-----|:--------|
| `/usr/share/seclists/Discovery/Web-Content/common.txt` | Common files/dirs |
| `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` | Larger directory list |
| `/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt` | Raft wordlist |
| `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` | Subdomains |
| `/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt` | LFI paths |

---

## Examples

```bash
# Find backup files
ffuf -u http://target.com/FUZZ -w wordlist.txt -e .bak,.old,.backup,.zip

# API endpoint discovery
ffuf -u http://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt

# LFI testing
ffuf -u "http://target.com/index.php?file=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -fs 0

# Find valid IDs
ffuf -u http://target.com/user/FUZZ -w <(seq 1 1000) -fc 404
```

---

## Comparison with Other Tools

| Tool | Speed | Features |
|:-----|:------|:---------|
| **ffuf** | Very Fast | Flexible, multiple fuzzing points |
| **gobuster** | Fast | Simple, reliable |
| **feroxbuster** | Fast | Recursive by default |
| **dirb** | Slow | Classic, simple |
| **dirbuster** | Medium | GUI available |
