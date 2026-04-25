# Gobuster

Fast brute-force discovery tool written in Go. Used for **directories/files**, **DNS subdomains**, **virtual hosts**, **cloud buckets**, and **generic fuzzing**. Simple, reliable, and the de-facto starting point for web/DNS enumeration alongside [[ffuf]].

> **Phase:** Reconnaissance / Web Application
> **Sibling tool:** [[ffuf]] — more flexible, multi-point fuzzing
> **Related notes:** [[DNS_Enumeration]], [[SMB_Enumeration]], [[Getting_Started]]

---

## Installation

```bash
# Debian / Kali
sudo apt install gobuster

# Go (latest)
go install github.com/OJ/gobuster/v3@latest

# Verify
gobuster version
```

---

## Modes Overview

| Mode | Purpose | Typical use |
|:-----|:--------|:------------|
| `dir` | Directory & file brute-force | Web content discovery |
| `dns` | Subdomain brute-force | Recon — see [[DNS_Enumeration]] |
| `vhost` | Virtual host brute-force | Discover sites on shared IP |
| `fuzz` | Generic fuzzing with `FUZZ` keyword | Parameter / path fuzzing |
| `s3` | AWS S3 bucket brute-force | Cloud recon |
| `gcs` | GCS bucket brute-force | Cloud recon |
| `tftp` | TFTP file brute-force | Niche / embedded systems |

```bash
gobuster <mode> [options]
gobuster dir --help     # per-mode help
```

---

## Directory & File Discovery (`dir`)

```bash
# Basic
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt

# With file extensions
gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt,bak

# Show only specific status codes
gobuster dir -u http://target.com -w wordlist.txt -s "200,204,301,302,307,401,403"

# Add headers / cookie / auth
gobuster dir -u http://target.com -w wordlist.txt \
  -H "User-Agent: Mozilla/5.0" \
  -c "session=abc123" \
  -U admin -P password
```

### Useful `dir` flags

| Flag | Description |
|:-----|:------------|
| `-u` | Target URL |
| `-w` | Wordlist |
| `-x` | Extensions to append (`php,html,txt`) |
| `-s` | Status codes to include (whitelist) |
| `-b` | Status codes to exclude (blacklist, default `404`) |
| `-t` | Threads (default `10`) |
| `-k` | Skip TLS verification |
| `-r` | Follow redirects |
| `-e` | Expanded mode — print full URL |
| `-n` | No status codes in output |
| `-f` | Add trailing `/` to each request |
| `--exclude-length` | Hide responses with N bytes (filter dynamic 200s) |
| `-H` | Custom header |
| `-c` | Cookie |
| `-U` / `-P` | HTTP basic auth user/pass |
| `--proxy` | Send through proxy (`http://127.0.0.1:8080`) |

---

## DNS Subdomain Brute-force (`dns`)

```bash
# Basic
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Show IPs of resolved hosts
gobuster dns -d example.com -w wordlist.txt -i

# Custom resolver (avoid ISP DNS)
gobuster dns -d example.com -w wordlist.txt -r 1.1.1.1

# Wildcard handling
gobuster dns -d example.com -w wordlist.txt --wildcard
```

| Flag | Description |
|:-----|:------------|
| `-d` | Target domain |
| `-w` | Subdomain wordlist |
| `-i` | Show resolved IPs |
| `-r` | Custom DNS resolver |
| `--wildcard` | Force run even if wildcard DNS detected |
| `-c` | Show CNAME records |
| `--timeout` | DNS query timeout |

> See [[DNS_Enumeration]] for the broader DNS recon workflow.

---

## Virtual Host Discovery (`vhost`)

Finds vhosts served by the same web server (different `Host:` header → different content).

```bash
# Basic vhost discovery
gobuster vhost -u http://target.com -w subdomains.txt

# Append the parent domain to each guess
gobuster vhost -u http://target.com -w subdomains.txt --append-domain

# Filter by response length (drop default vhost size)
gobuster vhost -u http://target.com -w subdomains.txt --exclude-length 1234
```

> **Difference from `dns`:** `vhost` does HTTP requests with varied `Host:` headers; `dns` resolves names via DNS. A subdomain may exist as a vhost without a DNS record.

---

## Generic Fuzzing (`fuzz`)

Acts like a lightweight [[ffuf]] — replace `FUZZ` in the URL.

```bash
# Path fuzzing
gobuster fuzz -u http://target.com/FUZZ -w wordlist.txt

# Parameter name fuzzing
gobuster fuzz -u "http://target.com/page?FUZZ=test" -w params.txt

# Hide responses by length
gobuster fuzz -u http://target.com/FUZZ -w wordlist.txt --exclude-length 0,1234
```

For anything more complex (multiple fuzz points, recursion, regex matchers) reach for [[ffuf]] instead.

---

## Cloud Bucket Discovery (`s3` / `gcs`)

```bash
# AWS S3 buckets
gobuster s3 -w bucket-names.txt

# Google Cloud Storage
gobuster gcs -w bucket-names.txt

# Show only existing buckets
gobuster s3 -w bucket-names.txt --maxfiles 5
```

Useful when the target's domain hints at cloud storage (`assets.target.com`, `cdn-target`, …).

---

## Output

```bash
# Plain text
gobuster dir -u http://target.com -w wordlist.txt -o results.txt

# Quiet mode (good for piping)
gobuster dir -u http://target.com -w wordlist.txt -q

# No progress bar (clean log files)
gobuster dir -u http://target.com -w wordlist.txt --no-progress

# Coloured / no-colour
gobuster dir -u http://target.com -w wordlist.txt --no-color
```

> Unlike [[ffuf]], gobuster does **not** support JSON/CSV output natively — pipe `-q` output through `awk`/`jq`-friendly parsers if you need structured results.

---

## Performance & Stealth

| Flag | Description |
|:-----|:------------|
| `-t <n>` | Threads (default `10`, raise to 50–100 on stable targets) |
| `--delay <dur>` | Delay between requests (`100ms`, `1s`) |
| `--timeout <dur>` | Request timeout (default `10s`) |
| `--retry` | Retry on timeout |
| `--retry-attempts <n>` | Number of retries |

```bash
# Aggressive
gobuster dir -u http://target.com -w big.txt -t 100

# Stealthy
gobuster dir -u http://target.com -w big.txt -t 5 --delay 500ms
```

---

## Wordlists

| Path | Purpose |
|:-----|:--------|
| `/usr/share/seclists/Discovery/Web-Content/common.txt` | Quick first pass |
| `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` | Standard medium dirs |
| `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt` | Raft dirs |
| `/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt` | Raft files |
| `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` | Fast subdomain pass |
| `/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt` | Deep subdomain pass |
| `/usr/share/wordlists/dirb/common.txt` | Tiny dirb fallback |
| `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` | Classic dirbuster list |

```bash
# Update SecLists if missing
sudo apt install seclists
# or
git clone https://github.com/danielmiessler/SecLists /usr/share/seclists
```

---

## Practical Examples

```bash
# 1) Full web content sweep with extensions and 403 visible
gobuster dir -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,txt,bak,old,zip \
  -s "200,204,301,302,307,401,403" \
  -t 50 -k

# 2) Subdomain enum with custom resolver and IP output
gobuster dns -d target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -r 1.1.1.1 -i -t 50

# 3) Vhost discovery on a single IP serving multiple sites
gobuster vhost -u http://10.10.10.10 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain --exclude-length 0

# 4) Authenticated dir scan through Burp
gobuster dir -u https://app.target.com \
  -w wordlist.txt \
  -c "PHPSESSID=abcdef" \
  --proxy http://127.0.0.1:8080 -k

# 5) Find backup files
gobuster dir -u http://target.com -w common.txt -x bak,old,backup,zip,tar.gz
```

---

## Common Pitfalls

- **Wildcard responses** — site returns `200` for everything. Use `--exclude-length` or switch to [[ffuf]] with `-fs`.
- **Rate limiting / WAF** — drop threads, add `--delay`, rotate `User-Agent` via `-H`.
- **Trailing slash mismatch** — try `-f` to force trailing `/`.
- **TLS errors on self-signed targets** — add `-k`.
- **DNS wildcard domain** — gobuster aborts unless `--wildcard` is set; verify manually first (`dig random123.target.com`).
- **No JSON output** — use [[ffuf]] (`-of json`) when you need machine-readable results.

---

## Comparison with Related Tools

| Tool | Speed | Strengths | Weaknesses |
|:-----|:------|:----------|:-----------|
| **gobuster** | Fast | Simple, reliable, multi-mode (dir/dns/vhost/cloud) | No recursion, no JSON output |
| [[ffuf]] | Very fast | Flexible, multi-point fuzzing, rich filtering, JSON | Slightly steeper learning curve |
| **feroxbuster** | Fast | Recursive by default, resume support | Less flexible filters |
| **dirb** | Slow | Classic, zero-config | Outdated, slow |
| **dirbuster** | Medium | GUI | Java, clunky |
| **wfuzz** | Medium | Very flexible | Older, slower than ffuf |

---

## Quick Reference Card

```bash
# Dirs
gobuster dir   -u <url>    -w <wl>  -x php,html,txt -t 50 -k
# Subdomains
gobuster dns   -d <domain> -w <wl>  -i -r 1.1.1.1
# Virtual hosts
gobuster vhost -u <url>    -w <wl>  --append-domain --exclude-length <n>
# Generic fuzz
gobuster fuzz  -u <url/FUZZ> -w <wl>
# Cloud
gobuster s3    -w <bucket-wl>
```

---

## See Also

- [[ffuf]] — when you need flexibility, recursion, or JSON output
- [[DNS_Enumeration]] — full DNS recon workflow
- [[SMB_Enumeration]] — pairs well after vhost discovery on internal targets
- [[Nmap]] — service discovery before web brute-forcing
- [[Getting_Started]] — where gobuster fits in the kill-chain
