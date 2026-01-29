# DNS Enumeration

Techniques for discovering DNS records and subdomains.

## Basic DNS Queries

### Using `dig`
```bash
# Query all record types
dig ANY example.com

# Specific record types
dig A example.com       # IPv4 address
dig AAAA example.com    # IPv6 address
dig MX example.com      # Mail servers
dig NS example.com      # Name servers
dig TXT example.com     # Text records (SPF, DKIM)
dig CNAME example.com   # Canonical name
dig SOA example.com     # Start of Authority

# Query specific DNS server
dig @8.8.8.8 example.com

# Short output
dig +short example.com

# Reverse lookup
dig -x 192.168.1.1
```

### Using `nslookup`
```bash
# Basic lookup
nslookup example.com

# Specific record type
nslookup -type=MX example.com

# Use specific DNS server
nslookup example.com 8.8.8.8
```

### Using `host`
```bash
host example.com
host -t MX example.com
host -t NS example.com
```

---

## Zone Transfer Attack

A misconfigured DNS server may allow zone transfers, revealing all DNS records.

```bash
# Attempt zone transfer
dig AXFR @ns1.example.com example.com

# Using host
host -l example.com ns1.example.com

# Using nslookup
nslookup
> server ns1.example.com
> ls -d example.com
```

> [!TIP]
> Zone transfers are often disabled, but always worth trying!

---

## Subdomain Enumeration

### Passive (Stealthy)
```bash
# Subfinder - fast passive enumeration
subfinder -d example.com -o subs.txt

# Amass passive mode
amass enum -passive -d example.com

# Sublist3r
sublist3r -d example.com -o subs.txt

# theHarvester
theHarvester -d example.com -b google,bing,crtsh
```

### Active (Brute Force)
```bash
# Gobuster DNS mode
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# ffuf
ffuf -u https://FUZZ.example.com -w wordlist.txt

# Amass brute force
amass enum -brute -d example.com -w wordlist.txt

# DNSRecon
dnsrecon -d example.com -t brt -D wordlist.txt
```

---

## Certificate Transparency Logs

Find subdomains from SSL certificate records:

```bash
# Using crt.sh
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Using certspotter
curl -s "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true" | jq
```

**Web Resources:**
- [crt.sh](https://crt.sh/)
- [Censys Certificates](https://search.censys.io/certificates)

---

## Useful Wordlists

| Wordlist | Location |
|:---------|:---------|
| Common subdomains | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` |
| Larger list | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt` |
| Bitquark | `/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt` |

---

## Quick Reference

```bash
# Quick subdomain discovery workflow
subfinder -d example.com -silent | httpx -silent > alive_subs.txt

# DNS enumeration with Nmap
nmap --script=dns-brute example.com
```
