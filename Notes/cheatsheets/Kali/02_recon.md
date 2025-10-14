# Kali Cheatsheet 2: Information Gathering / Reconnaissance

Collecting initial information about a target.
### whois
- **Description:** Get registration information for a domain.
- **Usage:**
  ```bash
  whois example.com
  ```

### dig
- **Description:** DNS lookup utility.
- **Usage:**
```bash
# Get A record
dig example.com

# Get MX (mail) records
dig example.com MX

# Perform a zone transfer (if allowed)
dig axfr @ns1.example.com example.com
```
### sublist3r
- **Description:** Enumerate subdomains of a domain using search engines.
- **Usage:**
```bash
sublist3r -d example.com -o subdomains.txt
```
### theHarvester
- **Description:** Gather emails, subdomains, hosts, employee names, open ports and banners from different public sources.
- **Usage:**
```bash
theharvester -d example.com -l 500 -b google,bing
```
    