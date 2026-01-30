# Wordlists

Essential password and fuzzing wordlists for penetration testing.

## Default Locations (Kali)

| Path | Description |
|:-----|:------------|
| `/usr/share/wordlists/` | Main wordlist directory |
| `/usr/share/seclists/` | SecLists collection |
| `/usr/share/wordlists/rockyou.txt` | Most popular password list |

---

## Password Lists

### RockYou (Essential)
```bash
# Location
/usr/share/wordlists/rockyou.txt

# May need to extract first
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

### SecLists Passwords
| List | Path |
|:-----|:-----|
| Common passwords | `Passwords/Common-Credentials/10-million-password-list-top-1000000.txt` |
| Top 10k | `Passwords/Common-Credentials/10k-most-common.txt` |
| Default credentials | `Passwords/Default-Credentials/` |
| Leaked databases | `Passwords/Leaked-Databases/` |

---

## Username Lists

| List | Path |
|:-----|:-----|
| Top usernames | `Usernames/top-usernames-shortlist.txt` |
| Common names | `Usernames/Names/names.txt` |

---

## Web Content Discovery

| List | Path |
|:-----|:-----|
| Common files | `Discovery/Web-Content/common.txt` |
| Directory medium | `Discovery/Web-Content/directory-list-2.3-medium.txt` |
| Raft directories | `Discovery/Web-Content/raft-medium-directories.txt` |
| Raft files | `Discovery/Web-Content/raft-medium-files.txt` |
| API endpoints | `Discovery/Web-Content/api/` |

---

## DNS/Subdomain Lists

| List | Path |
|:-----|:-----|
| Top 5000 | `Discovery/DNS/subdomains-top1million-5000.txt` |
| Top 110000 | `Discovery/DNS/subdomains-top1million-110000.txt` |
| Bitquark | `Discovery/DNS/bitquark-subdomains-top100000.txt` |

---

## Fuzzing Lists

| List | Path |
|:-----|:-----|
| LFI | `Fuzzing/LFI/LFI-gracefulsecurity-linux.txt` |
| SQLi | `Fuzzing/SQLi/` |
| XSS | `Fuzzing/XSS/` |

---

## Creating Custom Wordlists

### CeWL (Website Scraper)
```bash
# Basic scraping
cewl http://target.com -w custom.txt

# With depth and minimum length
cewl http://target.com -d 3 -m 6 -w custom.txt

# Include emails
cewl http://target.com -e --email_file emails.txt -w custom.txt
```

### Crunch (Generator)
```bash
# Generate patterns
crunch 8 8 -t @@@@%%%% -o wordlist.txt
# @ = lowercase, % = number, ^ = symbol, , = uppercase

# Generate from charset
crunch 4 6 0123456789 -o pins.txt
```

### Using Rules with Wordlists
```bash
# Hashcat with rules
hashcat --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule > mutated.txt

# John with rules
john --wordlist=input.txt --rules --stdout > mutated.txt
```

---

## Quick Install SecLists

```bash
# Kali (already installed)
apt install seclists

# Manual
git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

---

## Useful Online Resources

| Resource | URL |
|:---------|:----|
| SecLists | [github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) |
| Assetnote Wordlists | [wordlists.assetnote.io](https://wordlists.assetnote.io/) |
| FuzzDB | [github.com/fuzzdb-project](https://github.com/fuzzdb-project/fuzzdb) |
| PayloadsAllTheThings | [github.com/swisskyrepo](https://github.com/swisskyrepo/PayloadsAllTheThings) |
