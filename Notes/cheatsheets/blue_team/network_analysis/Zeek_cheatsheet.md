# Zeek Cheatsheet

Zeek (formerly Bro) is a powerful network security monitoring framework. Unlike packet capture tools, Zeek analyzes network traffic and generates rich, structured logs describing network activity.

---

## Installation and Setup

```bash
# Install on Debian/Ubuntu
sudo apt install zeek

# Install on RHEL/CentOS
sudo yum install zeek

# Verify installation
zeek --version

# Common installation paths
/opt/zeek/bin/      # Binaries
/opt/zeek/logs/     # Logs
/opt/zeek/share/zeek/  # Scripts
/opt/zeek/etc/      # Configuration
```

---

## Basic Usage

```bash
# Analyze pcap file (creates logs in current directory)
zeek -r capture.pcap

# Analyze with specific scripts
zeek -r capture.pcap local

# Analyze with custom script
zeek -r capture.pcap myscript.zeek

# Live capture on interface
sudo zeek -i eth0

# Live capture with local policy
sudo zeek -i eth0 local
```

---

## Output Log Files

Zeek generates multiple log files, each focusing on specific protocol or activity:

### Connection Logs

| Log File | Description |
|----------|-------------|
| `conn.log` | All connections (TCP, UDP, ICMP) |
| `ssl.log` | SSL/TLS handshakes |
| `x509.log` | X.509 certificates |
| `dns.log` | DNS queries and responses |
| `http.log` | HTTP requests and responses |
| `ftp.log` | FTP activity |
| `smtp.log` | SMTP transactions |
| `ssh.log` | SSH connections |
| `rdp.log` | RDP connections |
| `smb_*.log` | SMB/CIFS activity |
| `dhcp.log` | DHCP transactions |
| `ntp.log` | NTP activity |
| `kerberos.log` | Kerberos authentication |
| `ntlm.log` | NTLM authentication |
| `sip.log` | SIP (VoIP) |
| `snmp.log` | SNMP activity |

### Files and Analysis

| Log File | Description |
|----------|-------------|
| `files.log` | Files observed in network traffic |
| `pe.log` | Portable Executable (PE) file analysis |
| `software.log` | Software detected on network |
| `weird.log` | Unusual/unexpected network behavior |
| `notice.log` | Security-relevant notices |
| `intel.log` | Intelligence framework matches |
| `known_*.log` | Known services, hosts, certs |

---

## Log Format

Zeek logs are tab-separated values (TSV) with a header. Example `conn.log`:

```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	...
1234567890.123456	CHhAvVGS1DHFjwGM9	192.168.1.100	52424	93.184.216.34	80	tcp	http	0.5	...
```

### Common Fields

| Field | Description |
|-------|-------------|
| `ts` | Timestamp (Unix epoch) |
| `uid` | Unique connection identifier |
| `id.orig_h` | Originating host IP |
| `id.orig_p` | Originating port |
| `id.resp_h` | Responding host IP |
| `id.resp_p` | Responding port |
| `proto` | Protocol (tcp, udp, icmp) |
| `service` | Detected service |
| `duration` | Connection duration |

---

## Reading Logs with zeek-cut

`zeek-cut` extracts specific fields from Zeek logs:

```bash
# Extract specific columns
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p

# With timestamps in readable format
cat conn.log | zeek-cut -d ts id.orig_h id.resp_h

# Extract from DNS log
cat dns.log | zeek-cut query answers

# Extract HTTP requests
cat http.log | zeek-cut host uri user_agent

# Count connections per destination
cat conn.log | zeek-cut id.resp_h | sort | uniq -c | sort -rn | head -20

# Find top talkers
cat conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -rn | head -10

# Unique DNS queries
cat dns.log | zeek-cut query | sort -u
```

---

## Connection Analysis (conn.log)

```bash
# All connections to specific port
grep "	80	tcp" conn.log

# Long duration connections (potential C2)
cat conn.log | zeek-cut duration id.orig_h id.resp_h | awk '$1 > 3600'

# Large data transfers
cat conn.log | zeek-cut orig_bytes resp_bytes id.orig_h id.resp_h | awk '$1 > 1000000 || $2 > 1000000'

# Connections with specific protocol
cat conn.log | zeek-cut service id.orig_h id.resp_h | grep "http"

# Failed connections (no response)
cat conn.log | zeek-cut conn_state id.orig_h id.resp_h id.resp_p | grep "S0"

# Connection states
# S0 - SYN, no reply
# S1 - Established, not terminated
# SF - Normal establishment and termination
# REJ - Rejected
# S2 - Established, responder sent FIN
# S3 - Established, originator sent FIN
# RSTO - Established, reset by originator
# RSTR - Established, reset by responder
```

---

## DNS Analysis (dns.log)

```bash
# All DNS queries
cat dns.log | zeek-cut query

# DNS queries with responses
cat dns.log | zeek-cut query answers

# TXT record queries (potential DNS tunneling)
cat dns.log | zeek-cut qtype_name query | grep "TXT"

# Long DNS queries (potential tunneling)
cat dns.log | zeek-cut query | awk 'length($0) > 50'

# NXDOMAIN responses (potential DGA)
cat dns.log | zeek-cut rcode_name query | grep "NXDOMAIN"

# Queries to specific TLD
cat dns.log | zeek-cut query | grep "\.ru$"

# Top queried domains
cat dns.log | zeek-cut query | sort | uniq -c | sort -rn | head -20
```

---

## HTTP Analysis (http.log)

```bash
# All HTTP requests
cat http.log | zeek-cut method host uri

# POST requests (potential data exfiltration)
cat http.log | zeek-cut method host uri | grep "POST"

# User-Agents
cat http.log | zeek-cut user_agent | sort | uniq -c | sort -rn

# Specific User-Agent
cat http.log | zeek-cut host uri user_agent | grep -i "curl\|wget\|python"

# HTTP response codes
cat http.log | zeek-cut status_code | sort | uniq -c | sort -rn

# Large downloads
cat http.log | zeek-cut response_body_len host uri | awk '$1 > 1000000'

# Requests to IP addresses (no domain)
cat http.log | zeek-cut host | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'

# Executable downloads
cat http.log | zeek-cut resp_mime_types uri | grep "executable"
```

---

## SSL/TLS Analysis (ssl.log)

```bash
# All SSL connections
cat ssl.log | zeek-cut server_name

# SSL versions used
cat ssl.log | zeek-cut version | sort | uniq -c

# Self-signed or expired certs (check validation_status)
cat ssl.log | zeek-cut validation_status server_name | grep -v "ok"

# JA3 fingerprints
cat ssl.log | zeek-cut ja3 id.orig_h

# JA3S fingerprints
cat ssl.log | zeek-cut ja3s id.resp_h

# Connections without SNI
cat ssl.log | zeek-cut server_name id.resp_h | grep "^-"

# Certificate subjects
cat x509.log | zeek-cut certificate.subject
```

---

## Files Analysis (files.log)

```bash
# All observed files
cat files.log | zeek-cut mime_type filename

# Executable files
cat files.log | zeek-cut mime_type filename | grep -i "executable\|x-dosexec"

# Files with specific extension
cat files.log | zeek-cut filename | grep -i "\.exe$\|\.dll$\|\.ps1$"

# File hashes
cat files.log | zeek-cut md5 sha1 sha256 filename

# Large files
cat files.log | zeek-cut total_bytes filename | awk '$1 > 1000000'

# Files from specific source
cat files.log | zeek-cut tx_hosts mime_type | grep "192.168.1.100"
```

---

## Notice Log (notice.log)

```bash
# All notices (security events)
cat notice.log | zeek-cut note msg

# Specific notice types
cat notice.log | zeek-cut note | sort | uniq -c

# SSL certificate issues
cat notice.log | zeek-cut note msg | grep -i "ssl\|certificate"

# Scan detection
cat notice.log | zeek-cut note msg | grep -i "scan"
```

---

## Weird Log (weird.log)

```bash
# All anomalies
cat weird.log | zeek-cut name id.orig_h id.resp_h

# Count by anomaly type
cat weird.log | zeek-cut name | sort | uniq -c | sort -rn

# Common weird events:
# - bad_TCP_checksum
# - data_before_established
# - possible_split_routing
# - truncated_header
# - inappropriate_FIN
```

---

## Intel Framework

Match traffic against threat intelligence:

```bash
# Create intel file (intel.dat)
# Format: indicator, indicator_type, meta.source, meta.desc
# echo -e "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc" > intel.dat
# echo -e "evil.com\tIntel::DOMAIN\tmy_feed\tMalicious domain" >> intel.dat

# Run with intel framework
zeek -r capture.pcap local Intel/seen/where-locations.zeek

# Check intel hits
cat intel.log | zeek-cut indicator id.orig_h id.resp_h

# Indicator types:
# Intel::ADDR - IP address
# Intel::DOMAIN - Domain name
# Intel::URL - URL
# Intel::SOFTWARE - Software name
# Intel::EMAIL - Email address
# Intel::FILE_HASH - File hash (MD5, SHA1, SHA256)
# Intel::CERT_HASH - Certificate hash
```

---

## Zeek Scripts

### Basic Script Structure

```zeek
# myscript.zeek
@load base/frameworks/notice

event connection_established(c: connection) {
    if (c$id$resp_p == 4444/tcp) {
        NOTICE([
            $note=Weird::Activity,
            $msg=fmt("Connection to suspicious port 4444: %s -> %s",
                     c$id$orig_h, c$id$resp_h),
            $conn=c
        ]);
    }
}
```

### Run Custom Script

```bash
zeek -r capture.pcap myscript.zeek
```

### Useful Built-in Scripts

```bash
# Load local policy (recommended baseline)
zeek -r capture.pcap local

# File extraction
zeek -r capture.pcap local "FileExtract::prefix=./extracted"

# Hash all files
zeek -r capture.pcap frameworks/files/hash-all-files

# Extract executable files
zeek -r capture.pcap frameworks/files/extract-all-files
```

---

## File Extraction

```bash
# Enable file extraction with script
zeek -r capture.pcap local "FileExtract::prefix=./extracted"

# Or use extract-all-files (extracts everything)
zeek -r capture.pcap frameworks/files/extract-all-files

# Files are saved to extract_files/ directory by default
ls extract_files/

# Check what was extracted
cat files.log | zeek-cut extracted filename mime_type
```

---

## Zeekctl (Cluster Management)

```bash
# Deploy configuration
zeekctl deploy

# Check status
zeekctl status

# Start Zeek
zeekctl start

# Stop Zeek
zeekctl stop

# Restart
zeekctl restart

# Check for issues
zeekctl diag

# View current configuration
zeekctl config
```

---

## One-Liners for Threat Hunting

```bash
# Potential beaconing (regular interval connections)
cat conn.log | zeek-cut ts id.orig_h id.resp_h | sort -k2,3 | uniq -c | awk '$1 > 50'

# Unusual ports
cat conn.log | zeek-cut id.resp_p | sort | uniq -c | sort -rn | tail -20

# Long DNS names (tunneling)
cat dns.log | zeek-cut query | awk 'length($0) > 60'

# Non-standard HTTP ports
cat http.log | zeek-cut id.resp_p | grep -v "^80$\|^8080$\|^443$"

# SSH brute force attempts
cat ssh.log | zeek-cut auth_attempts id.orig_h | awk '$1 > 3'

# Failed SSL/TLS (crypto issues or interception)
cat ssl.log | zeek-cut established | grep "F"

# Outbound SMB (lateral movement)
cat smb_mapping.log | zeek-cut id.orig_h path

# PowerShell in HTTP
cat http.log | zeek-cut uri | grep -i "powershell\|IEX\|downloadstring"

# Base64 in DNS queries
cat dns.log | zeek-cut query | grep -E '[A-Za-z0-9+/=]{20,}'
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Analyze pcap | `zeek -r capture.pcap` |
| Live capture | `sudo zeek -i eth0` |
| With local policy | `zeek -r capture.pcap local` |
| Extract fields | `cat log.log \| zeek-cut field1 field2` |
| Readable timestamps | `cat log.log \| zeek-cut -d ts ...` |
| Extract files | Scripts: `extract-all-files` or `FileExtract` |
| Use intel | Load intel framework + intel.dat |
| Custom script | `zeek -r capture.pcap myscript.zeek` |

---

## Log Field Quick Reference

### conn.log Key Fields
| Field | Description |
|-------|-------------|
| `uid` | Unique ID (correlate across logs) |
| `id.orig_h/p` | Source IP/Port |
| `id.resp_h/p` | Destination IP/Port |
| `proto` | Protocol |
| `service` | Detected service |
| `duration` | Connection length |
| `orig_bytes` | Bytes from source |
| `resp_bytes` | Bytes from destination |
| `conn_state` | Final connection state |

### dns.log Key Fields
| Field | Description |
|-------|-------------|
| `query` | DNS query |
| `qtype_name` | Query type (A, AAAA, TXT, etc.) |
| `answers` | DNS response |
| `rcode_name` | Response code |

### http.log Key Fields
| Field | Description |
|-------|-------------|
| `method` | HTTP method |
| `host` | HTTP Host header |
| `uri` | Request URI |
| `user_agent` | User-Agent header |
| `status_code` | Response status |
| `resp_mime_types` | Response MIME type |

---

## Resources

- [Zeek Documentation](https://docs.zeek.org/)
- [Zeek Script Reference](https://docs.zeek.org/en/current/script-reference/)
- [Zeek Log Formats](https://docs.zeek.org/en/current/script-reference/log-files.html)
- [CORELIGHT Zeek Cheatsheet](https://github.com/corelight/bro-cheatsheets)
