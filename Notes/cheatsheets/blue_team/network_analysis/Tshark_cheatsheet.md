# Tshark Cheatsheet

Tshark is Wireshark's command-line network protocol analyzer. It's powerful for capturing and analyzing network traffic without a GUI.

---

## Basic Capture Commands

```bash
# List available interfaces
tshark -D

# Capture on specific interface
tshark -i eth0

# Capture on interface by number
tshark -i 1

# Capture with packet count limit
tshark -i eth0 -c 100

# Capture for specific duration (seconds)
tshark -i eth0 -a duration:60

# Capture to file (pcap format)
tshark -i eth0 -w capture.pcap

# Capture to file with ring buffer (5 files, 100MB each)
tshark -i eth0 -b filesize:102400 -b files:5 -w capture.pcap
```

---

## Reading Capture Files

```bash
# Read pcap file
tshark -r capture.pcap

# Read with packet limit
tshark -r capture.pcap -c 50

# Read specific packet range
tshark -r capture.pcap -Y "frame.number >= 10 && frame.number <= 20"

# Read and get summary statistics
tshark -r capture.pcap -q -z io,stat,1
```

---

## Display Filters

Display filters use Wireshark's filter syntax to select packets.

### Basic Protocol Filters
```bash
# Filter by protocol
tshark -r capture.pcap -Y "http"
tshark -r capture.pcap -Y "dns"
tshark -r capture.pcap -Y "tcp"
tshark -r capture.pcap -Y "udp"
tshark -r capture.pcap -Y "icmp"
tshark -r capture.pcap -Y "arp"
tshark -r capture.pcap -Y "ssl" # or "tls"
```

### IP Address Filters
```bash
# Filter by IP address
tshark -r capture.pcap -Y "ip.addr == 192.168.1.100"

# Filter source IP
tshark -r capture.pcap -Y "ip.src == 192.168.1.100"

# Filter destination IP
tshark -r capture.pcap -Y "ip.dst == 10.0.0.1"

# Filter IP range (subnet)
tshark -r capture.pcap -Y "ip.addr == 192.168.1.0/24"

# Exclude specific IP
tshark -r capture.pcap -Y "!(ip.addr == 192.168.1.1)"
```

### Port Filters
```bash
# Filter by port
tshark -r capture.pcap -Y "tcp.port == 80"
tshark -r capture.pcap -Y "udp.port == 53"

# Filter source port
tshark -r capture.pcap -Y "tcp.srcport == 443"

# Filter destination port
tshark -r capture.pcap -Y "tcp.dstport == 22"

# Filter port range
tshark -r capture.pcap -Y "tcp.port >= 1 && tcp.port <= 1024"
```

### Combining Filters
```bash
# AND operator
tshark -r capture.pcap -Y "ip.addr == 192.168.1.100 && tcp.port == 80"

# OR operator
tshark -r capture.pcap -Y "http || dns"

# NOT operator
tshark -r capture.pcap -Y "!arp"

# Complex filter
tshark -r capture.pcap -Y "(ip.src == 192.168.1.100 || ip.dst == 192.168.1.100) && tcp.port == 443"
```

---

## Capture Filters (BPF Syntax)

Capture filters use Berkeley Packet Filter (BPF) syntax during capture.

```bash
# Capture only specific host
tshark -i eth0 -f "host 192.168.1.100"

# Capture specific port
tshark -i eth0 -f "port 80"

# Capture specific protocol
tshark -i eth0 -f "tcp"
tshark -i eth0 -f "udp"

# Capture subnet
tshark -i eth0 -f "net 192.168.1.0/24"

# Exclude host
tshark -i eth0 -f "not host 192.168.1.1"

# Complex capture filter
tshark -i eth0 -f "tcp port 80 and host 192.168.1.100"
```

---

## Output Formatting

### Field Extraction
```bash
# Extract specific fields (-T fields)
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port

# Add header row
tshark -r capture.pcap -T fields -E header=y -e ip.src -e ip.dst

# Custom separator
tshark -r capture.pcap -T fields -E separator=, -e ip.src -e ip.dst

# Quote fields
tshark -r capture.pcap -T fields -E quote=d -e ip.src -e ip.dst
```

### Output Formats
```bash
# JSON output
tshark -r capture.pcap -T json

# JSON for Elasticsearch
tshark -r capture.pcap -T ek

# XML output
tshark -r capture.pcap -T pdml

# Plain text with full packet details
tshark -r capture.pcap -V

# One-line summary per packet
tshark -r capture.pcap -T tabs
```

---

## HTTP Analysis

```bash
# Show HTTP requests only
tshark -r capture.pcap -Y "http.request"

# Show HTTP responses only
tshark -r capture.pcap -Y "http.response"

# Filter by HTTP method
tshark -r capture.pcap -Y "http.request.method == GET"
tshark -r capture.pcap -Y "http.request.method == POST"

# Filter by URL
tshark -r capture.pcap -Y 'http.request.uri contains "/login"'

# Filter by Host header
tshark -r capture.pcap -Y 'http.host contains "example.com"'

# Filter by response code
tshark -r capture.pcap -Y "http.response.code == 200"
tshark -r capture.pcap -Y "http.response.code >= 400"

# Extract HTTP URLs
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# Extract User-Agent
tshark -r capture.pcap -Y "http.request" -T fields -e http.user_agent

# HTTP request and response statistics
tshark -r capture.pcap -q -z http,stat,
tshark -r capture.pcap -q -z http_req,tree
```

---

## DNS Analysis

```bash
# Show all DNS traffic
tshark -r capture.pcap -Y "dns"

# Show DNS queries only
tshark -r capture.pcap -Y "dns.flags.response == 0"

# Show DNS responses only
tshark -r capture.pcap -Y "dns.flags.response == 1"

# Filter by queried domain
tshark -r capture.pcap -Y 'dns.qry.name contains "example.com"'

# Extract DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name

# Extract DNS answers
tshark -r capture.pcap -Y "dns.flags.response == 1" -T fields -e dns.qry.name -e dns.a

# DNS with specific record type
tshark -r capture.pcap -Y "dns.qry.type == 1"  # A record
tshark -r capture.pcap -Y "dns.qry.type == 28" # AAAA record
tshark -r capture.pcap -Y "dns.qry.type == 5"  # CNAME
tshark -r capture.pcap -Y "dns.qry.type == 15" # MX
tshark -r capture.pcap -Y "dns.qry.type == 16" # TXT
```

---

## TCP Analysis

```bash
# Show TCP SYN packets (connection initiation)
tshark -r capture.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0"

# Show TCP RST packets (connection reset)
tshark -r capture.pcap -Y "tcp.flags.reset == 1"

# Show TCP FIN packets (connection termination)
tshark -r capture.pcap -Y "tcp.flags.fin == 1"

# Show retransmissions
tshark -r capture.pcap -Y "tcp.analysis.retransmission"

# Show duplicate ACKs
tshark -r capture.pcap -Y "tcp.analysis.duplicate_ack"

# Show zero window
tshark -r capture.pcap -Y "tcp.analysis.zero_window"

# TCP conversation statistics
tshark -r capture.pcap -q -z conv,tcp

# Follow TCP stream (stream number 0)
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```

---

## TLS/SSL Analysis

```bash
# Show TLS handshakes
tshark -r capture.pcap -Y "tls.handshake"

# Show TLS Client Hello
tshark -r capture.pcap -Y "tls.handshake.type == 1"

# Show TLS Server Hello
tshark -r capture.pcap -Y "tls.handshake.type == 2"

# Extract SNI (Server Name Indication)
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name

# Extract JA3 fingerprints
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e tls.handshake.ja3

# Extract JA3S fingerprints
tshark -r capture.pcap -Y "tls.handshake.type == 2" -T fields -e tls.handshake.ja3s

# Decrypt TLS with key log file
tshark -r capture.pcap -o "tls.keylog_file:sslkeys.log"
```

---

## Statistics and Analysis

```bash
# Protocol hierarchy statistics
tshark -r capture.pcap -q -z io,phs

# Packet length statistics
tshark -r capture.pcap -q -z plen,tree

# Endpoint statistics
tshark -r capture.pcap -q -z endpoints,ip
tshark -r capture.pcap -q -z endpoints,tcp
tshark -r capture.pcap -q -z endpoints,udp

# Conversation statistics
tshark -r capture.pcap -q -z conv,ip
tshark -r capture.pcap -q -z conv,tcp
tshark -r capture.pcap -q -z conv,udp

# I/O statistics (1-second intervals)
tshark -r capture.pcap -q -z io,stat,1

# I/O statistics with filter
tshark -r capture.pcap -q -z io,stat,1,"http","dns"

# Top talkers
tshark -r capture.pcap -q -z conv,ip -z conv,tcp | head -20

# Expert info (errors, warnings)
tshark -r capture.pcap -q -z expert
```

---

## Credential and Sensitive Data Extraction

```bash
# FTP credentials
tshark -r capture.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS" -T fields -e ftp.request.command -e ftp.request.arg

# HTTP Basic Auth
tshark -r capture.pcap -Y "http.authorization" -T fields -e http.authorization

# HTTP POST data
tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.file_data

# SMTP authentication
tshark -r capture.pcap -Y "smtp.auth.username || smtp.auth.password"

# Telnet data (cleartext)
tshark -r capture.pcap -Y "telnet" -T fields -e telnet.data
```

---

## Malware and Threat Hunting

```bash
# Unusual DNS (long domain names - potential DNS tunneling)
tshark -r capture.pcap -Y "dns && strlen(dns.qry.name) > 50" -T fields -e dns.qry.name

# Non-standard DNS ports
tshark -r capture.pcap -Y "dns && !(udp.port == 53 || tcp.port == 53)"

# ICMP data extraction (potential ICMP tunneling)
tshark -r capture.pcap -Y "icmp && icmp.type == 8" -T fields -e data

# Find potential beaconing (repeated connections)
tshark -r capture.pcap -Y "tcp.flags.syn == 1" -T fields -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn

# Detect port scanning (many SYN, few SYN-ACK)
tshark -r capture.pcap -q -z conv,tcp | awk '$5 == "0" {print}'

# Large outbound transfers (potential data exfiltration)
tshark -r capture.pcap -q -z conv,ip | sort -t'<' -k2 -rn

# HTTP requests to IP addresses (no domain)
tshark -r capture.pcap -Y 'http.request && http.host matches "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"'
```

---

## File Extraction

```bash
# Export HTTP objects
tshark -r capture.pcap --export-objects http,./extracted_files/

# Export SMB objects
tshark -r capture.pcap --export-objects smb,./extracted_files/

# Export TFTP objects
tshark -r capture.pcap --export-objects tftp,./extracted_files/

# Export DICOM objects
tshark -r capture.pcap --export-objects dicom,./extracted_files/

# Export IMF (email) objects
tshark -r capture.pcap --export-objects imf,./extracted_files/
```

---

## Useful One-Liners

```bash
# Top 10 source IPs by packet count
tshark -r capture.pcap -T fields -e ip.src | sort | uniq -c | sort -rn | head -10

# Top 10 destination IPs by packet count
tshark -r capture.pcap -T fields -e ip.dst | sort | uniq -c | sort -rn | head -10

# Top 10 DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -10

# Top 10 HTTP hosts
tshark -r capture.pcap -Y "http.request" -T fields -e http.host | sort | uniq -c | sort -rn | head -10

# Top 10 User-Agents
tshark -r capture.pcap -Y "http.request" -T fields -e http.user_agent | sort | uniq -c | sort -rn | head -10

# Connections per minute
tshark -r capture.pcap -Y "tcp.flags.syn == 1" -T fields -e frame.time | cut -d':' -f1-2 | uniq -c

# Extract all IP addresses (unique)
tshark -r capture.pcap -T fields -e ip.src -e ip.dst | tr '\t' '\n' | sort -u

# Timeline of connections
tshark -r capture.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport
```

---

## Live Capture + Processing

```bash
# Live capture with immediate display filter
tshark -i eth0 -Y "http.request" -f "port 80"

# Live capture to file with rotation (10 files, 100MB each)
tshark -i eth0 -b filesize:102400 -b files:10 -w /var/log/capture/traffic.pcap

# Capture and pipe to grep for specific content
tshark -i eth0 -l | grep -i "password"

# Live traffic statistics (refresh every second)
tshark -i eth0 -q -z io,stat,1

# Live DNS monitoring
tshark -i eth0 -f "udp port 53" -T fields -e frame.time -e ip.src -e dns.qry.name

# Live HTTP URL monitoring
tshark -i eth0 -f "tcp port 80" -Y "http.request" -T fields -e frame.time -e http.host -e http.request.uri
```

---

## Remote Capture

```bash
# Capture from remote host via SSH
ssh user@remote "tshark -i eth0 -c 1000 -w -" > capture.pcap

# Capture from remote host and analyze locally
ssh user@remote "tshark -i eth0 -w -" | tshark -i -

# Remote capture with compression
ssh user@remote "tshark -i eth0 -w - | gzip" > capture.pcap.gz
```

---

## Configuration and Options

```bash
# Use specific profile
tshark -C my_profile

# Set preference
tshark -o "tcp.desegment_tcp_streams:TRUE"

# Disable name resolution
tshark -n

# Enable all name resolutions
tshark -N mnNtdv

# Set snapshot length (capture only first N bytes per packet)
tshark -i eth0 -s 96

# Verbose output
tshark -V

# Show hex dump
tshark -x
```

---

## Quick Reference Table

| Task | Command |
|------|---------|
| List interfaces | `tshark -D` |
| Capture on interface | `tshark -i eth0` |
| Read pcap file | `tshark -r file.pcap` |
| Apply display filter | `tshark -r file.pcap -Y "filter"` |
| Apply capture filter | `tshark -i eth0 -f "filter"` |
| Write to file | `tshark -i eth0 -w output.pcap` |
| Extract fields | `tshark -r file.pcap -T fields -e field.name` |
| JSON output | `tshark -r file.pcap -T json` |
| Statistics | `tshark -r file.pcap -q -z stat_type` |
| Follow stream | `tshark -r file.pcap -q -z follow,tcp,ascii,0` |
| Export files | `tshark -r file.pcap --export-objects http,dir/` |

---

## Common Display Filter Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `==` | Equals | `ip.addr == 10.0.0.1` |
| `!=` | Not equals | `ip.addr != 10.0.0.1` |
| `>`, `<`, `>=`, `<=` | Comparison | `frame.len > 100` |
| `contains` | Contains string | `http.host contains "google"` |
| `matches` | Regex match | `http.host matches ".*\.com$"` |
| `&&` / `and` | Logical AND | `tcp && ip.src == 10.0.0.1` |
| `\|\|` / `or` | Logical OR | `tcp || udp` |
| `!` / `not` | Logical NOT | `!arp` |
| `in` | In set | `tcp.port in {80, 443, 8080}` |

---

## Resources

- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html/)
- [Tshark Man Page](https://www.wireshark.org/docs/man-pages/tshark.html)
- [BPF Capture Filter Syntax](https://biot.com/capstats/bpf.html)
