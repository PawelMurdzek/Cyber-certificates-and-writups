# Wireshark Cheatsheet

Wireshark is a GUI-based network protocol analyzer. It provides deep inspection of hundreds of protocols and powerful filtering capabilities.

---

## Interface and Capture

### Starting a Capture
1. **Select Interface**: Choose from the interface list on the main screen
2. **Start Capture**: Click the blue shark fin button or `Ctrl+E`
3. **Stop Capture**: Click the red square button or `Ctrl+E`

### Capture Options (`Ctrl+K`)

| Option | Description |
|--------|-------------|
| **Interface** | Select network interface to capture |
| **Promiscuous Mode** | Capture all packets, not just those addressed to your machine |
| **Capture Filter** | BPF filter applied during capture (reduces file size) |
| **Output File** | Save capture directly to file |
| **Ring Buffer** | Rotate through multiple files |

### Capture Filters (BPF Syntax)

Applied **during** capture to limit what's captured:

```
host 192.168.1.100
port 80
tcp
net 10.0.0.0/8
not broadcast
host 192.168.1.1 and port 443
```

---

## Display Filters

Applied **after** capture to filter displayed packets. Much more powerful than capture filters.

### Basic Syntax
```
# Protocol
http
dns
tcp
udp
icmp
arp

# Field comparison
ip.addr == 192.168.1.100
ip.src == 10.0.0.1
ip.dst == 172.16.0.1
tcp.port == 80
tcp.srcport == 443
tcp.dstport == 22
udp.port == 53

# String matching
http.host contains "google"
http.request.uri contains "/login"
dns.qry.name contains "evil"
```

### Comparison Operators

| Operator | Meaning | Example |
|----------|---------|---------|
| `==` or `eq` | Equal | `ip.addr == 10.0.0.1` |
| `!=` or `ne` | Not equal | `ip.addr != 10.0.0.1` |
| `>` or `gt` | Greater than | `frame.len > 1000` |
| `<` or `lt` | Less than | `frame.len < 100` |
| `>=` or `ge` | Greater/equal | `tcp.port >= 1024` |
| `<=` or `le` | Less/equal | `ip.ttl <= 10` |
| `contains` | Contains string | `http.host contains "test"` |
| `matches` | Regex match | `http.host matches ".*\.com$"` |
| `in` | In set | `tcp.port in {80, 443, 8080}` |

### Logical Operators

| Operator | Meaning | Example |
|----------|---------|---------|
| `&&` or `and` | AND | `ip.addr == 10.0.0.1 && tcp` |
| `\|\|` or `or` | OR | `tcp.port == 80 \|\| tcp.port == 443` |
| `!` or `not` | NOT | `!arp` |

### Common Display Filters

```
# IP Filters
ip.addr == 192.168.1.0/24
ip.src == 10.0.0.1 && ip.dst == 10.0.0.2
!(ip.addr == 192.168.1.1)

# TCP Filters
tcp.flags.syn == 1 && tcp.flags.ack == 0    # SYN only
tcp.flags.reset == 1                         # RST packets
tcp.flags.fin == 1                           # FIN packets
tcp.analysis.retransmission                  # Retransmissions
tcp.analysis.duplicate_ack                   # Duplicate ACKs
tcp.analysis.zero_window                     # Zero window

# HTTP Filters
http.request                                  # HTTP requests
http.response                                 # HTTP responses
http.request.method == "GET"
http.request.method == "POST"
http.response.code == 200
http.response.code >= 400                    # Errors
http.host contains "example.com"
http.request.uri contains "/api"
http.user_agent contains "Mozilla"

# DNS Filters
dns.flags.response == 0                      # Queries
dns.flags.response == 1                      # Responses
dns.qry.name contains "suspicious"
dns.qry.type == 1                            # A records
dns.qry.type == 28                           # AAAA records

# TLS/SSL Filters
tls.handshake.type == 1                      # Client Hello
tls.handshake.type == 2                      # Server Hello
tls.handshake.extensions_server_name         # SNI

# FTP Filters
ftp.request.command == "USER"
ftp.request.command == "PASS"

# SMB Filters
smb || smb2
smb2.cmd == 5                                # Create
```

---

## Following Streams

Right-click a packet → **Follow** → Select stream type:

| Stream Type | Description |
|-------------|-------------|
| **TCP Stream** | Follow entire TCP conversation |
| **UDP Stream** | Follow UDP conversation |
| **TLS Stream** | Follow decrypted TLS (if keys available) |
| **HTTP Stream** | Follow HTTP request/response |
| **HTTP/2 Stream** | Follow HTTP/2 stream |

**Keyboard Shortcut**: Select packet, then `Ctrl+Alt+Shift+T` (TCP Stream)

---

## Statistics Menu

### Conversations (`Statistics → Conversations`)
View all conversations grouped by:
- Ethernet (MAC addresses)
- IPv4/IPv6 (IP addresses)
- TCP (IP:Port pairs)
- UDP (IP:Port pairs)

### Endpoints (`Statistics → Endpoints`)
List all unique endpoints:
- IP addresses
- MAC addresses
- With packet/byte counts

### Protocol Hierarchy (`Statistics → Protocol Hierarchy`)
Breakdown of all protocols in the capture with percentages.

### I/O Graphs (`Statistics → I/O Graphs`)
Visualize traffic over time with customizable filters.

### HTTP Statistics
- `Statistics → HTTP → Packet Counter`
- `Statistics → HTTP → Requests`
- `Statistics → HTTP → Load Distribution`

### DNS Statistics
- `Statistics → DNS`

---

## Expert Info (`Analyze → Expert Information`)

Shows issues found in the capture:

| Severity | Description |
|----------|-------------|
| **Error** | Serious problems (malformed packets, checksum errors) |
| **Warning** | Notable issues (retransmissions, out-of-order) |
| **Note** | Informational (connection setup/teardown) |
| **Chat** | Normal protocol operations |

---

## Coloring Rules

### Built-in Colors

| Color | Typical Meaning |
|-------|-----------------|
| Light purple | TCP |
| Light blue | UDP |
| Light green | HTTP |
| Yellow | SMB/CIFS |
| Red | TCP problems (RST, errors) |
| Black w/ red text | Malformed packets |

### Custom Coloring
`View → Coloring Rules` - Create custom rules based on display filters.

---

## Useful Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+E` | Start/Stop capture |
| `Ctrl+K` | Capture options |
| `Ctrl+F` | Find packet |
| `Ctrl+G` | Go to packet number |
| `Ctrl+N` | Next packet |
| `Ctrl+B` | Previous packet |
| `Ctrl+M` | Mark/Unmark packet |
| `Ctrl+Shift+M` | Go to next marked packet |
| `Ctrl+Right` | Next packet in conversation |
| `Ctrl+Left` | Previous packet in conversation |
| `/` | Apply display filter |
| `Ctrl+Shift+O` | Export objects |

---

## File Operations

### Export Objects (`File → Export Objects`)
Extract files transferred via:
- HTTP
- SMB
- TFTP
- DICOM
- IMF (email)

### Export Packet Dissections
- `File → Export Packet Dissections → As Plain Text`
- `File → Export Packet Dissections → As CSV`
- `File → Export Packet Dissections → As JSON`
- `File → Export Packet Dissections → As XML`

### Save Filtered Packets
`File → Export Specified Packets` - Save only displayed packets to new file.

---

## Decryption

### TLS/SSL Decryption
1. **Pre-Master Secret Log File**:
   - `Edit → Preferences → Protocols → TLS`
   - Set `(Pre)-Master-Secret log filename` to your key log file

2. **Private Key** (RSA only, no forward secrecy):
   - `Edit → Preferences → Protocols → TLS → RSA keys list`

### WPA/WPA2 Decryption
1. `Edit → Preferences → Protocols → IEEE 802.11`
2. Add decryption keys (WPA password or PSK)
3. Ensure you captured the 4-way handshake

---

## Packet Marking and Comments

| Action | Method |
|--------|--------|
| **Mark Packet** | `Ctrl+M` or right-click → Mark/Unmark |
| **Add Comment** | Right-click → Packet Comment |
| **Find Marked** | `Ctrl+Shift+M` |
| **Export Marked** | Use filter `frame.marked == 1` |

---

## Name Resolution (`View → Name Resolution`)

| Option | Description |
|--------|-------------|
| **Resolve MAC Addresses** | Show vendor names |
| **Resolve Network Addresses** | DNS reverse lookup |
| **Resolve Transport Addresses** | Show service names (e.g., "http" for 80) |

---

## Profiles

Create custom profiles for different analysis scenarios:

`Edit → Configuration Profiles`

Each profile can have:
- Different coloring rules
- Different column layouts
- Different filter buttons
- Different preferences

---

## Threat Hunting Filters

```
# Potential port scanning
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Large DNS queries (DNS tunneling)
dns && frame.len > 150

# Non-standard DNS ports
dns && !(udp.port == 53 || tcp.port == 53)

# ICMP data (ICMP tunneling)
icmp && data.len > 48

# HTTP to IP addresses (no domain)
http.request && http.host matches "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"

# Unusual User-Agent
http.user_agent contains "curl" || http.user_agent contains "wget"

# Cleartext credentials
ftp.request.command == "PASS" || http.authorization

# PowerShell download cradles
http.request.uri contains "IEX" || http.request.uri contains "powershell"

# Potential beaconing (look for regular intervals in I/O graph)
ip.dst == <suspicious_ip>
```

---

## Command Line Options

```bash
# Open file directly
wireshark capture.pcap

# Open with display filter
wireshark -r capture.pcap -Y "http"

# Open with specific profile
wireshark -C "My Profile"

# Start capture immediately
wireshark -i eth0 -k

# Start capture with filter
wireshark -i eth0 -f "port 80" -k

# Capture for duration and save
wireshark -i eth0 -a duration:60 -w output.pcap -k
```

---

## Quick Reference

| Task | Method |
|------|--------|
| Start capture | Shark fin button or `Ctrl+E` |
| Stop capture | Red square or `Ctrl+E` |
| Apply filter | Type in filter bar, press Enter |
| Clear filter | Click X in filter bar |
| Follow stream | Right-click → Follow → TCP Stream |
| Find packet | `Ctrl+F` |
| Go to packet | `Ctrl+G` |
| Expert info | `Analyze → Expert Information` |
| Conversations | `Statistics → Conversations` |
| Export files | `File → Export Objects` |
| Packet details | Expand in middle pane |
| Packet bytes | View in bottom pane |

---

## Resources

- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html/)
- [Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [Sample Captures](https://wiki.wireshark.org/SampleCaptures)
- [Wireshark Wiki](https://wiki.wireshark.org/)
