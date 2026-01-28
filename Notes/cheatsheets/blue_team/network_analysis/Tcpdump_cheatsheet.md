# Tcpdump Cheatsheet

Tcpdump is a powerful command-line packet analyzer. It uses the libpcap library to capture network traffic and BPF (Berkeley Packet Filter) syntax for filtering.

---

## Basic Capture Commands

```bash
# List available interfaces
tcpdump -D

# Capture on specific interface
tcpdump -i eth0

# Capture on all interfaces
tcpdump -i any

# Capture with packet count limit
tcpdump -i eth0 -c 100

# Capture and write to file
tcpdump -i eth0 -w capture.pcap

# Read from capture file
tcpdump -r capture.pcap

# Quiet mode (less verbose)
tcpdump -q -i eth0

# Don't resolve hostnames
tcpdump -n -i eth0

# Don't resolve hostnames or ports
tcpdump -nn -i eth0

# Verbose output
tcpdump -v -i eth0

# More verbose
tcpdump -vv -i eth0

# Most verbose
tcpdump -vvv -i eth0
```

---

## Capture Filters (BPF Syntax)

### Host Filters
```bash
# Capture traffic to/from specific host
tcpdump -i eth0 host 192.168.1.100

# Capture traffic from source host
tcpdump -i eth0 src host 192.168.1.100

# Capture traffic to destination host
tcpdump -i eth0 dst host 192.168.1.100

# Capture traffic between two hosts
tcpdump -i eth0 host 192.168.1.100 and host 10.0.0.1

# Capture traffic to/from subnet
tcpdump -i eth0 net 192.168.1.0/24

# Exclude specific host
tcpdump -i eth0 not host 192.168.1.1
```

### Port Filters
```bash
# Capture traffic on specific port
tcpdump -i eth0 port 80

# Capture traffic from source port
tcpdump -i eth0 src port 443

# Capture traffic to destination port
tcpdump -i eth0 dst port 22

# Capture traffic on port range
tcpdump -i eth0 portrange 1-1024

# Capture excluding specific port
tcpdump -i eth0 not port 22
```

### Protocol Filters
```bash
# Capture only TCP
tcpdump -i eth0 tcp

# Capture only UDP
tcpdump -i eth0 udp

# Capture only ICMP
tcpdump -i eth0 icmp

# Capture only ARP
tcpdump -i eth0 arp

# Capture only IPv6
tcpdump -i eth0 ip6
```

### Combining Filters
```bash
# AND operator
tcpdump -i eth0 host 192.168.1.100 and port 80

# OR operator
tcpdump -i eth0 port 80 or port 443

# NOT operator
tcpdump -i eth0 not arp

# Complex filter
tcpdump -i eth0 'host 192.168.1.100 and (port 80 or port 443)'

# Complex filter with exclusion
tcpdump -i eth0 'tcp and not port 22'
```

---

## TCP Flag Filters

```bash
# Capture SYN packets only
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'

# Capture SYN-ACK packets
tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'

# Capture FIN packets
tcpdump -i eth0 'tcp[tcpflags] & tcp-fin != 0'

# Capture RST packets
tcpdump -i eth0 'tcp[tcpflags] & tcp-rst != 0'

# Capture PSH packets (with data)
tcpdump -i eth0 'tcp[tcpflags] & tcp-push != 0'

# Capture URG packets
tcpdump -i eth0 'tcp[tcpflags] & tcp-urg != 0'

# Capture only SYN (no ACK) - connection initiation
tcpdump -i eth0 'tcp[tcpflags] == tcp-syn'

# Alternative using offset notation
tcpdump -i eth0 'tcp[13] & 2 != 0'   # SYN flag
tcpdump -i eth0 'tcp[13] & 16 != 0'  # ACK flag
tcpdump -i eth0 'tcp[13] & 1 != 0'   # FIN flag
tcpdump -i eth0 'tcp[13] & 4 != 0'   # RST flag
```

---

## Packet Size Filters

```bash
# Capture packets greater than size
tcpdump -i eth0 greater 500

# Capture packets less than size
tcpdump -i eth0 less 100

# Capture packets greater than MTU (possible fragmentation)
tcpdump -i eth0 greater 1500
```

---

## Output Options

```bash
# ASCII output (show packet content)
tcpdump -A -i eth0

# Hex and ASCII output
tcpdump -X -i eth0

# Hex output only
tcpdump -x -i eth0

# Show absolute sequence numbers
tcpdump -S -i eth0

# Show timestamps with microseconds
tcpdump -tt -i eth0

# Show timestamp as date
tcpdump -tttt -i eth0

# Show link-level header
tcpdump -e -i eth0

# Limit capture length (snaplen)
tcpdump -s 96 -i eth0

# Full packet capture
tcpdump -s 0 -i eth0
```

---

## File Operations

```bash
# Write to file
tcpdump -i eth0 -w capture.pcap

# Write to file with size limit (rotate at 100MB)
tcpdump -i eth0 -w capture.pcap -C 100

# Write with file count limit (5 files max)
tcpdump -i eth0 -w capture.pcap -C 100 -W 5

# Write with timestamp in filename
tcpdump -i eth0 -w capture_%Y%m%d_%H%M%S.pcap -G 3600

# Read from file
tcpdump -r capture.pcap

# Read and apply filter
tcpdump -r capture.pcap host 192.168.1.100

# Read with specific number of packets
tcpdump -r capture.pcap -c 50
```

---

## DNS Analysis

```bash
# Capture DNS traffic
tcpdump -i eth0 port 53

# Capture DNS and show content
tcpdump -i eth0 -vv port 53

# Capture DNS queries only
tcpdump -i eth0 'udp port 53 and udp[10] & 0x80 = 0'

# Capture DNS responses only
tcpdump -i eth0 'udp port 53 and udp[10] & 0x80 = 0x80'

# DNS over TCP
tcpdump -i eth0 tcp port 53
```

---

## HTTP/HTTPS Analysis

```bash
# Capture HTTP traffic
tcpdump -i eth0 port 80

# Capture HTTP and show content
tcpdump -A -i eth0 port 80

# Capture HTTP GET requests
tcpdump -A -i eth0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# Capture HTTP User-Agent
tcpdump -A -i eth0 'port 80' | grep -i 'User-Agent'

# Capture HTTP Host header
tcpdump -A -i eth0 'port 80' | grep -i 'Host:'

# Capture HTTPS (metadata only)
tcpdump -i eth0 port 443
```

---

## ICMP Analysis

```bash
# Capture all ICMP
tcpdump -i eth0 icmp

# Capture ICMP echo requests (ping)
tcpdump -i eth0 'icmp[icmptype] = icmp-echo'

# Capture ICMP echo replies
tcpdump -i eth0 'icmp[icmptype] = icmp-echoreply'

# Capture ICMP unreachable
tcpdump -i eth0 'icmp[icmptype] = icmp-unreach'

# Capture ICMP redirects
tcpdump -i eth0 'icmp[icmptype] = icmp-redirect'

# Capture ICMP time exceeded
tcpdump -i eth0 'icmp[icmptype] = icmp-timxceed'
```

---

## Advanced Filters

### Capture Specific Content
```bash
# Capture packets containing specific hex pattern
tcpdump -i eth0 'ether[0x47:4] = 0x47455420'  # "GET " in hex

# HTTP GET requests
tcpdump -i eth0 -s 0 -A 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'

# HTTP POST requests
tcpdump -i eth0 -s 0 -A 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354'

# Capture packets with TTL less than 10 (potential traceroute)
tcpdump -i eth0 'ip[8] < 10'

# Capture fragmented packets
tcpdump -i eth0 '((ip[6:2] > 0) and (not ip[6] = 64))'
```

### MAC Address Filters
```bash
# Filter by source MAC
tcpdump -i eth0 ether src 11:22:33:44:55:66

# Filter by destination MAC
tcpdump -i eth0 ether dst 11:22:33:44:55:66

# Filter by any MAC
tcpdump -i eth0 ether host 11:22:33:44:55:66

# Capture broadcast traffic
tcpdump -i eth0 ether broadcast

# Capture multicast traffic
tcpdump -i eth0 ether multicast
```

---

## Security and Threat Hunting

```bash
# Detect port scanning (many SYN to different ports)
tcpdump -i eth0 'tcp[tcpflags] == tcp-syn'

# Detect NULL scan
tcpdump -i eth0 'tcp[13] = 0'

# Detect FIN scan
tcpdump -i eth0 'tcp[13] = 1'

# Detect XMAS scan
tcpdump -i eth0 'tcp[13] = 41'

# Capture potential C2 beaconing (periodic connections)
tcpdump -i eth0 -c 1000 'tcp[tcpflags] == tcp-syn' > syn_packets.txt

# Capture SMB traffic
tcpdump -i eth0 port 445 or port 139

# Capture RDP traffic
tcpdump -i eth0 port 3389

# Capture SSH traffic
tcpdump -i eth0 port 22

# Capture potential data exfiltration (large outbound)
tcpdump -i eth0 'src net 192.168.0.0/16 and greater 1000'
```

---

## Useful One-Liners

```bash
# Count packets by source IP
tcpdump -r capture.pcap -nn -q | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn

# Count packets by destination IP
tcpdump -r capture.pcap -nn -q | awk '{print $5}' | cut -d. -f1-4 | sort | uniq -c | sort -rn

# Extract unique IPs from capture
tcpdump -r capture.pcap -nn | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u

# Monitor for specific string in traffic
tcpdump -A -i eth0 | grep -i 'password'

# Capture and display timestamp + IP pairs
tcpdump -i eth0 -nn -tttt -c 100

# Show traffic rate (packets per second)
tcpdump -i eth0 -w - 2>/dev/null | pv -r > /dev/null
```

---

## Quick Reference Table

| Task | Command |
|------|---------|
| List interfaces | `tcpdump -D` |
| Capture on interface | `tcpdump -i eth0` |
| Write to file | `tcpdump -i eth0 -w file.pcap` |
| Read from file | `tcpdump -r file.pcap` |
| Filter by host | `tcpdump -i eth0 host 192.168.1.1` |
| Filter by port | `tcpdump -i eth0 port 80` |
| Filter by protocol | `tcpdump -i eth0 tcp` |
| Show ASCII content | `tcpdump -A -i eth0` |
| Show hex content | `tcpdump -X -i eth0` |
| No DNS resolution | `tcpdump -nn -i eth0` |
| Verbose output | `tcpdump -vv -i eth0` |
| Limit packet count | `tcpdump -c 100 -i eth0` |

---

## BPF Primitives Reference

| Primitive | Description | Example |
|-----------|-------------|---------|
| `host` | Source or destination host | `host 192.168.1.1` |
| `src host` | Source host | `src host 192.168.1.1` |
| `dst host` | Destination host | `dst host 192.168.1.1` |
| `net` | Network/subnet | `net 192.168.1.0/24` |
| `port` | Source or destination port | `port 80` |
| `src port` | Source port | `src port 443` |
| `dst port` | Destination port | `dst port 22` |
| `portrange` | Port range | `portrange 1-1024` |
| `tcp` | TCP protocol | `tcp` |
| `udp` | UDP protocol | `udp` |
| `icmp` | ICMP protocol | `icmp` |
| `arp` | ARP protocol | `arp` |
| `and` | Logical AND | `host 10.0.0.1 and port 80` |
| `or` | Logical OR | `port 80 or port 443` |
| `not` | Logical NOT | `not port 22` |
| `greater` | Packet size greater than | `greater 500` |
| `less` | Packet size less than | `less 100` |

---

## Resources

- [Tcpdump Man Page](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [BPF Filter Reference](https://biot.com/capstats/bpf.html)
- [Tcpdump Examples](https://danielmiessler.com/p/tcpdump/)
