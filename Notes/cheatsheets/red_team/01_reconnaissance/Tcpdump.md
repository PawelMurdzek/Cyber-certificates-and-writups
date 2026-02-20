# Tcpdump Cheat Sheet

Tcpdump is a powerful command-line packet analyzer. For Red Teamers, it is essential for passive reconnaissance, traffic sniffing, and verifying that C2 or exploitation traffic is reaching its destination.

## Basic Capture

| Command | Description |
| :--- | :--- |
| `tcpdump -D` | List available interfaces. |
| `tcpdump -i <interface>` | Capture on a specific interface. |
| `tcpdump -i any` | Capture on all interfaces. |
| `tcpdump -n` | Disable hostname resolution (faster, stealthier). |
| `tcpdump -nn` | Disable hostname and port resolution (even faster). |
| `tcpdump -c <count>` | Stop after capturing `<count>` packets. |
| `tcpdump -v / -vv / -vvv` | Increase output verbosity. |
| `tcpdump -q` | Quick output (print brief packet information). |

## File Operations

| Command | Description |
| :--- | :--- |
| `tcpdump -w capture.pcap` | Write packets to a file for later analysis. |
| `tcpdump -r capture.pcap` | Read packets from a previously saved file. |
| `tcpdump -r capture.pcap -G 3600` | Rotate capture file every hour. |
| `tcpdump -r capture.pcap -C 100` | Rotate file after it reaches 100MB. |

## BPF Filters (Recon Emphasis)

| Filter | Description |
| :--- | :--- |
| `host <IP>` | Traffic to/from a specific host. |
| `net <CIDR>` | Traffic to/from a specific subnet. |
| `port <number>` | Traffic on a specific port (e.g., `80`, `443`, `445`). |
| `src <IP>` | Traffic from a specific source. |
| `dst <IP>` | Traffic to a specific destination. |
| `tcp`, `udp`, `icmp` | Protocol-specific filtering. |

## Logical Operators

| Operator | Symbol | Description | Example |
| :--- | :--- | :--- | :--- |
| `and` | `&&` | Both conditions must be true. | `host 1.1.1.1 and tcp` |
| `or` | `\|\|` | Either condition can be true. | `udp or icmp` |
| `not` | `!` | Condition must not be true. | `not tcp` |

## Packet Size Filtering

| Command | Description |
| :--- | :--- |
| `greater <length>` | Filters packets >= specified length. |
| `less <length>` | Filters packets <= specified length. |

## Packet Content Analysis

| Command | Description |
| :--- | :--- |
| `tcpdump -q` | Quick output; print brief packet information. |
| `tcpdump -e` | Print the link-level header (e.g., Ethernet). |
| `tcpdump -A` | Show packet data in ASCII (useful for cleartext protocols). |
| `tcpdump -xx` | Show packet data in hexadecimal format (hex). |
| `tcpdump -X` | Show packet headers and data in hex and ASCII. |
| `tcpdump -S` | Show absolute TCP sequence numbers. |

## Advanced Header Filtering

BPF allows for granular inspection of protocol headers using the syntax: `proto[expr:size]`.

- `proto`: The protocol (e.g., `arp`, `ether`, `icmp`, `ip`, `ip6`, `tcp`, `udp`).
- `expr`: The byte offset (starting at 0).
- `size`: The number of bytes to inspect (1, 2, or 4). Defaults to 1.

## TCP Flags Analysis

You can use `tcp[tcpflags]` to reference the flags field. Available flags:
- `tcp-syn`, `tcp-ack`, `tcp-fin`, `tcp-rst`, `tcp-push`

### Flag Patterns

| Command | Description |
| :--- | :--- |
| `tcpdump "tcp[tcpflags] == tcp-syn"` | Capture packets with **only** the SYN flag set. |
| `tcpdump "tcp[tcpflags] & tcp-syn != 0"` | Capture packets with **at least** the SYN flag set. |
| `tcpdump "tcp[tcpflags] & (tcp-syn\|tcp-ack) != 0"` | Capture packets with **at least** SYN or ACK set. |

## Useful Recon One-Liners

**Identify active hosts (Passive Discovery):**
```bash
tcpdump -n -i eth0 icmp
```

**Capture cleartext HTTP credentials:**
```bash
tcpdump -i eth0 -A -s 0 'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)'
```

**Monitor for SMB authentication attempts:**
```bash
tcpdump -i eth0 port 445 or port 139
```

**Detect DNS queries for internal assets:**
```bash
tcpdump -i eth0 udp port 53
```

## See Also

- [Nmap Cheat Sheet](Nmap.md) - Active network discovery and security auditing.
- [Detailed Tcpdump Guide](../../blue_team/network_analysis/Tcpdump_cheatsheet.md) - Comprehensive BPF and deep analysis reference.
