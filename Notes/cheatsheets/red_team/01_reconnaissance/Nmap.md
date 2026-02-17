# Nmap Cheat Sheet

Nmap (Network Mapper) is a free and open-source utility for network discovery and security auditing.

## Basic Scanning

| Command | Description |
| :--- | :--- |
| `nmap <target>` | Scan a single target. |
| `nmap <target1> <target2>` | Scan multiple targets. |
| `nmap <target_range>` | Scan a range of IPs (e.g., `192.168.1.1-254`). |
| `nmap <subnet>` | Scan a subnet (e.g., `192.168.1.0/24`). |
| `nmap -iL <file>` | Scan targets from a file. |
| `nmap -iR <count>` | Scan random targets. |
| `nmap --exclude <host>` | Exclude hosts from scan. |

## Discovery Options

| Command | Description |
| :--- | :--- |
| `nmap -sn <target>` | Ping scan (No port scan). |
| `nmap -Pn <target>` | Treat all hosts as online (skip ping). |
| `nmap -PS <ports>` | TCP SYN discovery on ports. |
| `nmap -PA <ports>` | TCP ACK discovery on ports. |
| `nmap -PU <ports>` | UDP discovery on ports. |
| `nmap -PR <target>` | ARP discovery on local network. |
| `nmap -sL <subnet>` | List targets to scan without scanning (e.g., `nmap -sL 192.168.0.1/24`). |
| `nmap -n` | Never do DNS resolution. |
| `nmap -R` | Always resolve DNS. |

## Advanced Scanning Options

| Command | Description |
| :--- | :--- |
| `nmap -sS <target>` | TCP SYN scan (Stealth). Default for root. |
| `nmap -sT <target>` | TCP Connect scan. Default for non-root. |
| `nmap -sU <target>` | UDP scan. |
| `nmap -sA <target>` | TCP ACK scan. |
| `nmap -sW <target>` | TCP Window scan. |
| `nmap -sM <target>` | TCP Maimon scan. |
| `nmap -sN <target>` | TCP Null scan. |
| `nmap -sF <target>` | TCP FIN scan. |
| `nmap -sX <target>` | TCP Xmas scan. |

## Port Specification

| Command | Description |
| :--- | :--- |
| `nmap -p <ports>` | Scan specific ports (e.g., `80`, `22-25`). |
| `nmap -p- <target>` | Scan all 65535 ports. |
| `nmap -F <target>` | Fast scan (top 100 ports). |
| `nmap --top-ports <n>` | Scan top `n` most common ports. |

## Service and Version Detection

| Command | Description |
| :--- | :--- |
| `nmap -sV <target>` | Probe open ports to determine service/version info. |
| `nmap -sV --version-intensity <0-9>` | Set intensity level (0 light, 9 all probes). |
| `nmap -sV --version-light` | Limit to most likely probes (intensity 2). |
| `nmap -sV --version-all` | Try every single probe (intensity 9). |

## OS Detection

| Command | Description |
| :--- | :--- |
| `nmap -O <target>` | Enable OS detection. |
| `nmap -O --osscan-limit` | Limit OS detection to promising targets. |
| `nmap -O --osscan-guess` | Guess OS more aggressively. |

## Timing and Performance

| Command | Description |
| :--- | :--- |
| `nmap -T0` | Paranoid (Very slow, IDS evasion). |
| `nmap -T1` | Sneaky (Slow, IDS evasion). |
| `nmap -T2` | Polite (Slower to use less bandwidth). |
| `nmap -T3` | Normal (Default). |
| `nmap -T4` | Aggressive (Fast, optimized for reliable networks). |
| `nmap -T5` | Insane (Very fast, assumes fast network). |
| `nmap --min-rate <number>` | Send packets no slower than `<number>` per second. |
| `nmap --max-retries <number>` | Cap number of port scan probe retransmissions. |

## NSE Scripts

| Command | Description |
| :--- | :--- |
| `nmap -sC <target>` | Scan with default NSE scripts. |
| `nmap --script <script>` | Run a specific script. |
| `nmap --script <category>` | Run scripts by category (e.g., `vuln`, `auth`). |
| `nmap --script-args <args>` | Provide arguments to scripts. |
| `nmap --script-help <script>` | Show help for a script. |
| `nmap --script-updatedb` | Update the script database. |

## Firewall/IDS Evasion

| Command | Description |
| :--- | :--- |
| `nmap -f <target>` | Fragment packets. |
| `nmap -D <decoy1,decoy2...>` | Cloak a scan with decoys. |
| `nmap -S <IP_Address>` | Spoof source address. |
| `nmap -e <iface>` | Use specified interface. |
| `nmap -g <portnum>` | Source port manipulation. |
| `nmap --proxies <url>` | Relay connections through proxies. |
| `nmap --data-length <num>` | Append random data to sent packets. |
| `nmap --spoof-mac <mac>` | Spoof MAC address. |
| `nmap --badsum` | Send packets with a bogus TCP/UDP checksum. |

## Output Options

| Command | Description |
| :--- | :--- |
| `nmap -oN <file>` | Normal output to file. |
| `nmap -oX <file>` | XML output to file. |
| `nmap -oG <file>` | Grepable output to file. |
| `nmap -oA <basename>` | Output in all three major formats (N, X, G). |
| `nmap -v` | Increase verbosity level (use `-vv` or more for greater effect). |
| `nmap -d` | Increase debugging level (use `-dd` or more for greater effect). |
| `nmap -d[level]` | Set debugging level (e.g. `-d9` for max). |
| `nmap --packet-trace` | Trace all packets sent and received. |
| `nmap --reason` | Display the reason a port is in a particular state. |
| `nmap --open` | Only show open (or possibly open) ports. |

## Useful Examples

**Scan a network for active hosts:**
```bash
nmap -sn 192.168.1.0/24
```

**Aggressive scan (OS, Service, Scripts, Traceroute):**
```bash
nmap -A 10.10.10.10
```

**Scan all ports with version detection and save output:**
```bash
nmap -p- -sV -oA scan_result 10.10.10.10
```

**Vulnerability scan using NSE:**
```bash
nmap --script vuln 10.10.10.10
```
