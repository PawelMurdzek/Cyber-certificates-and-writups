# Proxychains

Route commands through proxy connections.

## Configuration

Edit `/etc/proxychains.conf` or `/etc/proxychains4.conf`:

```ini
# Proxy modes (uncomment one)
#dynamic_chain    # Skip dead proxies
#strict_chain     # All proxies must work
#round_robin_chain
#random_chain

# DNS through proxy
proxy_dns

# Proxy list at bottom
[ProxyList]
socks5 127.0.0.1 1080
```

---

## Proxy Types

```ini
# SOCKS4
socks4 127.0.0.1 1080

# SOCKS5
socks5 127.0.0.1 1080

# HTTP
http 127.0.0.1 8080
```

---

## Usage

```bash
# Basic usage
proxychains <command>

# Examples
proxychains curl http://internal-server
proxychains wget http://192.168.1.100/file
proxychains ssh user@internal-host
proxychains nmap -sT -Pn 192.168.1.100
```

---

## With SOCKS Proxies

### With SSH Dynamic Tunnel
```bash
# Create SOCKS proxy
ssh -D 1080 user@pivot

# Configure proxychains
# [ProxyList]
# socks5 127.0.0.1 1080

# Use
proxychains curl http://internal:80
```

### With Chisel
```bash
# Server (attacker)
chisel server -p 8080 --reverse

# Client (target)
chisel client attacker:8080 R:socks

# Use (default port 1080)
proxychains nmap -sT 192.168.1.0/24
```

---

## Nmap Through Proxychains

```bash
# TCP Connect scan only (-sT)
proxychains nmap -sT -Pn 192.168.1.100

# Skip host discovery (-Pn)
proxychains nmap -sT -Pn -n 192.168.1.100

# Service scan (slower)
proxychains nmap -sT -Pn -sV 192.168.1.100 -p 80,443

# Note: SYN scan (-sS) and UDP scan don't work through SOCKS
```

---

## Chain Multiple Proxies

```ini
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
socks5 127.0.0.1 1082
```

With `dynamic_chain`, proxychains will skip failed proxies.
With `strict_chain`, all must be reachable.

---

## Troubleshooting

| Issue | Solution |
|:------|:---------|
| "timeout" | Check proxy is running |
| DNS issues | Enable `proxy_dns` |
| Not working | Try `proxychains4` instead |
| Nmap failing | Use `-sT -Pn` flags |
| Command hangs | Proxy may be slow or dead |

---

## Quiet Mode

```bash
# Suppress proxychains output
proxychains -q <command>
```
