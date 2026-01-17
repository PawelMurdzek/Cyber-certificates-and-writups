# Incident Response & Forensics

## Incident Response Phases

1. **Preparation** - Policies, tools, training
2. **Identification** - Detect and confirm incident
3. **Containment** - Limit damage, isolate systems
4. **Eradication** - Remove threat, patch vulnerabilities
5. **Recovery** - Restore systems, verify functionality
6. **Lessons Learned** - Document and improve

## Windows Forensics

### Event Logs (Key Event IDs)

| Event ID | Log | Description |
| :--- | :--- | :--- |
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Explicit credential logon |
| 4672 | Security | Admin/special privileges assigned |
| 4688 | Security | Process created |
| 4697 | Security | Service installed |
| 7045 | System | New service installed |
| 1102 | Security | Audit log cleared |

### Useful Commands

```powershell
# Get recent security events
Get-WinEvent -LogName Security -MaxEvents 100

# Search for specific event ID
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}

# List scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'}

# Check autoruns
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

## Linux Forensics

### Important Logs

| File | Description |
| :--- | :--- |
| `/var/log/auth.log` | Authentication events (Debian) |
| `/var/log/secure` | Authentication events (RHEL) |
| `/var/log/syslog` | General system logs |
| `/var/log/apache2/access.log` | Web server access |
| `/var/log/nginx/error.log` | Web server errors |
| `~/.bash_history` | User command history |

### Useful Commands

```bash
# Recent logins
last -n 20
lastlog

# Failed logins
grep "Failed password" /var/log/auth.log

# Currently logged in
who
w

# Running processes with network
netstat -tulpn
ss -tulpn

# Find recently modified files
find / -mtime -1 -type f 2>/dev/null

# Check cron jobs
crontab -l
ls -la /etc/cron.*
```

## Network Analysis

| Tool | Description |
| :--- | :--- |
| `tcpdump -i eth0 -w capture.pcap` | Capture network traffic |
| `tshark -r capture.pcap` | CLI Wireshark |
| `wireshark` | GUI packet analyzer |
| `zeek` | Network security monitor |
