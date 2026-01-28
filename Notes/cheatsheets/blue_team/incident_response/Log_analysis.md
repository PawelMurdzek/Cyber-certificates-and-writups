# Log Analysis & SIEM

## Common Log Locations

### Windows
| Path | Description |
| :--- | :--- |
| `C:\Windows\System32\winevt\Logs\` | Windows Event Logs (.evtx) |
| `C:\Windows\System32\LogFiles\` | IIS and other service logs |

### Linux
| Path | Description |
| :--- | :--- |
| `/var/log/` | System and application logs |
| `/var/log/journal/` | Systemd journal |

## Splunk Queries (SPL)

```spl
# Basic search
index=security sourcetype=WinEventLog:Security EventCode=4625

# Failed logins by user
index=security EventCode=4625 | stats count by Account_Name

# Top source IPs
index=web | top limit=10 src_ip

# Timeline of events
index=security | timechart count by EventCode

# Detect brute force (>5 failures in 5 min)
index=security EventCode=4625 
| bucket _time span=5m 
| stats count by _time, src_ip 
| where count > 5
```

## Elastic/ELK Queries (KQL)

```
# Failed logins
event.code: 4625

# Specific user
user.name: "admin" AND event.action: "logon-failed"

# Time range
@timestamp >= "2024-01-01" AND @timestamp < "2024-01-02"

# Wildcard
process.name: *powershell*
```

## Sigma Rules

Sigma is a generic signature format for SIEM rules.

**Repository**: [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

```yaml
# Example Sigma rule - Suspicious PowerShell download
title: PowerShell Download Cradle
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'powershell'
            - 'downloadstring'
    condition: selection
level: high
```

## Detection Ideas

| Indicator | What to Look For |
| :--- | :--- |
| **Brute Force** | Multiple 4625 from same IP |
| **Lateral Movement** | 4624 Type 3 from internal IPs |
| **Privilege Escalation** | 4672 followed by 4688 |
| **Persistence** | 7045 (new service), 4698 (scheduled task) |
| **Data Exfil** | Large outbound transfers, DNS tunneling |
| **Malware** | Known bad hashes, unusual process parents |
