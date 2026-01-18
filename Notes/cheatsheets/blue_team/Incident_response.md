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

## Forensic Tools

| Tool | Purpose | Key Features |
| :--- | :--- | :--- |
| **KAPE** | Triage & Collection | Fast target collection, parsers (modules), flexible configuration. |
| **Autopsy** | Analysis | Open-source, GUI-based, timeline analysis, keyword search, web artifacts. |
| **FTK Imager** | Imaging & Mounting | Create forensic images (E01, RAW), mount images, capture RAM. |
| **Registry Viewer** | Registry Analysis | View registry hives, reporting. (AccessData). |
| **Registry Explorer** | Registry Analysis | Eric Zimmerman's tool. Parse hives, plugins, recover deleted keys. |
| **RegRipper** | Registry Analysis | Extract specific registry data via plugins (CLI/GUI). |

## System Triage & Artifacts

### System Information (Process First)

| Artifact | Source / Registry Key | Description |
| :--- | :--- | :--- |
| **OS Version** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | Product name, release ID, install date. |
| **Computer Name** | `HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName` | Active computer name. |
| **Time Zone** | `HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation` | Active time zone & bias. |
| **Current Control Set** | `HKLM\SYSTEM\Select` | Determine which ControlSet is `Current`. |
| **Last Shutdown** | `HKLM\SYSTEM\CurrentControlSet\Control\Windows` | ShutdownTime timestamp. |

### Network Information

| Artifact | Source / Registry Key | Description |
| :--- | :--- | :--- |
| **Interfaces** | `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces` | IP, Subnet, DHCP info for interfaces. |
| **Past Networks** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` | History of connected wireless/wired networks. |
| **Network Shares** | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares` | Folders shared by the system. |

### Persistence (Autoruns)

| Artifact | Source / Registry Key | Description |
| :--- | :--- | :--- |
| **Run Keys** | `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`<br>`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Programs starting at login. |
| **Services** | `HKLM\SYSTEM\CurrentControlSet\Services` | Background services (check Start mode 2/Auto). |
| **Scheduled Tasks** | `C:\Windows\System32\Tasks` | Detailed task definitions (XML). |
| **Startup Folder** | `%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup`<br>`%AppData%\Microsoft\Windows\Start Menu\Programs\Startup` | Files executed at login. |

### User & Execution Artifacts

| Artifact | Source / Registry Key | Description |
| :--- | :--- | :--- |
| **SAM Hive** | `C:\Windows\System32\Config\SAM` | User account info (SID, groups, login count). |
| **Last Logon** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI` | Username of last logged-in user. |
| **UserAssist** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | GUI execution history (ROT13 encoded). |
| **ShimCache** | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Execution history (exe name, mod time, size). |
| **Amcache.hve** | `C:\Windows\AppCompat\Programs\Amcache.hve` | Granular execution details (SHA1 hash, timestamps). |
