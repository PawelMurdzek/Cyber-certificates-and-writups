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
| **AppCompatCache Parser** | Execution Analysis | Parses ShimCache (AppCompatCache) to CSV. |
| **EZViewer** | Viewer | Lightweight viewer for logs, CSVs, and other data files. |

### Plaso (Log2Timeline)

Plaso is a backend engine for log2timeline. It automates the creation of a super timeline from various artifacts.

| Tool | Description |
| :--- | :--- |
| **log2timeline** | Extracts events from artifacts (disk image, folder) into a storage file (.plaso). |
| **psort** | Filters, sorts, and processes the storage file into a readable format (CSV, JSON, Elastic). |
| **psteal** | "Steal" everything. Combines log2timeline and psort in one command for speed. |
| **pinfo** | Shows metadata about the storage file (OS, collected artifacts, errors). |

```bash
# List available parsers and plugins
log2timeline.py --parsers list

# Basic timeline creation from disk image (supports .dd, .E01, etc.)
log2timeline.py --storage-file timeline.plaso image.E01
log2timeline.py --storage-file timeline.plaso image.dd

# Specific Parsing (e.g., Windows Events only)
log2timeline.py --storage-file winevents.plaso --parsers winevt --artifact-filters WindowsEventLogSystem image.E01

# Process storage file to CSV (timeline.csv)
psort.py -o l2tcsv -w timeline.csv timeline.plaso

# List available analysis plugins
psort.py --analysis list

# Filter by time range
psort.py -o dynamic -w timeline.csv timeline.plaso --slice "2024-01-01T00:00:00" "2024-01-02T00:00:00"

# Using psteal (One-shot)
psteal.py --source image.dd -o l2tcsv -w timeline.csv

# Check storage file metadata
pinfo.py Jimmy_timeline.plaso | more
```

### Timesketch

Open-source tool for collaborative forensic timeline analysis. It ingests Plaso files (and CSV/JSON) to visualize and search timelines.

| Feature | Description |
| :--- | :--- |
| **Collaboration** | Multiple analysts can work on the same timeline, add comments, and star events. |
| **Analyzers** | Automated scripts ("Sketchy") to find patterns, anomalies, and threat intel matches. |
| **Visualization** | Charts, graphs, and heatmaps to identify spikes in activity. |

```bash
# Upload Plaso file directly to Timesketch (requires config)
psort.py -o timesketch --name "Case 123" timeline.plaso

# Import CSV/JSONL via CLI (on server)
tsctl import --file timeline.csv --sketch_id 12
```

## System Triage & Artifacts

### Key Evidence Locations

| location | Description |
| :--- | :--- |
| **Logs** | System/Software chronicles recording user activity and security events. |
| **File Metadata (MACB)** | Creation, Modification, Access timestamps revealing user behavior patterns. |
| **Network Traffic** | Data transfers showing system connections and potential intrusions. |
| **Mount Points** | External drives or shares acting as additional evidence sources. |
| **Temp Locations** | Temp dirs holding recent downloads, history, and activity snapshots. |
| **Recycle Bin** | Deleted files that may contain recovered insights. |

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
| **ShimCache\AppCompatCache** | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Execution history (exe name, mod time, size). |
| **Amcache.hve** | `C:\Windows\AppCompat\Programs\Amcache.hve` | Granular execution details (SHA1 hash, timestamps). |
| **BAM/DAM** | `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` | Background Activity Moderator. Execution history (full path, last run time). |

### File Access & Navigation

| Artifact | Source / Registry Key | Description |
| :--- | :--- | :--- |
| **Recent Files (LNK)** | `%APPDATA%\Microsoft\Windows\Recent` | Shortcuts to recently accessed files/folders. |
| **Jumplists** | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations`<br>`CustomDestinations` | Recent files per application (Taskbar/Start Menu history). |
| **Office Recent** | `HKCU\Software\Microsoft\Office\<Ver>\<App>\File MRU` | Recent documents opened in Office apps. |
| **ShellBags** | `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags`<br>`...\BagMRU` (`USRCLASS.DAT`) | Folder view history. Proves folder existence/access. |
| **Open/Save MRU** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU` | History of files opened/saved via dialog box. |
| **Last Visited MRU** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU` | Last folder used in Open/Save dialog. |
| **Explorer Address** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` | Paths typed into Explorer address bar. |
| **Explorer Search** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` | Search terms typed into Explorer search box. |

### External Device & USB Forensics

| Artifact | Source / Registry Key | Description |
| :--- | :--- | :--- |
| **USBSTOR** | `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` | Device details (Vendor, Product, Serial No). |
| **MountedDevices** | `HKLM\SYSTEM\MountedDevices` | Maps drive letters to Device GUID/Serial. |
| **USB Devices** | `HKLM\SYSTEM\CurrentControlSet\Enum\USB` | Information on all USB devices (not just storage). |
| **DeviceClasses** | `HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses` | Interfaces exposed by devices. |
| **SetupAPI Log** | `C:\Windows\INF\setupapi.dev.log` | Plug-and-Play events (First install timestamp). |
| **ShellBags** | `HKCU` ... (See File Access) | Folder access on removable drives. |

#### USB Connection Timestamps (Device Properties)

Located in `HKLM\SYSTEM\CurrentControlSet\Enum\USB\<VID_PID>\<Serial>\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\...`

| Value | Information | Description |
| :--- | :--- | :--- |
| **0064** | First Connection Time | Timestamp of when the device was first installed. |
| **0066** | Last Connection Time | Timestamp of the most recent connection. |
| **0067** | Last Removal Time | Timestamp of the most recent removal. |
