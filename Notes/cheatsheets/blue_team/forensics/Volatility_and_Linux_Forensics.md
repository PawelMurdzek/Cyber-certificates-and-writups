# Volatility Cheatsheet
Memory forensics framework.

## Volatility 3 Usage

### Basic Command Structure
`python3 vol.py -f <memory_dump> <plugin>`

### Common Plugins (Windows)

| Plugin | Description |
|:-------|:------------|
| `windows.info` | Show OS info from image |
| `windows.pslist` | List running processes |
| `windows.pstree` | List processes in a tree (parent/child) |
| `windows.psscan` | Scan for unlinked processes (rootkits) |
| `windows.cmdline` | Show command line arguments for processes |
| `windows.netscan` | Scan for network connections (TCP/UDP) |
| `windows.malfind` | Find injected code / hidden malware |
| `windows.dlllist` | List loaded DLLs for a process |
| `windows.filescan` | Scan memory for file objects |
| `windows.registry.hivelist` | List registry hives |

### Example Workflow
1. **Identify OS**: `python3 vol.py -f dump.mem windows.info`
2. **Check Processes**: `python3 vol.py -f dump.mem windows.psscan`
3. **Check Network**: `python3 vol.py -f dump.mem windows.netscan`
4. **Dump Process**: `python3 vol.py -f dump.mem -o dumped/ windows.dumpfiles --pid <PID>`

## Volatility 2 (Legacy)

`vol.py -f <image> --profile=<profile> <plugin>`

- **Identify Profile**: `imageinfo` or `kdbgscan`
- **Commands**: `pslist`, `connscan`, `hivelist`, `hashdump`, `consoles` (command history)

## Linux Forensics (Basic)
- **Check Logs**: `/var/log/auth.log`, `/var/log/syslog`
- **User Activity**: `last`, `w`, `history`
- **Processes**: `ps -aux`, `top`
- **Network**: `netstat -antup`, `ss -lntp`
- **Open Files**: `lsof -p <PID>`
- **Persistence**: Cron jobs (`/var/spool/cron`, `/etc/cron*`), Systemd services (`/etc/systemd/system`)
