# Windows Commands & Concepts

## System Variables

| Variable | Description |
| :--- | :--- |
| `%windir%` | Windows installation directory (e.g., `C:\Windows`) |
| `%userprofile%` | Current user's profile directory |
| `%temp%` | Temporary files directory |

**Docs**: [learn.microsoft.com](https://learn.microsoft.com/)

## Run Commands (Win+R)

| Command | Description |
| :--- | :--- |
| `cmd` | Command Prompt |
| `powershell` | PowerShell |
| `services.msc` | Services Management |
| `compmgmt.msc` | Computer Management |
| `devmgmt.msc` | Device Manager |
| `diskmgmt.msc` | Disk Management |
| `eventvwr` | Event Viewer |
| `regedit` | Registry Editor |
| `taskmgr` | Task Manager |
| `ncpa.cpl` | Network Connections |
| `appwiz.cpl` | Programs and Features |
| `firewall.cpl` | Windows Firewall |
| `gpedit.msc` | Group Policy Editor |
| `secpol.msc` | Local Security Policy |
| `lusrmgr.msc` | Local Users and Groups |
| `perfmon` | Performance Monitor |
| `resmon` | Resource Monitor |

***

## CMD Commands

### System Information

| Command | Description |
| :--- | :--- |
| `systeminfo` | Detailed configuration and hotfixes |
| `tasklist` | List running processes |
| `taskkill /IM <name> /F` | Force kill process by name |

### Networking

| Command | Description |
| :--- | :--- |
| `ipconfig` | Display IP configuration |
| `ipconfig /all` | Full network configuration |
| `ipconfig /flushdns` | Purge DNS cache |
| `netstat -ano` | All connections with PIDs |
| `netstat -b` | Show executable per connection |
| `net view` | List shared resources |
| `net use` | Connect to network share |

### User Management

| Command | Description |
| :--- | :--- |
| `whoami` | Current username |
| `hostname` | Computer name |
| `net user` | List local users |
| `net user <name> <pass> /add` | Add user |
| `net user <name> /delete` | Delete user |
| `net user /domain` | List domain users |
| `net localgroup administrators` | List admin users |
| `net localgroup administrators <user> /add` | Add user to admins |

### Services & Shares

| Command | Description |
| :--- | :--- |
| `net start <service>` | Start a service |
| `net stop <service>` | Stop a service |
| `net share` | Manage shared resources |
| `net session` | List/disconnect sessions |

### Registry

| Command | Description |
| :--- | :--- |
| `reg query <key>` | Query registry key |
| `reg add <key>` | Add registry key |
| `reg delete <key>` | Delete registry key |
| `regedit` | Registry Editor (GUI) |

### Registry Hives

| Hive | Short | Description |
| :--- | :--- | :--- |
| **HKEY_CURRENT_USER** | HKCU | Config for logged-on user. Subkey of HKU. |
| **HKEY_USERS** | HKU | All loaded user profiles. |
| **HKEY_LOCAL_MACHINE** | HKLM | Machine-wide configuration. |
| **HKEY_CLASSES_ROOT** | HKCR | Merges `HKLM\Software\Classes` & `HKCU\.*\Classes`. File associations. |
| **HKEY_CURRENT_CONFIG** | HKCC | Boot hardware profile. |

> **Note**: HKCR writes go to HKLM unless the key exists in HKCU.

### Hive Locations

| Hive Type | File Path | Mounted As |
| :--- | :--- | :--- |
| **System** | `C:\Windows\System32\Config\*` <br> (`SAM`, `SECURITY`, `SOFTWARE`, `SYSTEM`, `DEFAULT`) | `HKLM\*`, `HKU\.DEFAULT` |
| **User** | `C:\Users\<user>\NTUSER.DAT` | `HKCU` |
| **User Classes** | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | `HKCU\Software\Classes` |

### Transaction Logs & Backups

| Type | Path / Extension | Description |
| :--- | :--- | :--- |
| **Transaction Logs** | `.LOG`, `.LOG1`, `.LOG2` | Journal files for data consistency. Located alongside hives. |
| **Backups** | `C:\Windows\System32\Config\RegBack\` | Legacy hive backups. Often empty (0kb) on modern Win10+. |

### Certutil

| Command | Description |
| :--- | :--- |
| `certutil -hashfile <file> <algo>` | Calculate hash (MD5, SHA1, SHA256) |
| `certutil -urlcache -split -f <url> <file>` | Download file from URL |
| `certutil -encode <in> <out>` | Encode file to Base64 |
| `certutil -decode <in> <out>` | Decode Base64 file |

***

## PowerShell

### Execution Policy

| Method | Command | Scope |
| :--- | :--- | :--- |
| **Single script** | `powershell -ExecutionPolicy Bypass -File .\script.ps1` | One-time |
| **Current session** | `Set-ExecutionPolicy RemoteSigned -Scope Process` | Until close |
| **Current user** | `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` | Permanent |
| **System** | `Set-ExecutionPolicy RemoteSigned` (Admin) | All users |

**Check policy**: `Get-ExecutionPolicy`

### Common Cmdlets

| Command | Description |
| :--- | :--- |
| `Get-Help <cmd>` | Get help for a command |
| `Get-Help <cmd> -Examples` | Show command examples |
| `Get-Command *keyword*` | Find commands |
| `Get-Command -CommandType <Type>` | Find specific types |
| `Get-Process` | List running processes |
| `Stop-Process -Name <name>` | Kill process by name |
| `Get-Service` | List services |
| `Start-Service <name>` | Start a service |
| `Get-LocalUser` | List local users |
| `New-LocalUser <name>` | Create local user |
| `Get-HotFix` | List installed patches |
| `Get-ComputerInfo` | Detailed system info |
| `Get-Date` | Get current date/time |
| `Get-NetIPAddress` | IP configuration (Detailed) |
| `Get-NetIPConfiguration` (`gip`) | IP configuration (Like ipconfig) |
| `Get-NetTCPConnection` | Network connections (netstat) |
| `Get-ChildItem` (`ls`, `dir`) | List files |
| `Get-Content` (`cat`, `type`) | Read file |
| `Get-FileHash <file> -Algorithm SHA256` | Checksum/Hash file |
| `New-Item <path>` | Create file (default) |
| `New-Item <path> -ItemType Directory` | Create directory |
| `Remove-Item <path>` (`rm`, `del`, `rmdir`) | Delete file/dir |
| `Remove-Item <path> -Recurse -Force` | Delete folder recursively |
| `Copy-Item <src> <dst>` (`cp`, `copy`) | Copy file/dir |
| `Copy-Item <src> <dst> -Recurse` | Copy folder recursively |
| `Move-Item <src> <dst>` (`mv`, `move`) | Move file/dir |
| `Set-Location` (`cd`) | Change directory |
| `Write-Output` (`echo`) | Print text |
| `Sort-Object -Property <prop>` | Sort by property |
| `Select-String <pattern>` (`sls`) | Search text (grep) |
| `Invoke-Command -ScriptBlock { ... }` | Run commands (remote/local) |
| `Invoke-WebRequest <URL> -OutFile <file>` | Download file |
| `Test-NetConnection <host> -Port <port>` | Test TCP connection |

### Aliases

For example, `dir` is an alias for `Get-ChildItem`, and `cd` is an alias for `Set-Location`.

| Command | Description |
| :--- | :--- |
| `Get-Alias` | List aliases |

### Piping & Filtering

PowerShell passes **objects** (not text) between commands using the pipe (`|`).

| Command | Description |
| :--- | :--- |
| `cmd1 | cmd2` | Pass output of cmd1 to cmd2 |
| `Select-Object <prop1>, <prop2>` | Select specific properties |
| `Where-Object { $_.<prop> -eq "val" }` | Filter objects |
| `Where-Object { $_.<prop> -like "*val*" }` | Filter with wildcard |

**Comparison Operators**:

| Operator | Description |
| :--- | :--- |
| `-eq` | Equal to |
| `-ne` | Not equal to |
| `-gt` | Greater than |
| `-ge` | Greater than or equal to |
| `-lt` | Less than |
| `-le` | Less than or equal to |
| `-like` | Filter by pattern (wildcard) |

### Modules

To search for modules (collections of cmdlets) in online repositories like the PowerShell Gallery, use `Find-Module`.

If you don't know the exact name, search with a wildcard (`*`) on the Name property.
Standard syntax: `Cmdlet -Property "pattern*"`.

| Command | Description |
| :--- | :--- |
| `Find-Module` | Search for modules |
| `Find-Module -Name "*pattern*"` | Search by partial name |
| `Install-Module <name>` | Install a module |

***

## Shadow Copies (VSS)

| Command | Description |
| :--- | :--- |
| `vssadmin list shadows` | List all shadow copies |
| `vssadmin create shadow /for=C:` | Create shadow copy |
| `vssadmin delete shadows /all` | Delete all shadows |
