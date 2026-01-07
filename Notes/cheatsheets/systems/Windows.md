# Windows Information

## System Variables

- **`%windir%`**: The system variable for the Windows installation directory (e.g., `C:\Windows`).

## Documentation

- **Microsoft Learn**: [learn.microsoft.com](https://learn.microsoft.com/pl-pl/)
  - The official portal for Microsoft documentation, training, and certifications.

## Run Commands (Win+R)

| Command | Description |
| :--- | :--- |
| `cmd` | Command Prompt |
| `powershell` | PowerShell |
| `control` | Control Panel |
| `appwiz.cpl` | Programs and Features (Uninstall programs) |
| `ncpa.cpl` | Network Connections |
| `services.msc` | Services Management |
| `compmgmt.msc` | Computer Management |
| `devmgmt.msc` | Device Manager |
| `diskmgmt.msc` | Disk Management |
| `eventvwr` | Event Viewer |
| `regedit` | Registry Editor |
| `mstsc` | Remote Desktop Connection |
| `taskmgr` | Task Manager |
| `calc` | Calculator |
| `notepad` | Notepad |
| `mspaint` | Microsoft Paint |
| `winver` | About Windows (Version info) |
| `sysdm.cpl` | System Properties |
| `firewall.cpl` | Windows Defender Firewall |
| `WF.msc` | Windows Defender Firewall with Advanced Security |
| `gpedit.msc` | Local Group Policy Editor |
| `secpol.msc` | Local Security Policy |
| `lusrmgr.msc` | Local Users and Groups |
| `inetcpl.cpl` | Internet Properties |
| `mrt` | Malicious Software Removal Tool |
| `perfmon` | Performance Monitor |
| `resmon` | Resource Monitor |

## PowerShell Commands

| Command | Description |
| :--- | :--- |
| `Get-Process` | List running processes |
| `Get-Service` | List services and status |
| `Get-LocalUser` | List local user accounts |
| `Get-HotFix` | List installed updates (patches) |
| `Get-ComputerInfo` | Detailed OS and system info |
| `Get-NetIPAddress` | Show IP configuration |
| `Get-ChildItem` (alias `ls`, `dir`) | List files and directories |
| `Get-Content` (alias `cat`) | Read file content |
| `Get-Command` | Search for commands/programs |
| `Get-Help <cmd>` | Get help for a command |

## CMD Commands

| Command | Description |
| :--- | :--- |
| `hostname` | Displays the computer name |
| `whoami` | Displays the current user |
| `cls` | Clears the screen |
| `ipconfig` | Displays IP configuration |
| `ipconfig /all` | Displays full configuration information |
| `ipconfig /release` | Releases the IPv4 address |
| `ipconfig /renew` | Renews the IPv4 address |
| `ipconfig /flushdns` | Purges the DNS Resolver cache |
| `netstat` | Displays network statistics |
| `netstat -a` | Displays all connections and listening ports |
| `netstat -b` | Displays the executable involved in creating each connection |
| `netstat -e` | Displays Ethernet statistics |
| `netstat -an` | Displays all connections and listening ports numerically |
| `net user` | Lists all user accounts |
| `net user <username>` | Displays information about a specific user |
| `net user <username> <password> /add` | Adds a new user with the specified password |
| `net user <username> /delete` | Deletes a user account |
| `net user <username> /active:yes` | Activates a user account |
| `net user /domain` | Lists all users in the current domain |
| `net localgroup` | Adds/modifies local groups |
| `net share` | Manages shared resources |
| `net use` | Connects/disconnects from a shared resource |
| `net view` | Displays a list of resources being shared on a computer |
| `net start` | Starts a service |
| `net stop` | Stops a service |
| `net accounts` | Updates the user accounts database and modifies password and logon requirements |
| `net session` | Lists or disconnects sessions between the computer and other computers on the network |
| `net help <command>` | Displays help for a specific net command (e.g., `net help user`) |
| `reg` | Console Registry Tool for reading, setting, and deleting registry keys |
| `regedit` | Opens the Registry Editor (GUI) |
| `regedt32` | Opens the Registry Editor (Legacy) |

## Shadow Copies (VSS)

| Command | Description |
| :--- | :--- |
| `vssadmin list shadows` | Lists all existing shadow copies |
| `vssadmin list writers` | Lists all shadow copy writers |
| `vssadmin create shadow /for=C:` | Creates a new shadow copy for C: drive |
| `vssadmin delete shadows /all` | Deletes all shadow copies |
| `vssadmin delete shadows /for=C: /oldest` | Deletes the oldest shadow copy for C: drive |