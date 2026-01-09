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

## Shadow Copies (VSS)

| Command | Description |
| :--- | :--- |
| `vssadmin list shadows` | Lists all existing shadow copies |
| `vssadmin list writers` | Lists all shadow copy writers |
| `vssadmin create shadow /for=C:` | Creates a new shadow copy for C: drive |
| `vssadmin delete shadows /all` | Deletes all shadow copies |
| `vssadmin delete shadows /for=C: /oldest` | Deletes the oldest shadow copy for C: drive |