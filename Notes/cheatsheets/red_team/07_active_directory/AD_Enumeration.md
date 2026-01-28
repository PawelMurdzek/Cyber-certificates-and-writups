# Active Directory Enumeration

Techniques for discovering AD structure and finding attack paths.

> [!TIP]
> For Active Directory System Concepts & Blue Team, see [AD System Concepts](../../systems/Active_directory.md)


## Initial Enumeration

### Domain Information
```cmd
# Basic domain info
systeminfo | findstr /B /C:"Domain"
echo %userdomain%

# Domain Controller
nltest /dclist:<domain>
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>
```

### PowerShell AD Module
```powershell
# Import module
Import-Module ActiveDirectory

# Domain info
Get-ADDomain
Get-ADForest
Get-ADDomainController

# Users
Get-ADUser -Filter * -Properties *
Get-ADUser -Filter * | Select Name,SamAccountName

# Groups
Get-ADGroup -Filter *
Get-ADGroupMember -Identity "Domain Admins"

# Computers
Get-ADComputer -Filter * -Properties *
```

---

## BloodHound

### Collection with SharpHound
```cmd
# Run collector
SharpHound.exe -c All

# Output: .zip file with JSON data
```

```powershell
# PowerShell version
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp
```

### Starting BloodHound
```bash
# Start neo4j database
neo4j console

# Start BloodHound
bloodhound
```

### Key Queries
- "Find Shortest Paths to Domain Admins"
- "Find Principals with DCSync Rights"
- "Find AS-REP Roastable Users"
- "Find Kerberoastable Users"

---

## LDAP Enumeration

### ldapsearch
```bash
# Anonymous bind
ldapsearch -x -H ldap://<DC_IP> -b "dc=domain,dc=local"

# Authenticated
ldapsearch -x -H ldap://<DC_IP> -D "user@domain.local" -w password -b "dc=domain,dc=local"

# Get users
ldapsearch -x -H ldap://<DC_IP> -D "user@domain.local" -w pass -b "dc=domain,dc=local" "(objectClass=user)"

# Get computers
ldapsearch -x -H ldap://<DC_IP> -D "user@domain.local" -w pass -b "dc=domain,dc=local" "(objectClass=computer)"
```

### ldapdomaindump
```bash
ldapdomaindump -u 'domain\user' -p password <DC_IP> -o output/
```

---

## User Enumeration

### No Credentials Needed
```bash
# Kerbrute user enumeration
kerbrute userenum --dc <DC_IP> -d <domain> users.txt

# RPC null session
rpcclient -U "" -N <DC_IP>
> enumdomusers
> enumdomgroups
```

### With Credentials
```powershell
# PowerView
Get-DomainUser
Get-DomainUser -SPN  # Kerberoastable
Get-DomainUser -PreAuthNotRequired  # AS-REP Roastable

# Net commands
net user /domain
net group /domain
net group "Domain Admins" /domain
```

---

## Service Principal Names (SPNs)

```powershell
# Find accounts with SPNs (Kerberoastable)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# PowerView
Get-DomainUser -SPN | Select SamAccountName,ServicePrincipalName
```

---

## ACL Enumeration

```powershell
# PowerView - Find interesting ACLs
Find-InterestingDomainAcl -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs

# Check specific user's rights
Get-DomainObjectAcl -Identity "target_user" -ResolveGUIDs
```

### Dangerous Rights
| Right | Abuse |
|:------|:------|
| GenericAll | Full control |
| GenericWrite | Modify attributes |
| WriteOwner | Take ownership |
| WriteDACL | Modify permissions |
| ForceChangePassword | Reset password |

---

## Group Policy

```powershell
# List GPOs
Get-DomainGPO | Select DisplayName

# Find GPOs that modify local groups
Get-DomainGPOLocalGroup

# GPP passwords (legacy)
Get-GPPPassword
```

---

## Trust Enumeration

```powershell
# Get domain trusts
Get-DomainTrust
Get-ADTrust -Filter *

# Forest trusts
Get-ForestTrust
```

---

## Shares & Sessions

```powershell
# PowerView
Find-DomainShare
Find-DomainShare -CheckShareAccess

# CrackMapExec
crackmapexec smb <DC_IP> -u user -p pass --shares
```

---

## Quick Enumeration Commands

```cmd
# Current domain
echo %userdomain%

# Domain controller
echo %logonserver%

# Current user groups
whoami /groups

# Domain users
net user /domain

# Domain groups
net group /domain

# Domain admins
net group "Domain Admins" /domain
```

---

## Tools Summary

| Tool | Purpose |
|:-----|:--------|
| **BloodHound** | Attack path visualization |
| **PowerView** | AD enumeration (PowerShell) |
| **ADModule** | Official AD PowerShell module |
| **ldapsearch** | LDAP queries |
| **kerbrute** | User enumeration |
| **enum4linux-ng** | SMB/RPC enumeration |
