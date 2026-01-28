# SMB Enumeration

Server Message Block (SMB) enumeration for Windows networks.

## Quick Reference

| Port | Service |
|:-----|:--------|
| 139 | NetBIOS Session Service |
| 445 | SMB over TCP (Direct) |

---

## Nmap SMB Scripts

```bash
# Enumerate SMB version
nmap -p 445 --script=smb-protocols <target>

# Enumerate shares
nmap -p 445 --script=smb-enum-shares <target>

# Enumerate users
nmap -p 445 --script=smb-enum-users <target>

# Check for vulnerabilities (EternalBlue, etc.)
nmap -p 445 --script=smb-vuln* <target>

# All SMB enumeration scripts
nmap -p 139,445 --script=smb-enum-* <target>
```

---

## enum4linux-ng

Modern SMB enumeration tool (Linux alternative to enum4linux).

```bash
# Full enumeration
enum4linux-ng -A <target>

# With credentials
enum4linux-ng -A -u 'user' -p 'password' <target>

# Specific checks
enum4linux-ng -U <target>  # Users
enum4linux-ng -S <target>  # Shares
enum4linux-ng -G <target>  # Groups
enum4linux-ng -P <target>  # Password policy
```

---

## smbclient

Connect to SMB shares.

```bash
# List shares (anonymous/null session)
smbclient -L //<target> -N

# List shares with credentials
smbclient -L //<target> -U 'username'

# Connect to a share
smbclient //<target>/share -U 'username'

# Download all files recursively
smbclient //<target>/share -U 'user' -c 'recurse ON; prompt OFF; mget *'
```

### smbclient Commands (once connected)
| Command | Description |
|:--------|:------------|
| `ls` | List files |
| `cd <dir>` | Change directory |
| `get <file>` | Download file |
| `put <file>` | Upload file |
| `mget *` | Download multiple files |
| `exit` | Disconnect |

---

## smbmap

Enumerate shares and permissions.

```bash
# Null session enumeration
smbmap -H <target>

# With credentials
smbmap -H <target> -u 'user' -p 'password'

# With domain
smbmap -H <target> -u 'user' -p 'password' -d 'DOMAIN'

# List contents of a share
smbmap -H <target> -u 'user' -p 'password' -r 'ShareName'

# Download a file
smbmap -H <target> -u 'user' -p 'password' --download 'Share\path\file.txt'

# Execute a command
smbmap -H <target> -u 'admin' -p 'password' -x 'ipconfig'
```

---

## CrackMapExec / NetExec

Swiss army knife for SMB (and more).

```bash
# Check for SMB signing
crackmapexec smb <target>

# Enumerate shares
crackmapexec smb <target> -u 'user' -p 'password' --shares

# Enumerate users
crackmapexec smb <target> -u 'user' -p 'password' --users

# Pass-the-Hash
crackmapexec smb <target> -u 'user' -H 'NTLM_HASH' --shares

# Password spraying
crackmapexec smb <target> -u users.txt -p 'Password123'
```

---

## rpcclient

RPC client for Windows information.

```bash
# Null session
rpcclient -U "" -N <target>

# With credentials
rpcclient -U 'user%password' <target>
```

### rpcclient Commands
| Command | Description |
|:--------|:------------|
| `enumdomusers` | List domain users |
| `enumdomgroups` | List domain groups |
| `queryuser <RID>` | Get user info by RID |
| `getdompwinfo` | Get password policy |
| `lookupnames <user>` | Get SID for username |

---

## Mounting SMB Shares

```bash
# Mount a share (Linux)
mount -t cifs //<target>/share /mnt/share -o username=user,password=pass

# Mount with guest access
mount -t cifs //<target>/share /mnt/share -o guest

# Unmount
umount /mnt/share
```

---

## Common Attack Vectors

| Vector | Description |
|:-------|:------------|
| Null Session | Anonymous access to shares/enumeration |
| Default Credentials | admin:admin, guest:guest |
| Writable Shares | Upload malicious files |
| EternalBlue (MS17-010) | Remote code execution |
| Sensitive Files | Look for passwords.txt, config files |
