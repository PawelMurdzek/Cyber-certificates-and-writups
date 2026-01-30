# Hydra

Fast online password brute-forcing tool.

## Basic Syntax

```bash
hydra -l <user> -P <wordlist> <target> <service>
hydra -L <userlist> -P <wordlist> <target> <service>
```

---

## Common Options

| Option | Description |
|:-------|:------------|
| `-l <user>` | Single username |
| `-L <file>` | Username wordlist |
| `-p <pass>` | Single password |
| `-P <file>` | Password wordlist |
| `-C <file>` | Colon-separated user:pass file |
| `-t <num>` | Number of threads (default: 16) |
| `-f` | Stop on first valid login |
| `-V` | Verbose output |
| `-s <port>` | Custom port |

---

## Service Attacks

### SSH
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.10
hydra -L users.txt -P passwords.txt 192.168.1.10 ssh
```

### FTP
```bash
hydra -l admin -P passwords.txt ftp://192.168.1.10
hydra -L users.txt -P passwords.txt 192.168.1.10 ftp
```

### SMB
```bash
hydra -l administrator -P passwords.txt smb://192.168.1.10
```

### RDP
```bash
hydra -l administrator -P passwords.txt rdp://192.168.1.10
```

### MySQL
```bash
hydra -l root -P passwords.txt mysql://192.168.1.10
```

### MSSQL
```bash
hydra -l sa -P passwords.txt mssql://192.168.1.10
```

### PostgreSQL
```bash
hydra -l postgres -P passwords.txt postgres://192.168.1.10
```

### Telnet
```bash
hydra -l admin -P passwords.txt telnet://192.168.1.10
```

---

## Web Forms

### HTTP POST Form
```bash
hydra -l admin -P passwords.txt <target> http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"
```

**Syntax breakdown:**
```
"/path:POST_DATA:FAILURE_STRING"

^USER^ = username placeholder
^PASS^ = password placeholder
F= = Failure indicator (text in failed response)
S= = Success indicator (text in successful response)
```

### HTTP GET Form
```bash
hydra -l admin -P passwords.txt <target> http-get-form "/login.php:user=^USER^&pass=^PASS^:F=Login failed"
```

### HTTP Basic Auth
```bash
hydra -l admin -P passwords.txt <target> http-get /admin/
```

### HTTPS
```bash
hydra -l admin -P passwords.txt <target> https-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"
```

---

## Advanced Options

```bash
# Custom port
hydra -l admin -P passwords.txt -s 2222 192.168.1.10 ssh

# Stop on first success
hydra -l admin -P passwords.txt -f 192.168.1.10 ssh

# Resume interrupted attack
hydra -R

# Wait time between tries (seconds)
hydra -l admin -P passwords.txt -W 3 192.168.1.10 ssh

# Save output
hydra -l admin -P passwords.txt 192.168.1.10 ssh -o results.txt
```

---

## Supported Services

| Service | Protocol |
|:--------|:---------|
| `ssh` | SSH |
| `ftp` | FTP |
| `smb` | SMB/Windows shares |
| `rdp` | Remote Desktop |
| `mysql` | MySQL |
| `mssql` | Microsoft SQL |
| `postgres` | PostgreSQL |
| `telnet` | Telnet |
| `http-get` | HTTP GET |
| `http-post-form` | HTTP POST form |
| `http-head` | HTTP HEAD |
| `smtp` | SMTP |
| `pop3` | POP3 |
| `imap` | IMAP |
| `ldap2` | LDAP |
| `vnc` | VNC |

Full list: `hydra -h`

---

## Tips

1. **Create custom wordlists** using CeWL:
   ```bash
   cewl http://target.com -w custom_wordlist.txt
   ```

2. **Use common username lists**:
   - `/usr/share/seclists/Usernames/top-usernames-shortlist.txt`

3. **Reduce threads** if getting blocked:
   ```bash
   hydra -t 4 ...
   ```

4. **Check for lockout policies** before brute-forcing

---

## Common Wordlists

| Wordlist | Path |
|:---------|:-----|
| RockYou | `/usr/share/wordlists/rockyou.txt` |
| Common passwords | `/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt` |
| Default credentials | `/usr/share/seclists/Passwords/Default-Credentials/` |
