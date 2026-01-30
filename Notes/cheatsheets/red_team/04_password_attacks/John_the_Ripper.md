# John the Ripper

Versatile offline password cracker.

## Basic Usage

```bash
# Crack with wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Show cracked passwords
john --show hashes.txt
```

---

## Attack Modes

### Wordlist Mode
```bash
john --wordlist=passwords.txt hashes.txt

# With rules (mutations)
john --wordlist=passwords.txt --rules hashes.txt
john --wordlist=passwords.txt --rules=best64 hashes.txt
```

### Single Crack Mode
Uses username/GECOS info for password guessing:
```bash
john --single hashes.txt
```

### Incremental (Brute Force)
```bash
# All characters
john --incremental hashes.txt

# Specific character set
john --incremental=digits hashes.txt
john --incremental=alpha hashes.txt
```

---

## Hash Format Specification

```bash
# List supported formats
john --list=formats

# Specify format
john --format=raw-md5 hashes.txt
john --format=nt hashes.txt
john --format=sha512crypt hashes.txt
```

### Common Formats

| Format | Description |
|:-------|:------------|
| `raw-md5` | Plain MD5 |
| `raw-sha1` | Plain SHA1 |
| `raw-sha256` | Plain SHA256 |
| `nt` | NTLM (Windows) |
| `lm` | LM (Legacy Windows) |
| `sha512crypt` | Linux shadow ($6$) |
| `sha256crypt` | Linux shadow ($5$) |
| `md5crypt` | Linux shadow ($1$) |
| `bcrypt` | bcrypt ($2a$) |
| `krb5tgs` | Kerberoast |

---

## Extracting Hashes

### From Shadow File
```bash
# Combine passwd and shadow
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john unshadowed.txt
```

### From ZIP Files
```bash
zip2john archive.zip > zip_hash.txt
john zip_hash.txt
```

### From RAR Files
```bash
rar2john archive.rar > rar_hash.txt
john rar_hash.txt
```

### From PDF Files
```bash
pdf2john doc.pdf > pdf_hash.txt
john pdf_hash.txt
```

### SSH Private Keys
```bash
ssh2john id_rsa > ssh_hash.txt
john ssh_hash.txt
```

### KeePass Databases
```bash
keepass2john database.kdbx > keepass_hash.txt
john keepass_hash.txt
```

### Office Documents
```bash
office2john document.docx > office_hash.txt
john office_hash.txt
```

---

## Session Management

```bash
# Name a session
john --session=mycrack --wordlist=rockyou.txt hashes.txt

# Resume session
john --restore=mycrack

# Check status (while running)
# Press any key for status
```

---

## Rules

Rules apply mutations to wordlist entries:

```bash
# Use default rules
john --wordlist=words.txt --rules hashes.txt

# Specific rule set
john --wordlist=words.txt --rules=Jumbo hashes.txt
john --wordlist=words.txt --rules=KoreLogic hashes.txt

# List available rules
john --list=rules
```

---

## Performance Options

```bash
# Use specific CPU cores (fork)
john --fork=4 hashes.txt

# Set maximum run time
john --max-run-time=3600 hashes.txt
```

---

## Viewing Results

```bash
# Show all cracked passwords
john --show hashes.txt

# Show in user:pass format
john --show --format=nt hashes.txt

# Show specific format
john --show --format=raw-md5 hashes.txt
```

---

## Examples

```bash
# Crack Linux passwords
unshadow /etc/passwd /etc/shadow > linux_hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt linux_hashes.txt

# Crack Windows NTLM
john --format=nt --wordlist=rockyou.txt ntlm_hashes.txt

# Crack MD5 hashes
john --format=raw-md5 --wordlist=rockyou.txt md5_hashes.txt

# Crack with rules
john --wordlist=custom.txt --rules=best64 hashes.txt

# Show what was cracked
john --show hashes.txt
```

---

## Hash File Format

```
# Simple format (auto-detect)
hash1
hash2

# With username
user1:hash1
user2:hash2

# Linux shadow format
username:$6$salt$hash:...
```
