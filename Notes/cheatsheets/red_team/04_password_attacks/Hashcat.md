# Hashcat

GPU-accelerated password cracker - extremely fast.

## Basic Syntax

```bash
hashcat -m <mode> -a <attack> <hashes> <wordlist/mask>
```

---

## Hash Modes (-m)

| Mode | Hash Type |
|:-----|:----------|
| `0` | MD5 |
| `100` | SHA1 |
| `1400` | SHA256 |
| `1700` | SHA512 |
| `1000` | NTLM |
| `3000` | LM |
| `1800` | sha512crypt ($6$) - Linux |
| `500` | md5crypt ($1$) - Linux |
| `3200` | bcrypt |
| `13100` | Kerberos TGS (Kerberoast) |
| `18200` | Kerberos AS-REP |
| `5600` | NetNTLMv2 |
| `22000` | WPA-PBKDF2-PMKID+EAPOL |

Full list: `hashcat --help | grep -i "hash-type"`

---

## Attack Modes (-a)

| Mode | Type | Description |
|:-----|:-----|:------------|
| `0` | Dictionary | Wordlist attack |
| `1` | Combination | Combine two wordlists |
| `3` | Brute-force | Mask attack |
| `6` | Hybrid | Wordlist + Mask |
| `7` | Hybrid | Mask + Wordlist |

---

## Dictionary Attack (a=0)

```bash
# Basic wordlist attack
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# With rules
hashcat -m 0 -a 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# Multiple rules
hashcat -m 0 -a 0 hashes.txt wordlist.txt -r rule1.rule -r rule2.rule
```

---

## Brute-Force/Mask Attack (a=3)

### Mask Characters
| Char | Character Set |
|:-----|:--------------|
| `?l` | Lowercase (a-z) |
| `?u` | Uppercase (A-Z) |
| `?d` | Digits (0-9) |
| `?s` | Symbols (!@#$...) |
| `?a` | All printable ASCII |
| `?b` | All bytes (0x00-0xff) |

```bash
# 8 digit PIN
hashcat -m 1000 -a 3 hashes.txt ?d?d?d?d?d?d?d?d

# Common password pattern (Upper, 6 lower, 2 digits)
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?l?l?d?d

# Custom charset (only abc123)
hashcat -m 0 -a 3 hashes.txt -1 abc123 ?1?1?1?1?1
```

### Increment Mode
```bash
# Try lengths 1-8
hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a?a?a?a --increment --increment-min=1
```

---

## Hybrid Attacks

```bash
# Wordlist + 2 digits (password01, password99)
hashcat -m 0 -a 6 hashes.txt wordlist.txt ?d?d

# 4 digits + wordlist (1234password)
hashcat -m 0 -a 7 hashes.txt ?d?d?d?d wordlist.txt
```

---

## Common Options

| Option | Description |
|:-------|:------------|
| `-O` | Optimized kernels (faster, limited password length) |
| `-w 3` | Workload profile (1=low, 3=high) |
| `--force` | Ignore warnings |
| `-o <file>` | Output cracked hashes |
| `--show` | Show previously cracked |
| `--username` | Ignore username in hash file |
| `-r <rules>` | Apply rules |
| `--increment` | Enable increment mode |

---

## Session Management

```bash
# Name session
hashcat -m 0 -a 0 hashes.txt wordlist.txt --session=mycrack

# Restore session
hashcat --restore --session=mycrack

# Status while running
# Press 's' for status
# Press 'p' to pause
# Press 'r' to resume
# Press 'q' to quit
```

---

## Rules

```bash
# Use built-in rules
hashcat -m 0 -a 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# Common rule files:
# /usr/share/hashcat/rules/best64.rule
# /usr/share/hashcat/rules/rockyou-30000.rule
# /usr/share/hashcat/rules/d3ad0ne.rule
# /usr/share/hashcat/rules/dive.rule
```

---

## Examples

```bash
# Crack NTLM with wordlist
hashcat -m 1000 -a 0 ntlm.txt /usr/share/wordlists/rockyou.txt

# Crack MD5 with rules
hashcat -m 0 -a 0 md5.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# Brute-force 4-digit PIN
hashcat -m 1000 -a 3 ntlm.txt ?d?d?d?d

# Crack Kerberoast
hashcat -m 13100 -a 0 kerberoast.txt /usr/share/wordlists/rockyou.txt

# Show cracked passwords
hashcat -m 1000 ntlm.txt --show
```

---

## Viewing Results

```bash
# Show cracked hashes
hashcat -m <mode> hashes.txt --show

# Output to file
hashcat -m <mode> hashes.txt -o cracked.txt
```

---

## Performance Tips

1. Use `-O` for optimized kernels (faster but limited length)
2. Use `-w 3` for maximum GPU usage
3. Use smaller, targeted wordlists with rules
4. Check `hashcat -b` to benchmark your system
