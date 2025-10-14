# Cybersecurity Cheatsheet: Password Cracking

This cheatsheet provides commands for offline password cracking tools John the Ripper and Hashcat.

## John the Ripper (JtR)

A versatile password cracker that auto-detects hash types.

| Command | Description |
| :--- | :--- |
| `john --wordlist=<pass_list> <hash_file>` | **Wordlist Mode**: Cracks hashes using a provided wordlist. |
| `john --single <hash_file>` | **Single Crack Mode**: Uses mangling rules based on login/GECOS information within the hash file (e.g., `/etc/shadow`). |
| `john --incremental <hash_file>` | **Incremental Mode**: A powerful brute-force mode that tries all character combinations. |
| `john --show <hash_file>` | **Show Cracked Passwords**: Displays the passwords that have already been cracked for the given hash file. |
| `john --format=<hash_type> <hash_file>` | **Specify Format**: Forces John to use a specific hash format (e.g., `raw-md5`, `nt`). |

## Hashcat

An extremely fast, GPU-based password cracker.

**Core Syntax**: `hashcat -m <mode> -a <attack_mode> <hash_file> <wordlist/mask>`

| Parameter | Description |
| :--- | :--- |
| `-m <mode>` | **Hash Mode**: An integer specifying the hash type. (e.g., `0` for MD5, `1000` for NTLM, `1800` for SHA-512 crypt). |
| `-a <attack>` | **Attack Mode**: `0` (Wordlist), `1` (Combination), `3` (Brute-force/Mask). |
| `-O` | **Optimized Kernel**: Enable for faster cracking on modern hardware. |
| `--show` | **Show Cracked Passwords**: Displays cracked passwords from the potfile. |

**Example Commands:**
```bash
# Wordlist attack on an MD5 hash
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Brute-force attack on an NTLM hash for a 4-digit PIN (?d = digit)
hashcat -m 1000 -a 3 hashes.txt ?d?d?d?d

# Wordlist attack with rules
hashcat -m 1000 -a 0 hashes.txt passwords.txt -r /usr/share/hashcat/rules/best64.rule