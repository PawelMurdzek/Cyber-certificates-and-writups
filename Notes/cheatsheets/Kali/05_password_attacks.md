# Kali Cheatsheet 5: Password Attacks Cracking hashes or bruteforcing logins. 
### John the Ripper (John) 
- **Description:** A fast password cracker. 
- **Usage:** 
```bash 
# Identify hash format 
john --show hash.txt 
# Crack a hash file using a wordlist 
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
### Hashcat
- **Description:** Advanced GPU-based password cracker.
- **Usage:**
```bash
# -m <hash_type_id> (e.g., 0 for MD5, 1000 for NTLM)
# -a 0 for Dictionary attack
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```
### Hydra
- **Description:** A very fast network logon cracker.
- **Usage:**
```bash
# Bruteforce SSH login
hydra -l user -P /path/to/passwords.txt ssh://192.168.1.105

# Bruteforce a web login form
hydra -l admin -P pass.txt 192.168.1.105 http-post-form "/login.php:username=^USER^&password=^PASS^:F=Login Failed"
```