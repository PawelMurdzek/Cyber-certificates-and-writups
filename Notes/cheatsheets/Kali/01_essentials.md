# Kali Cheatsheet 1: Essential Linux & Network Commands

These are fundamental commands for navigating the shell and managing network connections.

### File & Directory Management
| Command | Description | Example |
| :--- | :--- | :--- |
| `ls -la` | List all files (including hidden) in long format. | `ls -la /var/www` |
| `cd <dir>` | Change directory. | `cd /tmp` |
| `pwd` | Print the current working directory. | `pwd` |
| `mkdir <dir>` | Create a new directory. | `mkdir new_folder` |
| `rm -rf <file/dir>` | Remove a file or directory forcefully. | `rm -rf old_folder` |
| `cp <src> <dest>` | Copy a file or directory. | `cp report.txt /mnt/share` |
| `mv <src> <dest>` | Move or rename a file or directory. | `mv notes.txt secrets.txt` |
| `cat <file>` | Display file content. | `cat /etc/passwd` |
| `less <file>` | View file content page by page. | `less /var/log/syslog` |
| `find / -name <name>` | Find files by name, starting from root. | `find / -name "config.php"` |
| `grep <pattern> <file>` | Search for a pattern within a file. | `grep "admin" users.txt` |
| `chmod <perms> <file>` | Change file permissions. | `chmod 755 script.sh` |
| `chown <user>:<group> <file>` | Change file ownership. | `chown www-data:www-data config.php`|
| `wget <url>` | Download a file from a URL. | `wget https://example.com/tool.zip` |
| `curl <url>` | Transfer data from or to a server. | `curl -I https://example.com` |

### Network & System
| Command | Description | Example |
| :--- | :--- | :--- |
| `ip a` or `ifconfig` | Show network interface configuration. | `ip a` |
| `ping <host>` | Check connectivity to a host. | `ping 8.8.8.8` |
| `netstat -antup` | Show all listening ports and connections. | `sudo netstat -antup` |
| `ss -antup` | Modern replacement for `netstat`. | `sudo ss -antup` |
| `whoami` | Display the current username. | `whoami` |
| `ps aux` | List all running processes. | `ps aux` |
| `kill <pid>` | Terminate a process by its ID. | `kill 1234` |
| `ssh <user>@<host>` | Connect to a host via SSH. | `ssh admin@192.168.1.100` |
| `scp <file> <user>@<host>:<path>`| Securely copy a file to a remote host. | `scp shell.php user@host:/var/www/html`|
