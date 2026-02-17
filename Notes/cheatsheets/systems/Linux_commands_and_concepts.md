
# Linux Command Line & Concepts

## Linux Commands

| Command | Description | Example / Options |
| :--- | :--- | :--- |
| **File & Directory Management** | | |
| `ls` | Lists directory contents. | `-a` (all files), `-h` (human-readable) |
| `cd` | Changes the current directory. | `cd /home/user/Documents` |
| `pwd` | Prints the name of the current working directory. | `pwd` |
| `cat` | Concatenates and displays the content of files. | `cat myfile.txt` |
| `touch` | Creates an empty file. | `touch newfile.sh` |
| `mkdir` | Creates a new directory. | `mkdir new_folder` |
| `cp` | Copies files or directories. | `cp source.txt destination.txt` |
| `mv` | Moves or renames files or directories. | `mv old_name.txt new_name.txt` |
| `rm` | Removes files or directories. | `rm file_to_delete.txt` |
| `du` | Estimates file space usage. | `du -sh` (directory summary), `du -h` |
| `file` | Determines the type of a file. | `file my_document` |
| `strings` | Extracts printable strings from binary files. | `strings binary_file` |
| `size` | Lists section sizes of binary files. | `size /bin/ls` |
| **Search & Filtering** | | |
| `find` | Searches for files in a directory hierarchy. | `find / -name "*.txt"`, `find . -type f -perm -4000` (SUID files), `find / -user root -writable 2>/dev/null` |
| `grep` | Searches for patterns within files. | `grep -r "password" .` (recursive), `grep -i "error" log.txt` (case-insensitive), `grep -v "info"` (invert match) |
| `which` | Locates a command's executable path. | `which python` |
| `whereis` | Locates binary, source, and man page files for a command. | `whereis ls` |
| **Text Filtering** | | |
| `head` | Outputs the first part of a file. | `head -n 20 file.txt`, `head -c 100 file` (first 100 bytes) |
| `tail` | Outputs the last part of a file. | `tail -n 20 file.txt`, `tail -f logfile.log` (follow live) |
| `sort` | Sorts lines of text. | `sort file.txt`, `sort -n` (numeric), `sort -r` (reverse) |
| `uniq` | Filters out repeated lines. | `sort file.txt \| uniq`, `uniq -c` (count occurrences) |
| `wc` | Counts lines, words, and bytes. | `wc -l file.txt` (lines), `wc -w` (words), `wc -c` (bytes) |
| `cut` | Removes sections from each line. | `cut -d':' -f1 /etc/passwd`, `cut -c1-10 file.txt` |
| `awk` | Pattern scanning and processing language. | `awk '{print $1}' file`, `awk -F: '{print $1}' /etc/passwd` |
| `sed` | Stream editor for filtering and transforming text. | `sed 's/old/new/g' file`, `sed -n '5,10p' file` (lines 5-10) |
| `tr` | Translates or deletes characters. | `tr 'a-z' 'A-Z'` (to uppercase), `tr -d '\r'` (remove char) |
| **User & Permissions** | | |
| `whoami` | Displays the current username. | `whoami` |
| `id` | Displays user and group IDs. | `id`, `id username` |
| `su` | Switches to another user account. | `su otheruser`, `su - root` (login shell) |
| `chmod` | Changes file mode bits (permissions). | `chmod 755 script.sh`, `chmod +x script.sh` |
| **Networking & File Transfer** | | |
| `ss` | A utility to investigate sockets. Shows active connections. | `ss -tuna`, `ss -lntp` (listening ports with process) |
| `netstat` | (Deprecated) Prints network connections, routing tables, etc. | `netstat -ano`, `netstat -tulpn` |
| `ssh` | Secure Shell client for remote login. | `ssh username@192.168.1.100`, `ssh -L 8080:localhost:80 user@host` (port forwarding) |
| `xfreerdp` | Remote Desktop Protocol client. | `xfreerdp /v:IP /u:User /p:Pass /cert:ignore /dynamic-resolution /drive:share,./` |
| `wget` | Downloads files from the web via HTTP/HTTPS. | `wget https://example.com/file.zip`, `wget -q -O - URL` (quiet, stdout) |
| `curl` | Transfers data from or to a server. | `curl -X POST -d "data" URL`, `curl -s URL`, `curl -o file.txt URL` |
| `scp` | Securely copies files between hosts on a network. | `scp file.txt user@host:/remote/dir/`, `scp -r folder/ user@host:/path/` |
| `ftp` | Interactive File Transfer Protocol client. | `ftp 192.168.1.100` |
| `sftp` | Secure File Transfer Protocol client. | `sftp user@host` |
| `GET`, `POST` | Simple command line HTTP agents. | `GET http://example.com` |
| `python3 -m http.server` | Starts a simple HTTP web server in the current directory. | `python3 -m http.server 8000` |

### Raw / Interactive HTTP (via Netcat/Telnet)

Connect: `nc target.com 80` or `telnet target.com 80`

```http
# Basic GET Request
GET / HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0
<enter>
<enter>

# Basic HEAD Request (Headers only)
HEAD / HTTP/1.1
Host: target.com
<enter>
<enter>
```

## Network Reconnaissance

See [[Nmap]] for detailed usage.
| **Process Management** | | |
| `ps` | Reports a snapshot of the current processes. | `ps aux` (all processes), `ps -ef \| grep nginx`, `ps aux --sort=-%mem` (by memory) |
| `top` | Displays a real-time view of running system processes. | `top`, `htop` (better alternative) |
| `kill` | Sends a signal to a process, typically to terminate it. | `kill 12345` (SIGTERM), `kill -9 12345` (SIGKILL) |
| `pkill` | Kills processes by name. | `pkill nginx`, `pkill -9 python`, `pkill -u username` |
| **System & Service Management** | | |
| `systemctl` | Controls the systemd system and service manager. | `systemctl start apache2` `systemctl enable ssh` |
| `UFW` | Uncomplicated Firewall. A tool to manage the firewall. | `ufw enable`, `ufw allow 22` |
| `fail2ban` | A service that monitors logs for failed login attempts and bans IPs. | (Managed as a service) |
| **Package Management** | | |
| `apt` | Advanced Package Tool for managing software packages. | `apt update`, `apt install nano` |
| `dpkg` | A low-level tool to install, remove, and manage Debian packages. | `dpkg -i package.deb` |
| `add-apt-repository` | Adds an external APT repository to the system. | `add-apt-repository ppa:user/ppa-name` |
| **Miscellaneous** | | |
| `echo` | Displays a line of text. | `echo "Hello, World!"` |
| `man` | Displays the on-line manual pages for commands. | `man ls` |
| `history` | Displays command history list. | `history 10` (last 10), `!5` (run cmd 5), `!!` (run last) |

## FTP & SFTP Interactive Commands

| Command | Description |
| :--- | :--- |
| `get` | Download file from server. |
| `put` | Upload file to server. |
| `mget` | Download multiple files. |
| `mput` | Upload multiple files. |
| `ls` | List directory on server. |
| `cd` | Change directory on server. |
| `lcd` | Change local directory. |
| `binary` | Switch to binary transfer mode. |
| `ascii` | Switch to ascii transfer mode. |
| `bye` | Exit the client. |

#### **Local Shell & Automation (FTP)**

| Command | Description |
| :--- | :--- |
| `!ls` | Run `ls` on **local** machine (not server). |
| `!mkdir dir` | Create directory on **local** machine. |
| `lcd /path` | Change **local** directory. |
| `prompt` | Toggle interactive prompting (useful for `mget`). |
| `$ macro_name` | Execute a defined macro. |


## Shell Operators and Job Control

| Operator/Shortcut | Description |
| :--- | :--- |
| `&` | Runs a command in the background. |
| `&&` | "AND" operator. Runs the second command only if the first one succeeds. |
| `>` | Redirects the output of a command to a file, overwriting the file. |
| `>>` | Appends the output of a command to a file. |
| `Ctrl + Z` | Suspends the current foreground process. |
| `fg` | Resumes a suspended process and brings it to the foreground. |

### Output Redirection Examples

```bash
# Hide errors (redirect stderr to /dev/null)
command 2>/dev/null

# Hide everything (stdout and stderr)
command > /dev/null 2>&1

# Save errors to a file
command 2> errors.log

# Save everything to a file
command > output.log 2>&1
```

## Shell Scripting

| Command / Concept | Syntax / Description | Example |
| :--- | :--- | :--- |
| **Input** | | |
| `read` | Read user input into a variable. | `read -p "Enter name: " name`<br>`echo "Hello $name"` |
| **Conditionals** | | |
| `if` statement | Execute commands based on a condition. | `if [ "$a" -gt "$b" ]; then`<br>&nbsp;&nbsp;`echo "Greater"`<br>`fi` |
| `if-else` | Handle true and false cases. | `if [ -f "file.txt" ]; then`<br>&nbsp;&nbsp;`echo "Exists"`<br>`else`<br>&nbsp;&nbsp;`echo "Missing"`<br>`fi` |
| Comparison Ops | Integers: `-eq`, `-ne`, `-gt`, `-lt`. Strings: `=`, `!=`, `-z` (empty). Files: `-f` (file), `-d` (dir) | `[ "$a" -eq 10 ]`, `[ -z "$var" ]` |
| **Loops** | | |
| `for` loop | Iterate over a list or range. | `for i in {1..5}; do`<br>&nbsp;&nbsp;`echo "Num: $i"`<br>`done` |
| `while` loop | Repeat while condition is true. | `while [ "$x" -lt 5 ]; do`<br>&nbsp;&nbsp;`((x++))`<br>`done` |

## Automation with Cron

`cron` is a time-based job scheduler. User tasks are defined in a `crontab` file.

A `crontab` entry has 6 fields:
`MIN HOUR DOM MON DOW CMD`
- **MIN**: Minute (0-59)
- **HOUR**: Hour (0-23)
- **DOM**: Day of Month (1-31)
- **MON**: Month (1-12)
- **DOW**: Day of Week (0-7, Sun=0 or 7)
- **CMD**: The command to be executed.

An asterisk (`*`) in a field means "every".

**Example**: Run a backup script every 12 hours.
0 */12 * * * cp -R /home/user/Documents /var/backups/

**Special String**: `@reboot` runs a command once at startup.

**Crontab Generators**:
- [https://crontab-generator.org/](https://crontab-generator.org/)
- [https://crontab.guru/](https://crontab.guru/)

## Package Management (APT)

Managing software from third-party repositories typically involves three steps:

1.  **Trust the GPG Key**: Download the distributor's GPG key to verify the software's authenticity.
    ```bash
    wget -qO - [https://example.com/key.gpg](https://example.com/key.gpg) | sudo apt-key add -
    ```
2.  **Add the Repository**: Add the software repository to your system's sources list, usually in `/etc/apt/sources.list.d/`.
    ```bash
    echo "deb [arch=amd64] [https://example.com/](https://example.com/) stable main" | sudo tee /etc/apt/sources.list.d/example.list
    ```
3.  **Update and Install**: Update your package list and install the software.
    ```bash
    sudo apt update
    sudo apt install software-name
    ```

To remove the software and repository, use `apt remove` and delete the repository file from `/etc/apt/sources.list.d/`.
`