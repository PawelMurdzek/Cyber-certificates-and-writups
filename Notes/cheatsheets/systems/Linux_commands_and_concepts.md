
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
| `file` | Determines the type of a file. | `file my_document` |
| `strings` | Extracts printable strings from binary files. | `strings binary_file` |
| **Search & Filtering** | | |
| `find` | Searches for files in a directory hierarchy. | `find . -name "*.txt"` |
| `grep` | Searches for patterns within files. | `grep "error" logfile.log` |
| **User & Permissions** | | |
| `whoami` | Displays the current username. | `whoami` |
| `su` | Switches to another user account. | `su otheruser` |
| `chmod` | Changes file mode bits (permissions). | `chmod 755 script.sh` |
| **Networking & File Transfer** | | |
| `ss` | A utility to investigate sockets. Shows active connections. | `ss -tuna` |
| `netstat` | (Deprecated) Prints network connections, routing tables, etc. | `netstat -ano` |
| `ssh` | Secure Shell client for remote login. | `ssh username@192.168.1.100` |
| `wget` | Downloads files from the web via HTTP/HTTPS. | `wget https://example.com/file.zip` |
| `scp` | Securely copies files between hosts on a network. | `scp file.txt user@host:/remote/dir/` |
| `python3 -m http.server` | Starts a simple HTTP web server in the current directory. | `python3 -m http.server 8000` |
| **Process Management** | | |
| `ps` | Reports a snapshot of the current processes. | `ps aux` (shows all processes) |
| `top` | Displays a real-time view of running system processes. | `top` |
| `kill` | Sends a signal to a process, typically to terminate it. | `kill 12345` (sends SIGTERM), `kill -9 12345` (sends SIGKILL) |
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

## Shell Operators and Job Control

| Operator/Shortcut | Description |
| :--- | :--- |
| `&` | Runs a command in the background. |
| `&&` | "AND" operator. Runs the second command only if the first one succeeds. |
| `>` | Redirects the output of a command to a file, overwriting the file. |
| `>>` | Appends the output of a command to a file. |
| `Ctrl + Z` | Suspends the current foreground process. |
| `fg` | Resumes a suspended process and brings it to the foreground. |

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