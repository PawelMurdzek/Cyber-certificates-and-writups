# Kali Cheatsheet 3: Scanning & Enumeration
Actively discovering hosts, open ports, services, and vulnerabilities.
### ### Nmap (Network Mapper) 
- **Description:** The most popular tool for network discovery and security auditing. 
- **Common Scans:** 
```bash 
  # Intense scan: OS detection (-O), version detection (-sV), script scanning (-sC), and traceroute (--traceroute) 
  sudo nmap -A 192.168.1.1 
  # Fast scan of top 100 ports 
  nmap -F 192.168.1.1 
  # Scan a full subnet for live hosts (ping scan) 
  nmap -sn 192.168.1.0/24 
  # Scan all 65535 TCP ports (can be slow) 
  sudo nmap -p- -T4 192.168.1.1 
  # Scan for UDP ports 
  sudo nmap -sU 192.168.1.1 
  # Scan using default NSE scripts to find vulnerabilities 
  sudo nmap --script vuln 192.168.1.1 -oN nmap_vuln.txt
  # Scan all 65535 TCP ports (can be slow) 
  sudo nmap -p- -T4 192.168.1.1 
  # Scan for UDP ports 
  sudo nmap -sU 192.168.1.1 
  # Scan using default NSE scripts to find vulnerabilities 
  sudo nmap --script vuln 192.168.1.1 -oN nmap_vuln.txt
  ```
### Gobuster / Dirb / Feroxbuster
- **Description:** Bruteforce URIs (directories and files) on web servers.
- **Usage (Gobuster):**
```bash
  # Find directories
  gobuster dir -u [http://192.168.1.100](http://192.168.1.100) -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    
  # Find files with specific extensions
  gobuster dir -u [http://192.168.1.100](http://192.168.1.100) -w <wordlist> -x php,txt,html
```
### enum4linux

- **Description:** A tool for enumerating information from Windows and Samba systems.
- **Usage:**
```bash
    enum4linux -a 192.168.1.105
```