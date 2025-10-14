# Kali Cheatsheet 6: Web Application Analysis Tools for auditing web applications. 
### Burp Suite 
- **Description:** The industry-standard graphical tool for web app security testing. The Community Edition is included with Kali. It's primarily a GUI tool but can be launched from the CLI. 
- **Usage:** 
```bash 
  # Launch Burp Suite GUI 
  burpsuite
```
_(Configuration is done via the GUI by setting up your browser's proxy to `127.0.0.1:8080`)_

### SQLMap
- **Description:** Automatic SQL injection and database takeover tool.
- **Usage:**
```bash 
    # Scan a URL for SQLi vulnerabilities
    sqlmap -u "[http://testphp.vulnweb.com/artists.php?artist=1](http://testphp.vulnweb.com/artists.php?artist=1)"
    
    # Enumerate databases
    sqlmap -u "http://<url>" --dbs
    
    # Dump a table from a database
    sqlmap -u "http://<url>" -D <database_name> -T <table_name> --dump
```
### Nikto
- **Description:** A web server scanner that checks for dangerous files/CGIs, outdated server software, and other problems.
- **Usage:**
```bash
    nikto -h [http://192.168.1.100](http://192.168.1.100)
```
