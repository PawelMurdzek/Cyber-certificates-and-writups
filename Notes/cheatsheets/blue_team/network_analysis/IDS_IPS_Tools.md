# Network Analysis & IDS/IPS Tools

## NetworkMiner
Passive network sniffer / PCAP analyzer. 
- **Usage**: Open a `.pcap` file to extract files, credentials, images, and host details automatically.
- **Key Features**: OS fingerprinting, open ports discovery, file extraction/reassembly.

## Snort
Open Source IDS/IPS.

### Rule Syntax
```text
action proto src_ip src_port -> dest_ip dest_port (options)
```
**Example**:
```text
alert tcp any any -> 192.168.1.0/24 22 (msg:"SSH Connection Attempt"; sid:1000001; rev:1;)
```

### Common Commands
- **Test Configuration**: `snort -T -c /etc/snort/snort.conf`
- **Run in Console Mode**: `snort -A console -c /etc/snort/snort.conf -i eth0`
- **Read PCAP**: `snort -r capture.pcap -c /etc/snort/snort.conf`

## Suricata
High-performance Network IDS, IPS, and Network Security Monitoring engine.

### Rule Syntax (Compatible with Snort)
```text
alert http any any -> any any (msg:"Suspicious User-Agent"; content:"User-Agent: Evil"; sid:200001;)
```

### Common Commands
- **Update Rules**: `suricata-update`
- **Test Config**: `suricata -T -c /etc/suricata/suricata.yaml`
- **Run**: `suricata -c /etc/suricata/suricata.yaml -i eth0`

## Zeal / Bro (See Zeek_cheatsheet.md)
Reference `Zeek_cheatsheet.md` in this folder for Zeek specifics.
