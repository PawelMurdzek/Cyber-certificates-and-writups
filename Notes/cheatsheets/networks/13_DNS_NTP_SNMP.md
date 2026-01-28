# DNS, NTP, SNMP Overview

## DNS (Domain Name System)

### DNS Purpose
- Resolves hostnames to IP addresses
- Enables human-readable naming
- Distributed hierarchical database

### DNS Ports
- **UDP 53**: Standard queries
- **TCP 53**: Zone transfers, large responses

### DNS Record Types

| Type | Purpose | Example |
|------|---------|---------|
| **A** | IPv4 address | example.com → 192.168.1.1 |
| **AAAA** | IPv6 address | example.com → 2001:db8::1 |
| **CNAME** | Alias | www → example.com |
| **MX** | Mail server | mail.example.com, priority 10 |
| **NS** | Name server | ns1.example.com |
| **PTR** | Reverse lookup | 1.1.168.192.in-addr.arpa → example.com |
| **SOA** | Zone authority | Primary NS, admin email, serial |
| **TXT** | Text data | SPF, DKIM records |
| **SRV** | Service location | _sip._tcp.example.com |

### DNS Hierarchy
```
Root (.)
  └── TLD (.com, .org, .net, .edu)
        └── Domain (example.com)
              └── Subdomain (www.example.com)
```

### DNS Resolution Process
1. Client checks local cache
2. Query → Recursive resolver (ISP or 8.8.8.8)
3. Resolver queries root servers
4. Root refers to TLD server
5. TLD refers to authoritative server
6. Authoritative answers with IP
7. Resolver caches and returns to client

### Cisco DNS Client Configuration
```cisco
! Configure DNS servers
ip name-server 8.8.8.8 8.8.4.4

! Enable DNS lookup
ip domain-lookup

! Set domain name
ip domain-name example.com

! Verify
show hosts
```

### Disable DNS Lookup (prevent typo delays)
```cisco
no ip domain-lookup
```

---

## NTP (Network Time Protocol)

### NTP Purpose
- Synchronizes clocks across devices
- Critical for: logs, authentication, troubleshooting
- **Port**: UDP 123
- **Accuracy**: Milliseconds typically

### Stratum Levels
| Stratum | Description |
|---------|-------------|
| 0 | Atomic clock, GPS (reference clock) |
| 1 | Directly connected to stratum 0 |
| 2 | Syncs from stratum 1 |
| ... | Each level adds ~1 stratum |
| 15 | Maximum valid stratum |
| 16 | Unsynchronized |

### NTP Configuration

#### NTP Client
```cisco
! Point to NTP server
ntp server 0.pool.ntp.org
ntp server 1.pool.ntp.org

! Prefer specific server
ntp server 192.168.1.1 prefer

! Verify
show ntp status
show ntp associations
show clock
```

#### NTP Server
```cisco
! Act as NTP server using local clock
ntp master 3                    ! Stratum 3

! Verify
show ntp status
```

#### NTP Authentication
```cisco
! Configure authentication
ntp authenticate
ntp authentication-key 1 md5 MyPassword
ntp trusted-key 1
ntp server 192.168.1.1 key 1
```

### Clock Configuration
```cisco
! Set timezone
clock timezone EST -5
clock summer-time EDT recurring

! Manually set clock
clock set 14:30:00 28 Jan 2026
```

### NTP Verification
```cisco
show ntp status
show ntp associations
show ntp associations detail
show clock
show clock detail
```

---

## SNMP (Simple Network Management Protocol)

### SNMP Purpose
- Monitor and manage network devices
- Collect performance data
- Send alerts (traps)

### SNMP Versions

| Version | Security | Features |
|---------|----------|----------|
| **SNMPv1** | Community string (plaintext) | Basic, insecure |
| **SNMPv2c** | Community string (plaintext) | GetBulk, better errors |
| **SNMPv3** | Authentication + Encryption | Secure, recommended |

### SNMP Components

| Component | Description |
|-----------|-------------|
| **Manager** | NMS (Network Management System) |
| **Agent** | Runs on managed device |
| **MIB** | Management Information Base (database) |
| **OID** | Object Identifier (MIB entry path) |
| **Trap** | Unsolicited alert from agent |

### SNMP Operations

| Operation | Port | Direction | Purpose |
|-----------|------|-----------|---------|
| **Get** | UDP 161 | Manager → Agent | Request single value |
| **GetNext** | UDP 161 | Manager → Agent | Request next OID |
| **GetBulk** | UDP 161 | Manager → Agent | Request multiple values |
| **Set** | UDP 161 | Manager → Agent | Change value |
| **Trap** | UDP 162 | Agent → Manager | Unsolicited alert |
| **Inform** | UDP 162 | Agent → Manager | Acknowledged trap |

### SNMPv2c Configuration
```cisco
! Enable SNMP agent
snmp-server community PUBLIC ro         ! Read-only community
snmp-server community PRIVATE rw        ! Read-write community

! Restrict to specific host
snmp-server community PUBLIC ro 10      ! ACL 10 restricts access
access-list 10 permit 192.168.1.100

! Configure SNMP location and contact
snmp-server location "Data Center, Rack 5"
snmp-server contact admin@example.com

! Configure traps
snmp-server enable traps
snmp-server host 192.168.1.100 PUBLIC

! Specific traps
snmp-server enable traps snmp linkdown linkup
snmp-server enable traps config
```

### SNMPv3 Configuration (Secure)
```cisco
! Create SNMP group
snmp-server group ADMIN-GROUP v3 priv

! Create SNMP user
snmp-server user admin ADMIN-GROUP v3 auth sha AuthPass123 priv aes 128 PrivPass123

! Configure SNMPv3 host
snmp-server host 192.168.1.100 version 3 priv admin

! Verify
show snmp user
show snmp group
show snmp host
```

### SNMPv3 Security Levels

| Level | Authentication | Encryption | Keyword |
|-------|----------------|------------|---------|
| noAuthNoPriv | No | No | `noauth` |
| authNoPriv | Yes | No | `auth` |
| authPriv | Yes | Yes | `priv` |

### SNMP Verification
```cisco
show snmp
show snmp community
show snmp host
show snmp user
show snmp group
```

---

## Syslog

### Syslog Purpose
- Centralized logging from network devices
- Essential for troubleshooting and security
- **Port**: UDP 514 (default)

### Syslog Severity Levels

| Level | Keyword | Description | Example |
|-------|---------|-------------|---------|
| 0 | Emergency | System unusable | Kernel crash |
| 1 | Alert | Immediate action needed | Interface down |
| 2 | Critical | Critical conditions | Memory error |
| 3 | Error | Error conditions | Config error |
| 4 | Warning | Warning conditions | CPU high |
| 5 | Notice | Normal but significant | Reload complete |
| 6 | Informational | Informational messages | ACL match |
| 7 | Debug | Debug messages | Debug output |

> **Mnemonic**: Every Awesome Cisco Engineer Will Need Icecream Daily

### Syslog Configuration
```cisco
! Enable logging
logging on

! Log to remote syslog server
logging host 192.168.1.100
logging host 192.168.1.101

! Set severity level (log this level and above)
logging trap informational          ! 0-6

! Console logging
logging console warnings            ! 0-4

! Buffer logging
logging buffered 16384 informational

! Add timestamps
service timestamps log datetime msec localtime

! Enable sequence numbers
service sequence-numbers

! Logging source interface
logging source-interface Loopback0
```

### Log to Multiple Destinations
```cisco
! Console
logging console 6               ! Informational and above

! Monitor (VTY sessions)
logging monitor 6
terminal monitor                ! Enable for current session

! Buffer
logging buffered 32768 6

! Syslog server
logging trap 6
logging host 192.168.1.100
```

### View Logs
```cisco
show logging
show logging | include %LINK
```

---

## Common Management Protocols Summary

| Protocol | Port(s) | Purpose |
|----------|---------|---------|
| SSH | TCP 22 | Secure remote access |
| Telnet | TCP 23 | Unsecure remote access |
| HTTP | TCP 80 | Web interface |
| HTTPS | TCP 443 | Secure web interface |
| DNS | UDP/TCP 53 | Name resolution |
| NTP | UDP 123 | Time synchronization |
| SNMP | UDP 161/162 | Monitoring/traps |
| Syslog | UDP 514 | Logging |
| TFTP | UDP 69 | File transfer |
| FTP | TCP 20/21 | File transfer |
| SCP | TCP 22 | Secure file transfer |

---

## Best Practices

### DNS
- Use redundant DNS servers
- Consider public DNS as backup (8.8.8.8, 1.1.1.1)
- Disable DNS lookup in CLI to prevent delays

### NTP
- Synchronize all devices to same time source
- Use authentication for NTP
- Configure multiple NTP servers
- Use stratum 2-3 servers (not stratum 1 directly)

### SNMP
- **Use SNMPv3** with authPriv
- Change default community strings
- Restrict SNMP access with ACLs
- Disable SNMP if not needed

### Syslog
- Send logs to centralized server
- Use appropriate severity levels
- Enable timestamps
- Regular log review

---

## Quick Reference

| Task | Command |
|------|---------|
| DNS server | `ip name-server [ip]` |
| Disable DNS lookup | `no ip domain-lookup` |
| NTP server | `ntp server [ip]` |
| Show NTP | `show ntp status` |
| SNMP community | `snmp-server community [name] ro/rw` |
| SNMP trap host | `snmp-server host [ip] [community]` |
| Syslog server | `logging host [ip]` |
| Syslog level | `logging trap [level]` |
| Show logs | `show logging` |
