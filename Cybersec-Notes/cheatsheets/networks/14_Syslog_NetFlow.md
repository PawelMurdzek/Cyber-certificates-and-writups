# Syslog and NetFlow

## Syslog Deep Dive

### Syslog Architecture
```
Device (Agent) ────UDP 514────> Syslog Server
                               (Collector)
```

### Syslog Message Format
```
<Priority>Timestamp Hostname: %Facility-Severity-Mnemonic: Description

Example:
<165>Jan 28 14:30:00 Router1: %LINK-3-UPDOWN: Interface GigabitEthernet0/0, changed state to down
```

### Common Facilities

| Facility | Description |
|----------|-------------|
| %LINK | Interface link status |
| %LINEPROTO | Line protocol status |
| %SYS | System messages |
| %SEC | Security messages |
| %SSH | SSH events |
| %OSPF | OSPF events |
| %HSRP | HSRP events |
| %ACL | ACL matches |

### Syslog Configuration Examples

```cisco
! Basic syslog server
logging host 192.168.1.100

! Syslog with transport options
logging host 192.168.1.100 transport tcp port 1514
logging host 192.168.1.100 transport udp port 514

! Configure all logging destinations
logging console critical          ! Only critical to console
logging monitor informational     ! Info to VTY sessions
logging buffered 65536 debugging  ! All to buffer
logging trap notifications        ! Warnings+ to syslog

! Timestamps with precision
service timestamps log datetime msec localtime show-timezone

! Add sequence numbers
service sequence-numbers

! Source interface for syslog
logging source-interface Loopback0

! Facility override
logging facility local7
```

### Log Rate Limiting
```cisco
! Limit duplicate messages
logging rate-limit 10 except critical
logging rate-limit console 10
```

### Viewing and Managing Logs
```cisco
! View log buffer
show logging
show logging | include OSPF
show logging | include %SYS
show logging | section config

! Clear log buffer
clear logging

! Show logging configuration
show logging history
```

---

## NetFlow

### NetFlow Purpose
- **Traffic analysis**: Who's talking to whom?
- **Capacity planning**: Bandwidth utilization
- **Security monitoring**: Detect anomalies
- **Billing**: Account for network usage

### NetFlow Versions

| Version | Features |
|---------|----------|
| **v5** | Fixed format, IPv4 only |
| **v9** | Template-based, flexible, IPv6 |
| **IPFIX** | Industry standard (based on v9) |

### NetFlow Components

| Component | Description |
|-----------|-------------|
| **Flow** | Unique traffic conversation |
| **Flow Record** | Key fields defining a flow |
| **Flow Exporter** | Router sending flow data |
| **Flow Collector** | Server receiving/analyzing data |

### What Defines a Flow? (5/7-tuple)
1. Source IP address
2. Destination IP address
3. Source port
4. Destination port
5. IP protocol
6. Type of Service (ToS)
7. Input interface

### Traditional NetFlow Configuration
```cisco
! Enable NetFlow on interface
interface GigabitEthernet0/0
  ip flow ingress
  ip flow egress

! Configure NetFlow export
ip flow-export version 9
ip flow-export destination 192.168.1.200 9996
ip flow-export source Loopback0

! Optional settings
ip flow-cache timeout active 1
ip flow-cache timeout inactive 15
```

### Flexible NetFlow Configuration
```cisco
! Create flow record
flow record CUSTOM-RECORD
  match ipv4 source address
  match ipv4 destination address
  match transport source-port
  match transport destination-port
  match ipv4 protocol
  match interface input
  collect counter bytes
  collect counter packets
  collect timestamp sys-uptime first
  collect timestamp sys-uptime last

! Create flow exporter
flow exporter EXPORTER-1
  destination 192.168.1.200
  source Loopback0
  transport udp 9996
  export-protocol netflow-v9
  template data timeout 60

! Create flow monitor
flow monitor FLOW-MONITOR-1
  record CUSTOM-RECORD
  exporter EXPORTER-1
  cache timeout active 60
  cache timeout inactive 15

! Apply to interface
interface GigabitEthernet0/0
  ip flow monitor FLOW-MONITOR-1 input
  ip flow monitor FLOW-MONITOR-1 output
```

### NetFlow Verification
```cisco
! Traditional NetFlow
show ip flow export
show ip cache flow

! Flexible NetFlow
show flow monitor
show flow monitor FLOW-MONITOR-1 cache
show flow exporter
show flow record
```

---

## IP SLA (Service Level Agreement)

### IP SLA Purpose
- Monitor network performance
- Measure latency, jitter, packet loss
- Trigger actions based on thresholds

### Common IP SLA Operations

| Operation | Measures | Use Case |
|-----------|----------|----------|
| **ICMP Echo** | RTT, packet loss | Reachability |
| **UDP Jitter** | Jitter, latency, loss | VoIP quality |
| **TCP Connect** | Connection time | Service availability |
| **HTTP** | Web server response | Application monitoring |
| **DNS** | DNS resolution time | DNS performance |

### IP SLA Configuration

#### ICMP Echo (Basic Ping)
```cisco
! Define SLA operation
ip sla 1
  icmp-echo 8.8.8.8 source-ip 192.168.1.1
  frequency 30

! Schedule SLA
ip sla schedule 1 life forever start-time now

! Verify
show ip sla configuration
show ip sla statistics
```

#### UDP Jitter (VoIP Testing)
```cisco
! On responder (remote end)
ip sla responder

! On initiator
ip sla 2
  udp-jitter 192.168.2.1 16384 source-ip 192.168.1.1
  frequency 60

ip sla schedule 2 life forever start-time now
```

#### HTTP Operation
```cisco
ip sla 3
  http get http://www.example.com
  frequency 300

ip sla schedule 3 life forever start-time now
```

### IP SLA Tracking
```cisco
! Track SLA result
track 1 ip sla 1 reachability

! Use with static route (floating)
ip route 0.0.0.0 0.0.0.0 192.168.1.1 track 1
ip route 0.0.0.0 0.0.0.0 192.168.2.1 10     ! Backup (higher AD)
```

### IP SLA Verification
```cisco
show ip sla configuration
show ip sla statistics
show ip sla statistics aggregated
show track
```

---

## SPAN (Port Mirroring)

### SPAN Purpose
- Copy traffic to monitoring port
- Used for: IDS, packet capture, troubleshooting

### SPAN Types

| Type | Description |
|------|-------------|
| **Local SPAN** | Source and destination on same switch |
| **RSPAN** | Remote SPAN across switches (uses VLAN) |
| **ERSPAN** | Encapsulated RSPAN (uses GRE over IP) |

### Local SPAN Configuration
```cisco
! Monitor specific interface
monitor session 1 source interface GigabitEthernet0/1 both
monitor session 1 destination interface GigabitEthernet0/24

! Monitor VLAN
monitor session 1 source vlan 10 rx
monitor session 1 destination interface GigabitEthernet0/24

! Verify
show monitor session 1
```

### RSPAN Configuration
```cisco
! Create RSPAN VLAN (all switches)
vlan 999
  remote-span

! Source switch
monitor session 1 source interface Gi0/1 both
monitor session 1 destination remote vlan 999

! Destination switch
monitor session 1 source remote vlan 999
monitor session 1 destination interface Gi0/24
```

---

## Best Practices

### Syslog
- Use reliable transport (TCP) for critical logs
- Timestamp all messages
- Filter logs appropriately (avoid flooding)
- Regularly review and archive logs

### NetFlow
- Monitor key interfaces (WAN, critical servers)
- Use Flexible NetFlow for granular control
- Configure appropriate cache timeouts
- Analyze flows for capacity planning

### IP SLA
- Monitor critical paths and services
- Use tracking for automated failover
- Set appropriate frequencies (balance accuracy vs overhead)
- Alert on threshold violations

---

## Quick Reference

| Task | Command |
|------|---------|
| Syslog server | `logging host [ip]` |
| Syslog level | `logging trap [level]` |
| View logs | `show logging` |
| NetFlow export | `ip flow-export destination [ip] [port]` |
| Show NetFlow | `show ip cache flow` |
| IP SLA ping | `ip sla [#]` → `icmp-echo [ip]` |
| IP SLA schedule | `ip sla schedule [#] life forever start-time now` |
| Show IP SLA | `show ip sla statistics` |
| SPAN source | `monitor session [#] source interface [if]` |
| SPAN destination | `monitor session [#] destination interface [if]` |
