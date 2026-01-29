# Network Troubleshooting

## Troubleshooting Methodology

### Structured Approach

1. **Define the Problem**
   - Gather information
   - Identify symptoms
   - Determine scope

2. **Gather Information**
   - User reports
   - Network documentation
   - Device logs
   - Show commands

3. **Analyze Information**
   - Compare to baseline
   - Identify changes
   - Isolate the issue

4. **Eliminate Possibilities**
   - Test hypotheses
   - Use process of elimination

5. **Propose and Test Solution**
   - Implement fix
   - Verify resolution

6. **Document**
   - Record findings
   - Update documentation

---

## Troubleshooting Models

| Model | Approach | Use When |
|-------|----------|----------|
| **Top-Down** | Start at Layer 7, work down | Application issues |
| **Bottom-Up** | Start at Layer 1, work up | Physical/connectivity issues |
| **Divide and Conquer** | Start at Layer 3, go up or down | Uncertain where problem is |
| **Follow the Path** | Trace packet path | Intermittent issues |
| **Substitution** | Replace components | Hardware suspected |
| **Comparison** | Compare working vs non-working | Similar systems available |

---

## Layer 1 (Physical) Issues

### Symptoms
- No link light
- Intermittent connectivity
- CRC errors
- Runts/Giants

### Troubleshooting
```cisco
show interfaces status
show interfaces [interface]
show interface counters errors
```

### Common Causes
- Bad cable
- Wrong cable type
- Damaged connector
- Speed/duplex mismatch
- Power issues

### Resolution
- Reseat/replace cables
- Check cable type (straight/cross)
- Fix speed/duplex
- Check transceivers

---

## Layer 2 (Data Link) Issues

### Symptoms
- Can't reach local devices
- VLAN issues
- STP blocking
- MAC table problems

### Commands
```cisco
! VLAN troubleshooting
show vlan brief
show interfaces trunk
show interfaces switchport

! MAC address table
show mac address-table
show mac address-table interface [if]

! STP
show spanning-tree
show spanning-tree blockedports

! Port security
show port-security interface [if]
show interfaces status err-disabled
```

### Common Issues

| Problem | Check | Solution |
|---------|-------|----------|
| Port down | Cable, speed/duplex | Fix physical |
| Wrong VLAN | `show vlan` | Assign correct VLAN |
| Trunk not working | `show int trunk` | Check mode, native VLAN |
| STP blocking | `show spanning-tree` | Verify topology |
| Port err-disabled | `show int status` | Fix cause, recover |

### Recover err-disabled Port
```cisco
interface GigabitEthernet0/1
  shutdown
  no shutdown

! Or automatic recovery
errdisable recovery cause all
errdisable recovery interval 300
```

---

## Layer 3 (Network) Issues

### Symptoms
- Can ping local, not remote
- Wrong route taken
- No route to destination

### Commands
```cisco
! IP configuration
show ip interface brief
show ip interface [interface]

! Routing
show ip route
show ip route [network]
show ip protocols

! ARP
show ip arp

! Connectivity tests
ping [destination]
traceroute [destination]
```

### Ping Responses

| Response | Meaning |
|----------|---------|
| ! | Success |
| . | Timeout |
| U | Unreachable |
| Q | Source quench |
| M | Could not fragment |
| ? | Unknown packet type |

### Extended Ping
```cisco
ping
Protocol [ip]:
Target IP address: 10.0.0.1
Repeat count [5]: 100
Datagram size [100]: 1500
Timeout [2]:
Extended commands [n]: y
Source address: 192.168.1.1
```

### Common Issues

| Problem | Check | Solution |
|---------|-------|----------|
| No route | `show ip route` | Add route |
| Wrong route | `show ip route [dest]` | Fix routing |
| Interface down | `show ip int brief` | `no shutdown` |
| Wrong IP/mask | `show ip interface` | Fix addressing |
| ARP issue | `show ip arp` | Check L2 |

---

## Layer 4-7 Issues

### Symptoms
- Application-specific failures
- Port blocked
- Service unavailable

### Commands
```cisco
! Check ACLs
show access-lists
show ip interface [if] | include access

! NAT
show ip nat translations
show ip nat statistics

! Debug (use carefully)
debug ip packet
```

### Common Causes
- ACL blocking traffic
- NAT misconfiguration
- Port not listening
- Application error

---

## OSPF Troubleshooting

### Neighbor Not Forming

```cisco
show ip ospf neighbor
show ip ospf interface [interface]
debug ip ospf adj
```

| Issue | Check | Solution |
|-------|-------|----------|
| Same area? | `show ip ospf int` | Match areas |
| Same timers? | `show ip ospf int` | Match hello/dead |
| Same network type? | `show ip ospf int` | Match type |
| Authentication? | Config | Match auth |
| MTU match? | `show int` | Match or ignore |
| Unique router ID? | `show ip ospf` | Change router-id |

### OSPF Neighbor States

| State | Normal? | Issue if Stuck |
|-------|---------|----------------|
| Down | No | No hello received |
| Init | No | One-way (check network) |
| 2-Way | Yes* | *DR/BDR election |
| ExStart | No | MTU mismatch |
| Exchange | No | MTU/auth |
| Loading | No | LSDB issue |
| Full | Yes | Adjacency formed |

---

## DHCP Troubleshooting

### No IP Address

```cisco
! Server side
show ip dhcp binding
show ip dhcp pool
show ip dhcp conflict

! Client side
show dhcp lease

! Relay
show ip helper-address
```

### Common Issues

| Problem | Check | Solution |
|---------|-------|----------|
| No DHCP server | `show ip dhcp` | Configure server |
| Wrong pool | `show ip dhcp pool` | Fix pool config |
| Pool exhausted | `show ip dhcp pool` | Increase pool |
| Missing relay | `show ip int` | Add helper-address |
| DHCP snooping | `show ip dhcp snoop` | Trust port |

---

## Network Diagram

When troubleshooting, trace the path:

```
[PC] ──> [Access SW] ──> [Distribution] ──> [Core] ──> [Router] ──> [WAN]
  │          │               │              │           │
  └──────────┴───────────────┴──────────────┴───────────┘
  Check each hop systematically
```

---

## Essential Troubleshooting Commands

### Show Commands
```cisco
! General status
show version
show running-config
show interfaces status

! Connectivity
show ip interface brief
show ip route
show arp

! Layer 2
show vlan brief
show interfaces trunk
show spanning-tree

! Specific protocols
show ip ospf neighbor
show ip dhcp binding
show ip nat translations
show access-lists
```

### Diagnostic Commands
```cisco
ping [ip] source [source-ip]
traceroute [ip]
show logging
show processes cpu
show memory
```

### Debug (Use Sparingly!)
```cisco
debug ip packet
debug ip ospf adj
debug dhcp
debug spanning-tree events

! Always stop debugging
undebug all
no debug all
```

---

## Troubleshooting Checklist

### Connectivity Issue
- [ ] Verify physical connectivity (Layer 1)
- [ ] Check port status (`show int status`)
- [ ] Verify VLAN assignment
- [ ] Check for STP blocking
- [ ] Verify IP configuration
- [ ] Check routing table
- [ ] Test with ping/traceroute
- [ ] Check ACLs
- [ ] Verify NAT (if applicable)

### Application Issue
- [ ] Verify network connectivity first
- [ ] Check DNS resolution
- [ ] Verify port/service is listening
- [ ] Check ACLs for specific ports
- [ ] Verify application configuration

---

## Common Error Messages

| Error | Likely Cause |
|-------|--------------|
| `Destination unreachable` | No route, ACL block |
| `Request timed out` | Host down, blocked |
| `TTL expired` | Routing loop |
| `Host unreachable` | ARP failure, no route |
| `Network unreachable` | No route to network |

---

## Documentation Template

When documenting issues:

```
Date/Time:
Reported by:
Symptoms:
Affected systems:
Timeline:
Investigation steps:
Root cause:
Resolution:
Prevention:
```

---

## Quick Troubleshooting Reference

| Layer | Command | What to Check |
|-------|---------|---------------|
| 1 | `show int status` | Link, errors |
| 2 | `show vlan brief` | VLAN, trunk |
| 2 | `show spanning-tree` | STP state |
| 3 | `show ip int brief` | IP, status |
| 3 | `show ip route` | Routes |
| 3 | `ping/traceroute` | Connectivity |
| 4+ | `show access-lists` | ACL matches |
| 4+ | `show ip nat trans` | NAT entries |
