# DHCP (Dynamic Host Configuration Protocol)

## DHCP Overview

- **Purpose**: Automatically assign IP configuration to clients
- **Port**: UDP 67 (server), UDP 68 (client)
- **Type**: Client-server model
- **Reduces**: Manual configuration, errors, IP conflicts

---

## DHCP Provides

- IP Address
- Subnet Mask
- Default Gateway
- DNS Server(s)
- Domain Name
- Lease Time
- Other options (NTP, TFTP, etc.)

---

## DHCP Process (DORA)

```
Client                                Server
  |                                     |
  |------ DISCOVER (broadcast) -------->|  "Anyone have an IP for me?"
  |                                     |
  |<-------- OFFER (unicast/broadcast) -|  "Here's an IP you can use"
  |                                     |
  |-------- REQUEST (broadcast) ------->|  "I'll take that IP"
  |                                     |
  |<------- ACK (unicast/broadcast) ----|  "It's yours, enjoy!"
  |                                     |
```

| Step | Direction | Type | Purpose |
|------|-----------|------|---------|
| **Discover** | Client → Server | Broadcast | Find DHCP server |
| **Offer** | Server → Client | Unicast/Broadcast | Offer IP config |
| **Request** | Client → Server | Broadcast | Accept offered IP |
| **Acknowledge** | Server → Client | Unicast/Broadcast | Confirm lease |

---

## DHCP Server Configuration (Cisco)

### Basic DHCP Server
```cisco
! Exclude addresses for static assignment
ip dhcp excluded-address 192.168.1.1 192.168.1.10

! Create DHCP pool
ip dhcp pool LAN-POOL
  network 192.168.1.0 255.255.255.0
  default-router 192.168.1.1
  dns-server 8.8.8.8 8.8.4.4
  domain-name example.com
  lease 7                              ! Days (or 0 2 0 for 2 hours)

! Multiple pools for different VLANs
ip dhcp pool VLAN10
  network 192.168.10.0 255.255.255.0
  default-router 192.168.10.1
  dns-server 8.8.8.8

ip dhcp pool VLAN20
  network 192.168.20.0 255.255.255.0
  default-router 192.168.20.1
  dns-server 8.8.8.8
```

### DHCP Options
```cisco
ip dhcp pool LAN-POOL
  network 192.168.1.0 255.255.255.0
  default-router 192.168.1.1
  dns-server 8.8.8.8 8.8.4.4
  domain-name example.com
  netbios-name-server 192.168.1.5     ! WINS server
  option 150 ip 192.168.1.5           ! TFTP server (for VoIP)
  lease 7 0 0                         ! 7 days, 0 hours, 0 minutes
```

### DHCP Verification
```cisco
show ip dhcp binding                   ! Current leases
show ip dhcp pool                      ! Pool statistics
show ip dhcp conflict                  ! Detected conflicts
show ip dhcp server statistics         ! Server statistics

! Clear bindings
clear ip dhcp binding *
clear ip dhcp conflict *
```

---

## DHCP Relay (ip helper-address)

When DHCP server is on a different subnet, broadcasts don't cross routers.

### Problem
```
Client (192.168.10.0/24) ---> Router ---> DHCP Server (192.168.1.0/24)
     DISCOVER (broadcast) --X-- Blocked at router!
```

### Solution: DHCP Relay
```cisco
! On router interface facing clients
interface GigabitEthernet0/0
  ip address 192.168.10.1 255.255.255.0
  ip helper-address 192.168.1.100      ! DHCP server IP

! Multiple servers
interface GigabitEthernet0/0
  ip helper-address 192.168.1.100
  ip helper-address 192.168.1.101
```

### How Relay Works
1. Client broadcasts DISCOVER
2. Router receives, changes to unicast
3. Adds **giaddr** (gateway IP) field
4. Forwards to DHCP server
5. Server responds based on giaddr subnet
6. Router relays response to client

### ip helper-address Forwards These Protocols
| Port | Protocol |
|------|----------|
| 37 | Time |
| 49 | TACACS |
| 53 | DNS |
| 67 | DHCP/BOOTP server |
| 68 | DHCP/BOOTP client |
| 69 | TFTP |
| 137 | NetBIOS Name Service |
| 138 | NetBIOS Datagram |

```cisco
! Disable specific UDP forwards
no ip forward-protocol udp 69
```

---

## DHCP Snooping

Security feature that filters untrusted DHCP messages.

### Purpose
- Prevent rogue DHCP servers
- Prevent DHCP starvation attacks
- Build binding table for DAI/IP Source Guard

### Configuration
```cisco
! Enable DHCP snooping globally
ip dhcp snooping
ip dhcp snooping vlan 10,20,30

! Trust uplink to legitimate DHCP server
interface GigabitEthernet0/24
  ip dhcp snooping trust

! Untrusted by default - access ports
interface range GigabitEthernet0/1 - 23
  ip dhcp snooping limit rate 15        ! Limit DHCP packets/second

! Verify
show ip dhcp snooping
show ip dhcp snooping binding
```

### DHCP Snooping Database
```cisco
! Save binding database
ip dhcp snooping database flash:/dhcp-snooping.db
ip dhcp snooping database timeout 60
```

---

## Client-Side DHCP

### Cisco Router as DHCP Client
```cisco
interface GigabitEthernet0/0
  ip address dhcp
  no shutdown

! Verify
show ip interface GigabitEthernet0/0
show dhcp lease
```

### Cisco Router DHCPv6 Client
```cisco
interface GigabitEthernet0/0
  ipv6 address dhcp
  no shutdown
```

---

## DHCPv6

### DHCPv6 vs SLAAC
| Feature | SLAAC | Stateless DHCPv6 | Stateful DHCPv6 |
|---------|-------|------------------|-----------------|
| Address | RA prefix + EUI-64/random | RA prefix + EUI-64/random | DHCPv6 |
| Other config | No | DHCPv6 (DNS, etc.) | DHCPv6 |
| RA M flag | 0 | 0 | 1 |
| RA O flag | 0 | 1 | 0 or 1 |

### DHCPv6 Server Configuration
```cisco
! Stateful DHCPv6
ipv6 dhcp pool LAN-POOL-V6
  address prefix 2001:db8:1:1::/64
  dns-server 2001:4860:4860::8888
  domain-name example.com

interface GigabitEthernet0/0
  ipv6 address 2001:db8:1:1::1/64
  ipv6 dhcp server LAN-POOL-V6
  ipv6 nd managed-config-flag          ! Set M flag in RA
```

### Stateless DHCPv6 (O flag)
```cisco
ipv6 dhcp pool STATELESS-POOL
  dns-server 2001:4860:4860::8888
  domain-name example.com

interface GigabitEthernet0/0
  ipv6 address 2001:db8:1:1::1/64
  ipv6 dhcp server STATELESS-POOL
  ipv6 nd other-config-flag            ! Set O flag in RA
```

### DHCPv6 Relay
```cisco
interface GigabitEthernet0/0
  ipv6 dhcp relay destination 2001:db8:1:100::1
```

---

## DHCP Lease Renewal

| Time | Action |
|------|--------|
| T1 (50%) | Client attempts to renew with original server |
| T2 (87.5%) | Client broadcasts to any DHCP server |
| Lease expires | Client releases IP, restarts DORA |

---

## Troubleshooting DHCP

### Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| No IP address | Server unreachable | Check connectivity, relay |
| Wrong IP range | Wrong pool matched | Check giaddr, pool config |
| Pool exhausted | All IPs leased | Increase pool, reduce lease time |
| Conflicts | Duplicate IPs | Check excluded addresses |
| Slow assignment | Snooping rate limit | Increase rate limit |

### Troubleshooting Commands
```cisco
! Server side
show ip dhcp binding
show ip dhcp pool
show ip dhcp conflict
show ip dhcp server statistics
debug ip dhcp server events
debug ip dhcp server packet

! Client side
show dhcp lease
release dhcp GigabitEthernet0/0
renew dhcp GigabitEthernet0/0

! Relay
show ip helper-address
debug ip dhcp server events
```

---

## DHCP Security Best Practices

1. **Enable DHCP snooping** on all access switches
2. **Rate limit** DHCP on untrusted ports
3. **Trust only** legitimate DHCP server uplinks
4. **Combine with** DAI and IP Source Guard
5. **Document** DHCP pools and exclusions
6. **Monitor** for conflicts and rogue servers
7. **Use reservations** for critical devices

---

## Quick Reference

| Task | Command |
|------|---------|
| Exclude addresses | `ip dhcp excluded-address [start] [end]` |
| Create pool | `ip dhcp pool [name]` |
| Network | `network [ip] [mask]` |
| Default gateway | `default-router [ip]` |
| DNS server | `dns-server [ip] [ip2]` |
| Domain name | `domain-name [name]` |
| Lease time | `lease [days] [hours] [minutes]` |
| DHCP relay | `ip helper-address [server-ip]` |
| DHCP snooping | `ip dhcp snooping` |
| Trust interface | `ip dhcp snooping trust` |
| Show bindings | `show ip dhcp binding` |
| Show pools | `show ip dhcp pool` |
