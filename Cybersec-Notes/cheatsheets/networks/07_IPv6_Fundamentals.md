# IPv6 Fundamentals

## Why IPv6?

- **IPv4 exhaustion**: ~4.3 billion addresses not enough
- **IPv6 provides**: 340 undecillion addresses (2^128)
- **No NAT needed**: End-to-end connectivity
- **Built-in**: IPsec, autoconfiguration, multicast

---

## IPv6 Address Structure

- **128 bits** (vs 32 for IPv4)
- **8 groups of 4 hex digits** separated by colons
- Example: `2001:0DB8:0000:0001:0000:0000:0000:0001`

### Address Abbreviation Rules

1. **Leading zeros** can be omitted within each group
2. **Consecutive groups of zeros** can be replaced with `::` (only once!)

**Full**: `2001:0DB8:0000:0001:0000:0000:0000:0001`
**Shortened**: `2001:DB8:0:1::1`

**Examples:**
```
FE80:0000:0000:0000:0000:0000:0000:0001  →  FE80::1
2001:0DB8:0000:0000:0001:0000:0000:0001  →  2001:DB8::1:0:0:1
0000:0000:0000:0000:0000:0000:0000:0001  →  ::1 (loopback)
0000:0000:0000:0000:0000:0000:0000:0000  →  :: (unspecified)
```

---

## IPv6 Address Types

### Unicast Addresses

| Type | Prefix | Scope | Description |
|------|--------|-------|-------------|
| **Global Unicast (GUA)** | 2000::/3 | Internet | Routable, like public IPv4 |
| **Link-Local** | FE80::/10 | Link only | Auto-configured, not routable |
| **Unique Local (ULA)** | FC00::/7 | Private | Like private IPv4 (RFC 1918) |
| **Loopback** | ::1/128 | Host | Same as 127.0.0.1 |
| **Unspecified** | ::/128 | - | Same as 0.0.0.0 |

### Global Unicast Address (GUA) Structure
```
|     48 bits      |  16 bits  |        64 bits        |
|  Global Routing  |  Subnet   |    Interface ID       |
|     Prefix       |    ID     |                       |
2001:0DB8:AAAA    :    0001   :    1234:5678:ABCD:EF01
```

### Link-Local Address (LLA)
- **Prefix**: FE80::/10 (always starts with FE80)
- **Automatically created** on every IPv6 interface
- **Required** for IPv6 to function
- Used for: NDP, routing protocols, next-hop addresses

```
FE80:0000:0000:0000  :  Interface ID (EUI-64 or random)
FE80::1
```

### Interface ID Generation

**EUI-64 Method** (from MAC address):
1. Take MAC: `AA:BB:CC:DD:EE:FF`
2. Insert `FFFE` in middle: `AA:BB:CC:FF:FE:DD:EE:FF`
3. Flip 7th bit (Universal/Local): `A8BB:CCFF:FEDD:EEFF`

**Random/Privacy Extensions**: Random 64-bit ID

---

## Multicast Addresses

| Address | Scope | Purpose |
|---------|-------|---------|
| FF02::1 | Link | All nodes |
| FF02::2 | Link | All routers |
| FF02::5 | Link | OSPF routers |
| FF02::6 | Link | OSPF DRs |
| FF02::9 | Link | RIPng routers |
| FF02::A | Link | EIGRP routers |
| FF02::1:FF00:0/104 | Link | Solicited-node multicast |

### Solicited-Node Multicast
- Format: `FF02::1:FF` + last 24 bits of unicast address
- Used for Neighbor Discovery (replaces ARP)
- Example: For `2001:DB8::1234:5678`, solicited-node = `FF02::1:FF34:5678`

---

## Anycast Addresses

- Same address assigned to multiple interfaces
- Packet delivered to **nearest** device
- Used for: DNS, load balancing
- Syntactically identical to unicast

---

## IPv6 Address Assignment

### Static Configuration
```cisco
interface GigabitEthernet0/0
  ipv6 address 2001:DB8:1:1::1/64
  no shutdown
  
! Link-local only
interface GigabitEthernet0/0
  ipv6 address FE80::1 link-local
```

### SLAAC (Stateless Address Autoconfiguration)
```cisco
! Router side (send RAs)
interface GigabitEthernet0/0
  ipv6 address 2001:DB8:1:1::1/64
  no shutdown
  
! Client side (auto-configure)
interface GigabitEthernet0/0
  ipv6 address autoconfig
```

### DHCPv6 (Stateful)
```cisco
! DHCPv6 Server
ipv6 dhcp pool LAN-POOL
  address prefix 2001:DB8:1:1::/64
  dns-server 2001:4860:4860::8888

interface GigabitEthernet0/0
  ipv6 dhcp server LAN-POOL
  ipv6 nd managed-config-flag    ! M flag
  
! DHCPv6 Client
interface GigabitEthernet0/0
  ipv6 address dhcp
```

### DHCPv6 Flags (RA)

| Flag | Name | Meaning |
|------|------|---------|
| **M** | Managed | Get address from DHCPv6 |
| **O** | Other | Get other info (DNS) from DHCPv6, address from SLAAC |

---

## Neighbor Discovery Protocol (NDP)

Replaces ARP, ICMP Router Discovery, and more.

### NDP Message Types (ICMPv6)

| Type | Message | Purpose |
|------|---------|---------|
| 133 | Router Solicitation (RS) | Host asks for RA |
| 134 | Router Advertisement (RA) | Router announces prefix/gateway |
| 135 | Neighbor Solicitation (NS) | Like ARP request |
| 136 | Neighbor Advertisement (NA) | Like ARP reply |
| 137 | Redirect | Better next-hop |

### DAD (Duplicate Address Detection)
- Uses NS/NA to check if address is in use
- Happens before address is assigned
- Target address in NS is tentative address

---

## IPv6 Routing

### Enable IPv6 Routing
```cisco
! Enable IPv6 routing (required on routers)
ipv6 unicast-routing

! Configure interface
interface GigabitEthernet0/0
  ipv6 address 2001:DB8:1:1::1/64
  no shutdown
```

### Static Routes
```cisco
! To specific network
ipv6 route 2001:DB8:2::/64 2001:DB8:1:2::2

! Via next-hop link-local (requires exit interface)
ipv6 route 2001:DB8:2::/64 GigabitEthernet0/1 FE80::2

! Default route
ipv6 route ::/0 2001:DB8:1:1::1

! Floating static (higher AD)
ipv6 route 2001:DB8:2::/64 2001:DB8:1:3::3 100
```

### Verification
```cisco
show ipv6 route
show ipv6 interface brief
show ipv6 interface GigabitEthernet0/0
show ipv6 neighbors
show ipv6 routers
```

---

## OSPFv3 for IPv6

```cisco
! Enable OSPFv3
ipv6 router ospf 1
  router-id 1.1.1.1

! Assign interfaces
interface GigabitEthernet0/0
  ipv6 ospf 1 area 0

! Verify
show ipv6 ospf neighbor
show ipv6 ospf interface
show ipv6 route ospf
```

---

## IPv6 vs IPv4 Comparison

| Feature | IPv4 | IPv6 |
|---------|------|------|
| Address size | 32 bits | 128 bits |
| Address format | Dotted decimal | Colon hexadecimal |
| Header size | 20-60 bytes | 40 bytes (fixed) |
| Broadcast | Yes | No (multicast instead) |
| ARP | Yes | NDP (ICMPv6) |
| DHCP | Optional | SLAAC or DHCPv6 |
| IPsec | Optional | Built-in |
| Fragmentation | Routers & host | Host only |
| Checksum | In header | Removed (L4 handles) |

---

## IPv6 Header

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| Traffic Class |           Flow Label                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Payload Length        |  Next Header  |   Hop Limit   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                         Source Address                        +
|                           (128 bits)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                      Destination Address                      +
|                           (128 bits)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Version**: 6
- **Traffic Class**: QoS marking (like DSCP)
- **Flow Label**: Identify packet flows
- **Next Header**: Protocol (TCP=6, UDP=17, ICMPv6=58)
- **Hop Limit**: Like TTL

---

## Transition Mechanisms

### Dual-Stack
- Run IPv4 and IPv6 simultaneously
- Preferred method for migration

```cisco
interface GigabitEthernet0/0
  ip address 192.168.1.1 255.255.255.0
  ipv6 address 2001:DB8:1:1::1/64
```

### Tunneling
- Encapsulate IPv6 in IPv4 packets
- Types: 6to4, ISATAP, GRE, Teredo

### NAT64
- Translate between IPv6 and IPv4
- For IPv6-only networks to reach IPv4

---

## Common IPv6 Addresses Reference

| Address | Purpose |
|---------|---------|
| `::1` | Loopback |
| `::` | Unspecified |
| `FE80::/10` | Link-local |
| `2000::/3` | Global unicast |
| `FC00::/7` | Unique local |
| `FF00::/8` | Multicast |
| `FF02::1` | All nodes (link) |
| `FF02::2` | All routers (link) |

---

## Troubleshooting IPv6

### Commands
```cisco
show ipv6 interface brief
show ipv6 interface [interface]
show ipv6 neighbors
show ipv6 route
show ipv6 routers
ping ipv6 [address]
traceroute ipv6 [address]

! Debug
debug ipv6 nd
debug ipv6 icmp
```

### Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| No link-local | IPv6 not enabled | `ipv6 enable` on interface |
| Can't ping LL | Wrong interface | Specify exit interface |
| No GUA | SLAAC failed | Check RA, routing |
| No connectivity | Routing disabled | `ipv6 unicast-routing` |
| DAD failed | Duplicate address | Change address |

---

## Best Practices

1. **Always use link-local** for next-hop when possible
2. **Use /64 for LANs** (required for SLAAC)
3. **Use /127 or /126 for point-to-point**
4. **Plan address allocation** carefully
5. **Document addressing scheme**
6. **Enable IPv6 routing** on all routers
7. **Use EUI-64** sparingly (privacy concerns)
8. **Implement IPv6 ACLs** (security)
