# Routing Fundamentals

## What is Routing?

**Routing** is the process of selecting paths in a network to send traffic from source to destination across multiple networks (Layer 3).

---

## Router Functions

1. **Determine best path** to destination
2. **Forward packets** based on routing table
3. **Separate broadcast domains**
4. **Perform NAT** (if configured)
5. **Filter traffic** with ACLs

---

## Routing Table

The routing table contains:
- **Destination network/prefix**
- **Next-hop address or exit interface**
- **Administrative distance**
- **Metric**
- **Route source** (how it was learned)

### Show Routing Table
```cisco
show ip route

! Example output
C    192.168.1.0/24 is directly connected, GigabitEthernet0/0
L    192.168.1.1/32 is directly connected, GigabitEthernet0/0
S    10.0.0.0/8 [1/0] via 192.168.1.2
O    172.16.0.0/16 [110/20] via 192.168.2.2, 00:05:23, GigabitEthernet0/1
```

### Route Codes

| Code | Meaning |
|------|---------|
| C | Connected |
| L | Local (interface IP) |
| S | Static |
| R | RIP |
| O | OSPF |
| D | EIGRP |
| B | BGP |
| * | Candidate default route |

---

## Administrative Distance (AD)

AD determines **trustworthiness** of route source. **Lower = better**.

| Route Source | Default AD |
|--------------|------------|
| Connected | 0 |
| Static | 1 |
| EIGRP summary | 5 |
| External BGP | 20 |
| Internal EIGRP | 90 |
| IGRP | 100 |
| OSPF | 110 |
| IS-IS | 115 |
| RIP | 120 |
| External EIGRP | 170 |
| Internal BGP | 200 |
| Unknown | 255 (unusable) |

> **Tip**: Remember "SEORI" - Static (1), EIGRP (90), OSPF (110), RIP (120), IGRP (100)

---

## Metric

Metric determines **best path** when multiple routes exist to same destination via same routing protocol.

| Protocol | Metric Based On |
|----------|-----------------|
| RIP | Hop count (max 15) |
| OSPF | Cost (based on bandwidth) |
| EIGRP | Composite (bandwidth, delay, reliability, load) |
| BGP | Attributes (AS path, etc.) |

---

## Longest Prefix Match

When multiple routes match, router uses route with **longest prefix (most specific)**.

```
Routes:
10.0.0.0/8 via 192.168.1.1
10.1.0.0/16 via 192.168.1.2
10.1.1.0/24 via 192.168.1.3

Packet to 10.1.1.50:
→ Matches /8, /16, and /24
→ Uses 10.1.1.0/24 (longest match)
```

---

## Static Routes

### Configuration Syntax
```cisco
ip route [destination-network] [mask] [next-hop-ip | exit-interface] [AD]
```

### Static Route Types

#### Standard Static Route
```cisco
! Via next-hop IP
ip route 10.0.0.0 255.0.0.0 192.168.1.2

! Via exit interface (point-to-point only)
ip route 10.0.0.0 255.0.0.0 Serial0/0

! Via both (fully specified - recommended)
ip route 10.0.0.0 255.0.0.0 GigabitEthernet0/1 192.168.1.2
```

#### Default Route (Gateway of Last Resort)
```cisco
ip route 0.0.0.0 0.0.0.0 192.168.1.1

! Verify
show ip route | include Gateway
```

#### Floating Static Route
Backup route with higher AD than primary.
```cisco
! Primary (OSPF, AD 110)
! Backup static (AD 115, only used if OSPF fails)
ip route 10.0.0.0 255.0.0.0 192.168.2.1 115
```

#### Summary Static Route
```cisco
! Instead of 4 routes to 10.1.0.0-10.1.3.0
ip route 10.1.0.0 255.255.252.0 192.168.1.1
```

### Static Route Verification
```cisco
show ip route static
show ip route [network]
show running-config | include ip route
```

---

## IPv6 Static Routes

```cisco
! Standard static
ipv6 route 2001:DB8:2::/64 2001:DB8:1::2

! Default route
ipv6 route ::/0 2001:DB8:1::1

! Via link-local (requires interface)
ipv6 route 2001:DB8:2::/64 GigabitEthernet0/1 FE80::2

! Floating static
ipv6 route 2001:DB8:2::/64 2001:DB8:1::3 120
```

---

## Dynamic Routing Protocols

### Classification

| Type | Protocols | Description |
|------|-----------|-------------|
| **IGP** (Interior Gateway Protocol) | OSPF, EIGRP, RIP, IS-IS | Within autonomous system |
| **EGP** (Exterior Gateway Protocol) | BGP | Between autonomous systems |

### Algorithm Types

| Type | Protocols | How It Works |
|------|-----------|--------------|
| **Distance Vector** | RIP, EIGRP | Share routing table with neighbors |
| **Link State** | OSPF, IS-IS | Build complete topology map |
| **Path Vector** | BGP | Track AS path |

### Protocol Comparison

| Feature | RIP | OSPF | EIGRP |
|---------|-----|------|-------|
| Type | Distance Vector | Link State | Advanced Distance Vector |
| Standard | Open | Open | Cisco (now open) |
| Metric | Hop count | Cost (BW) | Composite |
| Max hops | 15 | Unlimited | 224 |
| Convergence | Slow | Fast | Very fast |
| AD | 120 | 110 | 90 |
| Updates | Periodic (30s) | Event-driven | Event-driven |
| Hierarchy | Flat | Areas | Flat |
| VLSM | v2 only | Yes | Yes |

---

## RIP (Routing Information Protocol)

### Versions
- **RIPv1**: Classful, broadcast updates, no authentication
- **RIPv2**: Classless (VLSM/CIDR), multicast (224.0.0.9), authentication

### Configuration
```cisco
router rip
  version 2
  network 192.168.1.0
  network 10.0.0.0
  no auto-summary                    ! Disable classful summarization
  passive-interface GigabitEthernet0/0  ! Don't send updates here

! Verify
show ip protocols
show ip route rip
```

### RIP Timers
- **Update**: 30 seconds
- **Invalid**: 180 seconds (mark unreachable)
- **Holddown**: 180 seconds (ignore updates)
- **Flush**: 240 seconds (remove route)

---

## Routing Protocol Best Practices

1. **Use OSPF or EIGRP** for enterprise networks
2. **Avoid RIP** unless very simple network
3. **Document routing design**
4. **Use passive-interface** on user-facing ports
5. **Summarize routes** where possible
6. **Implement backup routes**
7. **Monitor routing table** for changes

---

## Packet Forwarding Process

1. **Receive packet** on interface
2. **Decrement TTL** (drop if 0, send ICMP Time Exceeded)
3. **Check destination IP** against routing table
4. **Longest prefix match**
5. **Layer 2 encapsulation** for next-hop
6. **Forward out** exit interface

### CEF (Cisco Express Forwarding)
- **FIB** (Forwarding Information Base): Optimized routing table
- **Adjacency Table**: Next-hop L2 rewrite info
- Hardware-accelerated forwarding

```cisco
show ip cef
show adjacency
```

---

## Path Selection

Order of preference:
1. **Longest prefix match** (most specific route)
2. **Lowest administrative distance**
3. **Lowest metric** (within same protocol)
4. **Load balancing** (equal-cost paths)

### Equal-Cost Multi-Path (ECMP)
```cisco
! Maximum parallel paths (OSPF)
router ospf 1
  maximum-paths 4

! Verify load balancing
show ip route [network]
```

---

## Default Routing Behavior

### Default Route Propagation
```cisco
! OSPF - generate default route
router ospf 1
  default-information originate

! Always advertise (even if no default in table)
router ospf 1
  default-information originate always

! RIP
router rip
  default-information originate
```

---

## Verification Commands

```cisco
! Routing table
show ip route
show ip route [protocol]
show ip route [network] [longer-prefixes]

! Routing protocols
show ip protocols

! Interface status
show ip interface brief

! Next-hop resolution
show ip arp
show ip cef [network]

! Debugging
debug ip routing
debug ip packet
```

---

## Troubleshooting Routing

### Common Issues

| Problem | Possible Cause | Solution |
|---------|----------------|----------|
| No route to host | Missing route | Add static or enable routing protocol |
| Suboptimal path | Wrong metric/AD | Adjust weights or costs |
| Routing loop | Misconfiguration | Check for conflicting routes |
| Blackhole | Null route or no return | Verify bidirectional routing |
| Flapping | Unstable link | Check physical layer |

### Troubleshooting Steps
1. `ping` destination
2. `traceroute` to see path
3. Check routing table: `show ip route`
4. Verify interface status
5. Check next-hop reachability
6. Verify return path exists
7. Check for ACLs blocking traffic

---

## Quick Reference

| Task | Command |
|------|---------|
| Show routes | `show ip route` |
| Show static routes | `show ip route static` |
| Add static route | `ip route [net] [mask] [next-hop]` |
| Default route | `ip route 0.0.0.0 0.0.0.0 [next-hop]` |
| Show protocols | `show ip protocols` |
| Test path | `traceroute [destination]` |
