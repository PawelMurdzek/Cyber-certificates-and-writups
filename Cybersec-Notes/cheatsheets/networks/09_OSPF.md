# OSPF (Open Shortest Path First)

## OSPF Overview

- **Type**: Link-State Interior Gateway Protocol (IGP)
- **Standard**: IETF (Open standard, RFC 2328)
- **Algorithm**: Dijkstra's SPF (Shortest Path First)
- **Metric**: Cost (based on bandwidth)
- **AD**: 110
- **Transport**: IP protocol 89
- **Multicast**: 224.0.0.5 (all OSPF), 224.0.0.6 (DR/BDR)

---

## OSPF Characteristics

| Feature | Description |
|---------|-------------|
| Hierarchical design | Uses areas for scalability |
| Fast convergence | Triggered updates, SPF calculation |
| Classless | Supports VLSM and CIDR |
| Authentication | Plaintext, MD5, SHA |
| Equal-cost load balancing | Up to 4 paths (default) |
| Loop-free | SPF algorithm |

---

## OSPF Terminology

| Term | Description |
|------|-------------|
| **Router ID** | Unique identifier (32-bit, like IP) |
| **Area** | Logical grouping of routers |
| **Area 0 (Backbone)** | All areas must connect to this |
| **ABR** | Area Border Router (connects areas) |
| **ASBR** | AS Boundary Router (external routes) |
| **LSA** | Link-State Advertisement |
| **LSDB** | Link-State Database |
| **SPF** | Shortest Path First algorithm |
| **DR** | Designated Router |
| **BDR** | Backup Designated Router |

---

## OSPF Packet Types

| Type | Name | Purpose |
|------|------|---------|
| 1 | Hello | Discover/maintain neighbors |
| 2 | DBD | Database Description - exchange LSDB summary |
| 3 | LSR | Link-State Request - request specific LSAs |
| 4 | LSU | Link-State Update - send LSAs |
| 5 | LSAck | Link-State Acknowledgment |

---

## OSPF Neighbor States

```
Down → Init → 2-Way → ExStart → Exchange → Loading → Full
```

| State | Description |
|-------|-------------|
| **Down** | No hellos received |
| **Init** | Hello received, but own Router ID not seen |
| **2-Way** | Bidirectional communication established |
| **ExStart** | Master/slave election for DBD exchange |
| **Exchange** | DBD packets exchanged |
| **Loading** | LSR/LSU exchange |
| **Full** | LSDB synchronized, adjacency formed |

> **Note**: On multi-access networks, non-DR/BDR routers stay in 2-Way with each other

---

## DR/BDR Election

On **multi-access networks** (Ethernet), DR/BDR reduce flooding:
- **DR**: Receives updates from all, floods to all
- **BDR**: Backup, takes over if DR fails
- **DROTHER**: Neither DR nor BDR

### Election Criteria (in order)
1. **Highest OSPF priority** (default 1, range 0-255)
2. **Highest Router ID**

> **Priority 0** = Cannot be DR/BDR

### Election Behavior
- **Non-preemptive**: New router with higher priority doesn't take over
- To change DR: Restart OSPF process or wait for failure

```cisco
! Set interface priority
interface GigabitEthernet0/0
  ip ospf priority 100

! Verify
show ip ospf interface GigabitEthernet0/0
```

---

## OSPF Network Types

| Type | Default On | DR/BDR | Hello | Dead |
|------|------------|--------|-------|------|
| **Broadcast** | Ethernet | Yes | 10s | 40s |
| **Point-to-Point** | Serial, P2P subif | No | 10s | 40s |
| **Non-Broadcast** | Frame Relay | Yes | 30s | 120s |
| **Point-to-Multipoint** | Frame Relay | No | 30s | 120s |

```cisco
! Change network type
interface GigabitEthernet0/0
  ip ospf network point-to-point
```

---

## OSPF Metric (Cost)

```
Cost = Reference Bandwidth / Interface Bandwidth
Default Reference: 100 Mbps (100,000,000 bps)
```

| Link Speed | Default Cost |
|------------|--------------|
| 10 Mbps | 10 |
| 100 Mbps | 1 |
| 1 Gbps | 1 |
| 10 Gbps | 1 |

> **Problem**: 100Mbps to 100Gbps all have cost 1!

### Solution: Increase Reference Bandwidth
```cisco
router ospf 1
  auto-cost reference-bandwidth 100000   ! 100 Gbps
  
! New costs: 100M=1000, 1G=100, 10G=10, 100G=1
```

### Manually Set Cost
```cisco
interface GigabitEthernet0/0
  ip ospf cost 50
```

---

## Single-Area OSPF Configuration

### Basic Configuration
```cisco
! Enable OSPF with process ID
router ospf 1
  router-id 1.1.1.1                      ! Manually set (recommended)
  network 192.168.1.0 0.0.0.255 area 0   ! Wildcard mask = inverse of subnet
  network 10.0.0.0 0.255.255.255 area 0
  passive-interface GigabitEthernet0/2   ! No hellos on this interface

! Alternative: Enable OSPF on interface
interface GigabitEthernet0/0
  ip ospf 1 area 0
```

### Router ID Selection (in order)
1. Manually configured `router-id`
2. Highest IP on loopback interface
3. Highest IP on any active interface

```cisco
! Force Router ID change
clear ip ospf process
```

### Wildcard Masks
```
Subnet Mask:   255.255.255.0   → Network bits
Wildcard Mask: 0.0.0.255       → Host bits (inverse)

Common:
/24 = 255.255.255.0   → 0.0.0.255
/16 = 255.255.0.0     → 0.0.255.255
/30 = 255.255.255.252 → 0.0.0.3
/32 = 255.255.255.255 → 0.0.0.0 (exact match)
```

---

## Multi-Area OSPF

### Area Types

| Area Type | External Routes | Summary Routes |
|-----------|-----------------|----------------|
| **Normal** | Full | Full |
| **Stub** | No Type 5 LSAs | Yes |
| **Totally Stub** | No Type 5 | No inter-area (Type 3) |
| **NSSA** | Type 7 (external-to-NSSA) | Yes |
| **Totally NSSA** | Type 7 | No inter-area |

### LSA Types

| Type | Name | Description | Flooded |
|------|------|-------------|---------|
| 1 | Router LSA | Router links within area | Within area |
| 2 | Network LSA | DR advertises network | Within area |
| 3 | Summary LSA | ABR summarizes inter-area | Between areas |
| 4 | ASBR Summary | Location of ASBR | Between areas |
| 5 | External LSA | External routes | Entire domain |
| 7 | NSSA External | External in NSSA | Within NSSA |

### Multi-Area Configuration
```cisco
! ABR Configuration
router ospf 1
  router-id 2.2.2.2
  network 10.0.0.0 0.0.0.255 area 0
  network 172.16.0.0 0.0.255.255 area 1
  
! Stub area
router ospf 1
  area 1 stub

! Totally stubby area (ABR)
router ospf 1
  area 1 stub no-summary

! NSSA
router ospf 1
  area 2 nssa
```

---

## OSPF Default Route

```cisco
! Advertise default route into OSPF
router ospf 1
  default-information originate

! Always advertise (even if no default route exists)
router ospf 1
  default-information originate always
```

---

## OSPF Authentication

### Interface-Level Authentication
```cisco
! Plaintext
interface GigabitEthernet0/0
  ip ospf authentication
  ip ospf authentication-key MyPassword

! MD5
interface GigabitEthernet0/0
  ip ospf authentication message-digest
  ip ospf message-digest-key 1 md5 MyPassword
```

### Area-Level Authentication
```cisco
router ospf 1
  area 0 authentication message-digest

interface GigabitEthernet0/0
  ip ospf message-digest-key 1 md5 MyPassword
```

---

## OSPF Timers

| Timer | Default (Broadcast) | Default (NBMA) |
|-------|---------------------|----------------|
| Hello | 10 seconds | 30 seconds |
| Dead | 40 seconds | 120 seconds |

> **Dead = 4 × Hello** by default

```cisco
! Modify timers (must match on both ends)
interface GigabitEthernet0/0
  ip ospf hello-interval 5
  ip ospf dead-interval 20

! Verify
show ip ospf interface GigabitEthernet0/0
```

---

## OSPFv3 for IPv6

```cisco
! Enable IPv6 routing
ipv6 unicast-routing

! Configure OSPFv3
ipv6 router ospf 1
  router-id 1.1.1.1

! Enable on interface
interface GigabitEthernet0/0
  ipv6 ospf 1 area 0

! Verify
show ipv6 ospf neighbor
show ipv6 route ospf
```

---

## OSPF Verification Commands

```cisco
! Neighbors
show ip ospf neighbor
show ip ospf neighbor detail

! Interface
show ip ospf interface
show ip ospf interface brief

! Database
show ip ospf database
show ip ospf database router
show ip ospf database summary

! Routes
show ip route ospf

! Process info
show ip ospf
show ip protocols

! Debug (use carefully!)
debug ip ospf adj
debug ip ospf events
```

---

## OSPF Troubleshooting

### Neighbor Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| Stuck in Init | Hello not reaching | Check L1/L2 connectivity |
| Stuck in 2-Way | Normal for DROTHERs | Check if DR/BDR elected |
| Stuck in ExStart | MTU mismatch | Match MTU or ignore |
| No neighbor | Mismatched parameters | See checklist below |

### Neighbor Requirements Checklist
- [ ] Same area
- [ ] Same hello/dead timers
- [ ] Same network type
- [ ] Same authentication
- [ ] Same MTU (or `ip ospf mtu-ignore`)
- [ ] Unique router IDs
- [ ] Same subnet

### Fix MTU Mismatch
```cisco
interface GigabitEthernet0/0
  ip ospf mtu-ignore
```

---

## OSPF Summarization

### Inter-Area (ABR)
```cisco
router ospf 1
  area 1 range 10.1.0.0 255.255.0.0
```

### External (ASBR)
```cisco
router ospf 1
  summary-address 172.16.0.0 255.255.0.0
```

---

## OSPF Best Practices

1. **Use loopback** for Router ID stability
2. **Consistent reference bandwidth** across all routers
3. **Passive-interface** on user-facing ports
4. **Summarize** at area boundaries
5. **Use authentication**
6. **Keep Area 0** contiguous
7. **Document area design**
8. **Avoid too many routers** per area (~50 max)
9. **Use stub areas** to reduce LSDB size
10. **Monitor adjacencies** regularly

---

## Quick Reference

| Task | Command |
|------|---------|
| Enable OSPF | `router ospf [process-id]` |
| Set Router ID | `router-id [x.x.x.x]` |
| Network statement | `network [ip] [wildcard] area [#]` |
| Interface enable | `ip ospf [process] area [#]` |
| Passive interface | `passive-interface [if]` |
| Show neighbors | `show ip ospf neighbor` |
| Show routes | `show ip route ospf` |
| Show database | `show ip ospf database` |
| Default route | `default-information originate` |
