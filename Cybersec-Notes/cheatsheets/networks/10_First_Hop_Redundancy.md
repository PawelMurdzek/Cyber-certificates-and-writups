# First Hop Redundancy Protocols (FHRP)

## Why FHRP?

Hosts typically have a **single default gateway**. If that gateway fails, hosts lose connectivity even if alternate paths exist.

**FHRP** provides gateway redundancy by creating a **virtual IP/MAC** shared by multiple routers.

---

## FHRP Comparison

| Feature | HSRP | VRRP | GLBP |
|---------|------|------|------|
| **Standard** | Cisco | IEEE (RFC 5798) | Cisco |
| **Active/Standby** | Yes | Yes | No (load sharing) |
| **Load Balancing** | No (without config) | No | Yes (native) |
| **Default Priority** | 100 | 100 | 100 |
| **Virtual MAC** | 0000.0c07.acXX | 0000.5e00.01XX | 0007.b400.XXYY |
| **Multicast Address** | 224.0.0.2 (v1), 224.0.0.102 (v2) | 224.0.0.18 | 224.0.0.102 |
| **Timers** | Hello 3s, Hold 10s | Advertise 1s, Master Down 3s | Hello 3s, Hold 10s |

---

## HSRP (Hot Standby Router Protocol)

### HSRP States

```
Initial → Learn → Listen → Speak → Standby → Active
```

| State | Description |
|-------|-------------|
| **Initial** | Starting state |
| **Learn** | Waiting for hello from active |
| **Listen** | Knows VIP, not active/standby |
| **Speak** | Participating in election |
| **Standby** | Backup, ready to take over |
| **Active** | Forwarding traffic |

### HSRP Election
- **Highest priority** wins (default 100, range 0-255)
- Tie-breaker: **Highest IP address**
- **Non-preemptive** by default

### HSRP Configuration

```cisco
! Basic HSRP
interface GigabitEthernet0/0
  ip address 192.168.1.2 255.255.255.0
  standby version 2
  standby 1 ip 192.168.1.1           ! Virtual IP (gateway for hosts)
  standby 1 priority 110             ! Higher = preferred (default 100)
  standby 1 preempt                  ! Take over when higher priority

! On backup router
interface GigabitEthernet0/0
  ip address 192.168.1.3 255.255.255.0
  standby version 2
  standby 1 ip 192.168.1.1
  standby 1 priority 100             ! Default
  standby 1 preempt
```

### HSRP Tracking
Track interface/object status to adjust priority automatically.

```cisco
interface GigabitEthernet0/0
  standby 1 ip 192.168.1.1
  standby 1 priority 110
  standby 1 preempt
  standby 1 track GigabitEthernet0/1 30   ! Reduce priority by 30 if Gi0/1 fails

! Object tracking (more flexible)
track 1 interface GigabitEthernet0/1 line-protocol

interface GigabitEthernet0/0
  standby 1 track 1 decrement 50
```

### HSRP Versions

| Feature | HSRPv1 | HSRPv2 |
|---------|--------|--------|
| Groups | 0-255 | 0-4095 |
| Virtual MAC | 0000.0c07.acXX | 0000.0c9f.fXXX |
| Multicast | 224.0.0.2 | 224.0.0.102 |
| Timers | 3s hello, 10s hold | Millisecond support |

### HSRP Load Balancing
Use multiple HSRP groups with different active routers:

```cisco
! Router A - Active for Group 1, Standby for Group 2
interface GigabitEthernet0/0
  standby 1 ip 192.168.1.1
  standby 1 priority 110
  standby 1 preempt
  standby 2 ip 192.168.1.2
  standby 2 priority 100
  standby 2 preempt

! Router B - Standby for Group 1, Active for Group 2
interface GigabitEthernet0/0
  standby 1 ip 192.168.1.1
  standby 1 priority 100
  standby 1 preempt
  standby 2 ip 192.168.1.2
  standby 2 priority 110
  standby 2 preempt

! Configure half of hosts with .1 as gateway, half with .2
```

### HSRP Verification
```cisco
show standby
show standby brief
show standby GigabitEthernet0/0
```

---

## VRRP (Virtual Router Redundancy Protocol)

### VRRP Terminology
- **Master**: Active router (vs HSRP's "Active")
- **Backup**: Standby router
- **Virtual Router**: VRID + Virtual IP

### VRRP States
```
Initialize → Backup → Master
```

### VRRP Configuration
```cisco
interface GigabitEthernet0/0
  ip address 192.168.1.2 255.255.255.0
  vrrp 1 ip 192.168.1.1
  vrrp 1 priority 110
  vrrp 1 preempt                  ! Enabled by default in VRRP

! Backup router
interface GigabitEthernet0/0
  ip address 192.168.1.3 255.255.255.0
  vrrp 1 ip 192.168.1.1
  vrrp 1 priority 100
```

### VRRP Unique Feature
- **Interface IP can be VIP**: Master with matching IP has priority 255

### VRRP Verification
```cisco
show vrrp
show vrrp brief
```

---

## GLBP (Gateway Load Balancing Protocol)

### GLBP Roles

| Role | Description |
|------|-------------|
| **AVG** (Active Virtual Gateway) | Responds to ARP requests, assigns VFs |
| **AVF** (Active Virtual Forwarder) | Forwards traffic using assigned virtual MAC |

- One AVG per group
- Up to 4 AVFs per group (load sharing)

### GLBP Load Balancing Methods

| Method | Description |
|--------|-------------|
| **Round-robin** | Rotates through AVFs (default) |
| **Weighted** | Based on configured weights |
| **Host-dependent** | Same host → same AVF |

### GLBP Configuration
```cisco
interface GigabitEthernet0/0
  ip address 192.168.1.2 255.255.255.0
  glbp 1 ip 192.168.1.1
  glbp 1 priority 110              ! AVG election
  glbp 1 preempt
  glbp 1 load-balancing round-robin

! Second router
interface GigabitEthernet0/0
  ip address 192.168.1.3 255.255.255.0
  glbp 1 ip 192.168.1.1
  glbp 1 priority 100
  glbp 1 preempt
```

### GLBP Weighting
```cisco
interface GigabitEthernet0/0
  glbp 1 weighting 100 lower 70 upper 90
  glbp 1 load-balancing weighted
  glbp 1 weighting track 1 decrement 30

track 1 interface GigabitEthernet0/1 line-protocol
```

### GLBP Verification
```cisco
show glbp
show glbp brief
```

---

## FHRP Best Practices

1. **Use HSRPv2** for Cisco environments
2. **Enable preempt** for faster failback
3. **Configure tracking** for upstream failure detection
4. **Use GLBP** when load balancing is needed
5. **Document virtual IPs** and priorities
6. **Match timers** on all routers in group
7. **Use authentication** in production
8. **Monitor FHRP status** regularly

---

## Authentication

### HSRP Authentication
```cisco
! Plain text
interface GigabitEthernet0/0
  standby 1 authentication MyPassword

! MD5
interface GigabitEthernet0/0
  standby 1 authentication md5 key-string MyPassword
```

### VRRP Authentication
```cisco
interface GigabitEthernet0/0
  vrrp 1 authentication md5 key-string MyPassword
```

---

## Timer Tuning

### HSRP Timers
```cisco
interface GigabitEthernet0/0
  standby 1 timers 1 3              ! Hello 1s, Hold 3s
  
! Millisecond timers (HSRPv2)
interface GigabitEthernet0/0
  standby 1 timers msec 200 msec 700
```

### VRRP Timers
```cisco
interface GigabitEthernet0/0
  vrrp 1 timers advertise 1         ! Advertisement interval
  vrrp 1 timers learn               ! Learn master's timers
```

---

## Troubleshooting

### Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| Both routers Active | No communication | Check L2 connectivity |
| No failover | Preempt not configured | Enable preempt |
| Slow failover | Hold timer too long | Tune timers |
| Wrong router Active | Priority wrong | Adjust priorities |
| Upstream failure ignored | No tracking | Configure tracking |

### Verification Commands
```cisco
! HSRP
show standby brief
debug standby events

! VRRP
show vrrp brief
debug vrrp events

! GLBP
show glbp brief
debug glbp events
```

---

## Quick Reference

| Task | HSRP | VRRP | GLBP |
|------|------|------|------|
| Version | `standby version 2` | N/A | N/A |
| Virtual IP | `standby [#] ip [ip]` | `vrrp [#] ip [ip]` | `glbp [#] ip [ip]` |
| Priority | `standby [#] priority [#]` | `vrrp [#] priority [#]` | `glbp [#] priority [#]` |
| Preempt | `standby [#] preempt` | `vrrp [#] preempt` | `glbp [#] preempt` |
| Track | `standby [#] track [if]` | `vrrp [#] track [if]` | `glbp [#] weighting track [#]` |
| Show | `show standby` | `show vrrp` | `show glbp` |
