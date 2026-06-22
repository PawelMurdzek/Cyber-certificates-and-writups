# NAT and PAT (Network Address Translation)

## Why NAT?

- **IPv4 address conservation**: Private IPs don't consume public IPs
- **Security**: Hides internal network structure
- **Flexibility**: Change internal addressing without affecting external

---

## NAT Terminology

| Term | Description |
|------|-------------|
| **Inside Local** | Private IP of internal host |
| **Inside Global** | Public IP representing internal host |
| **Outside Local** | Private IP of external host (rare) |
| **Outside Global** | Public IP of external host |

```
Internal Network          Router/NAT              Internet
[Inside Local] ────→ [Inside Global] ────→ [Outside Global]
192.168.1.10          203.0.113.5              8.8.8.8
```

---

## NAT Types

| Type | Mapping | Use Case |
|------|---------|----------|
| **Static NAT** | 1:1 (permanent) | Servers needing consistent public IP |
| **Dynamic NAT** | 1:1 (from pool) | Multiple hosts, each gets unique public IP |
| **PAT/NAT Overload** | Many:1 (port-based) | Most common - many hosts share one public IP |

---

## Static NAT

Maps one private IP to one public IP permanently.

```cisco
! Define inside and outside interfaces
interface GigabitEthernet0/0
  ip address 192.168.1.1 255.255.255.0
  ip nat inside

interface GigabitEthernet0/1
  ip address 203.0.113.1 255.255.255.0
  ip nat outside

! Static NAT mapping
ip nat inside source static 192.168.1.10 203.0.113.10

! With port (Static PAT / Port Forwarding)
ip nat inside source static tcp 192.168.1.10 80 203.0.113.10 80
ip nat inside source static tcp 192.168.1.10 443 203.0.113.10 443
```

---

## Dynamic NAT

Maps private IPs to a pool of public IPs (first-come, first-served).

```cisco
! Define interfaces
interface GigabitEthernet0/0
  ip nat inside
interface GigabitEthernet0/1
  ip nat outside

! Define pool of public IPs
ip nat pool PUBLIC-POOL 203.0.113.10 203.0.113.20 netmask 255.255.255.0

! Define what hosts can use NAT (ACL)
access-list 1 permit 192.168.1.0 0.0.0.255

! Apply dynamic NAT
ip nat inside source list 1 pool PUBLIC-POOL
```

---

## PAT (Port Address Translation) / NAT Overload

Most common - many internal hosts share one public IP using different port numbers.

### PAT with Interface IP
```cisco
! Define interfaces
interface GigabitEthernet0/0
  ip nat inside
interface GigabitEthernet0/1
  ip nat outside

! Define hosts for NAT
access-list 1 permit 192.168.1.0 0.0.0.255

! PAT using outside interface IP
ip nat inside source list 1 interface GigabitEthernet0/1 overload
```

### PAT with Pool
```cisco
ip nat pool PUBLIC-POOL 203.0.113.10 203.0.113.10 netmask 255.255.255.0
access-list 1 permit 192.168.1.0 0.0.0.255
ip nat inside source list 1 pool PUBLIC-POOL overload
```

---

## NAT Verification

```cisco
! Show NAT translations
show ip nat translations

! Show NAT statistics
show ip nat statistics

! Debug NAT
debug ip nat
debug ip nat detailed

! Clear translations
clear ip nat translation *
```

### Translation Table Example
```
Pro  Inside global      Inside local       Outside local      Outside global
tcp  203.0.113.5:1024   192.168.1.10:1024  8.8.8.8:53         8.8.8.8:53
tcp  203.0.113.5:1025   192.168.1.11:1025  1.1.1.1:80         1.1.1.1:80
```

---

## NAT with ACLs

### Standard ACL for NAT
```cisco
! Permit hosts/networks for translation
access-list 10 permit 192.168.1.0 0.0.0.255
access-list 10 permit 192.168.2.0 0.0.0.255

ip nat inside source list 10 interface Gi0/1 overload
```

### Named ACL
```cisco
ip access-list standard NAT-HOSTS
  permit 192.168.1.0 0.0.0.255
  permit 192.168.2.0 0.0.0.255

ip nat inside source list NAT-HOSTS interface Gi0/1 overload
```

---

## NAT Virtual Interface (NVI)

Simplifies NAT configuration - no need to specify inside/outside.

```cisco
interface GigabitEthernet0/0
  ip nat enable
interface GigabitEthernet0/1
  ip nat enable

access-list 1 permit 192.168.1.0 0.0.0.255
ip nat source list 1 interface GigabitEthernet0/1 overload
```

---

## NAT64

Translates between IPv6 and IPv4 (for IPv6-only networks to reach IPv4).

```cisco
! Basic NAT64 stateful
nat64 enable
nat64 prefix stateful 64:ff9b::/96

interface GigabitEthernet0/0
  nat64 enable

! IPv6 host requests: 64:ff9b::8.8.8.8
! Router translates to IPv4: 8.8.8.8
```

---

## Troubleshooting NAT

### Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| No translation | ACL not matching | Check ACL, verify inside/outside |
| Pool exhausted | Not enough public IPs | Use PAT or larger pool |
| One-way traffic | Missing inside/outside | Configure both interfaces |
| Slow performance | Too many translations | Increase NAT table timeout |

### Troubleshooting Steps
1. Verify inside/outside interface configuration
2. Check ACL matches source traffic
3. Verify pool has available addresses
4. Check `show ip nat translations`
5. Use `debug ip nat` (carefully)

---

## NAT Timeout
```cisco
! Adjust translation timeout (seconds)
ip nat translation timeout 86400              ! General entries
ip nat translation tcp-timeout 86400          ! TCP
ip nat translation udp-timeout 300            ! UDP
ip nat translation icmp-timeout 60            ! ICMP
ip nat translation syn-timeout 60             ! TCP SYN

! Verify
show ip nat translations verbose
```

---

## NAT Order of Operations

### Inside to Outside
1. Routing (destination lookup)
2. NAT inside→outside (source translated)
3. Forward packet

### Outside to Inside
1. NAT outside→inside (destination translated)
2. Routing (destination lookup)
3. Forward packet

> **Important**: ACLs are checked AFTER NAT for inbound, BEFORE NAT for outbound

---

## NAT Best Practices

1. **Use PAT** for most scenarios (conserves IPs)
2. **Static NAT** for servers needing inbound connections
3. **Document all NAT mappings**
4. **Use descriptive ACLs** for NAT source lists
5. **Consider NAT and ACL interaction**
6. **Monitor translation table** for exhaustion
7. **Use logging** for troubleshooting
8. **Plan for NAT traversal** (VPN, SIP, FTP)

---

## Quick Reference

| NAT Type | Command |
|----------|---------|
| Static NAT | `ip nat inside source static [local] [global]` |
| Static PAT | `ip nat inside source static [proto] [local] [port] [global] [port]` |
| Dynamic NAT | `ip nat inside source list [acl] pool [name]` |
| PAT (Interface) | `ip nat inside source list [acl] interface [if] overload` |
| PAT (Pool) | `ip nat inside source list [acl] pool [name] overload` |
| Inside interface | `ip nat inside` |
| Outside interface | `ip nat outside` |
| Show translations | `show ip nat translations` |
| Show stats | `show ip nat statistics` |
| Clear translations | `clear ip nat translation *` |
