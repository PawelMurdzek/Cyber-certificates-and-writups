# Access Control Lists (ACLs)

## ACL Overview

ACLs filter traffic based on criteria:
- Source/destination IP addresses
- Protocol (TCP, UDP, ICMP)
- Port numbers
- Other header fields

---

## ACL Types

| Type | Number Range | Matches On | Use Case |
|------|--------------|------------|----------|
| **Standard** | 1-99, 1300-1999 | Source IP only | Simple filtering |
| **Extended** | 100-199, 2000-2699 | Source, dest, protocol, ports | Detailed filtering |
| **Named** | Text name | Either type | Easier management |

---

## ACL Processing

1. ACL processed **top-to-bottom**
2. First match wins
3. **Implicit deny all** at the end
4. No match = packet dropped

```
              ┌─────────────┐
              │   Packet    │
              └──────┬──────┘
                     ▼
              ┌─────────────┐
         ┌────│  ACE 1?     │────┐
         │Yes └─────────────┘ No │
         ▼                       ▼
    ┌─────────┐           ┌─────────────┐
    │ Action  │     ┌─────│  ACE 2?     │─────┐
    │(permit/ │     │Yes  └─────────────┘ No  │
    │ deny)   │     ▼                         ▼
    └─────────┘ ┌─────────┐            ┌─────────────┐
                │ Action  │      ┌─────│  ACE 3?     │
                └─────────┘      │     └─────────────┘
                                 ▼            ...
                            ┌─────────┐       ▼
                            │ Action  │  ┌─────────────┐
                            └─────────┘  │Implicit Deny│
                                         └─────────────┘
```

---

## Wildcard Masks

Wildcard = inverse of subnet mask
- **0** = must match
- **1** = ignore (wildcard)

| Subnet Mask | Wildcard Mask | Meaning |
|-------------|---------------|---------|
| 255.255.255.255 | 0.0.0.0 | Match exact host |
| 255.255.255.0 | 0.0.0.255 | Match /24 network |
| 255.255.0.0 | 0.0.255.255 | Match /16 network |
| 255.0.0.0 | 0.255.255.255 | Match /8 network |
| 0.0.0.0 | 255.255.255.255 | Match any address |

### Shortcut Keywords
- `host 192.168.1.1` = `192.168.1.1 0.0.0.0`
- `any` = `0.0.0.0 255.255.255.255`

---

## Standard ACLs

Match **source IP only**.

### Numbered Standard ACL
```cisco
! Permit specific host
access-list 10 permit host 192.168.1.100

! Permit network
access-list 10 permit 192.168.1.0 0.0.0.255

! Deny network
access-list 10 deny 10.0.0.0 0.255.255.255

! Permit everything else (override implicit deny)
access-list 10 permit any

! Apply to interface (outbound)
interface GigabitEthernet0/0
  ip access-group 10 out
```

### Named Standard ACL
```cisco
ip access-list standard ALLOW-HOSTS
  permit host 192.168.1.100
  permit host 192.168.1.101
  deny 192.168.1.0 0.0.0.255
  permit any

interface GigabitEthernet0/0
  ip access-group ALLOW-HOSTS out
```

---

## Extended ACLs

Match source, destination, protocol, ports.

### Syntax
```
access-list [number] [permit|deny] [protocol] [source] [destination] [options]
```

### Numbered Extended ACL
```cisco
! Permit HTTP from any to web server
access-list 110 permit tcp any host 192.168.1.100 eq 80

! Permit HTTPS 
access-list 110 permit tcp any host 192.168.1.100 eq 443

! Permit SSH from admin network
access-list 110 permit tcp 10.0.0.0 0.255.255.255 any eq 22

! Deny Telnet from anywhere
access-list 110 deny tcp any any eq 23

! Permit ICMP (ping)
access-list 110 permit icmp any any

! Permit established TCP connections
access-list 110 permit tcp any any established

! Explicit deny with log
access-list 110 deny ip any any log

! Apply inbound
interface GigabitEthernet0/0
  ip access-group 110 in
```

### Named Extended ACL
```cisco
ip access-list extended WEB-FILTER
  permit tcp any host 192.168.1.100 eq 80
  permit tcp any host 192.168.1.100 eq 443
  deny tcp any any eq 23
  permit icmp any any
  deny ip any any log

interface GigabitEthernet0/0
  ip access-group WEB-FILTER in
```

---

## Port Operators

| Operator | Meaning | Example |
|----------|---------|---------|
| **eq** | Equal | `eq 80` |
| **neq** | Not equal | `neq 23` |
| **lt** | Less than | `lt 1024` |
| **gt** | Greater than | `gt 1023` |
| **range** | Range | `range 20 21` |

### Protocol Keywords

| Protocol | Number | Common Use |
|----------|--------|------------|
| **ip** | - | Any IP traffic |
| **tcp** | 6 | TCP traffic |
| **udp** | 17 | UDP traffic |
| **icmp** | 1 | Ping, traceroute |
| **ospf** | 89 | OSPF routing |
| **eigrp** | 88 | EIGRP routing |
| **gre** | 47 | GRE tunnels |
| **ahp** | 51 | IPsec AH |
| **esp** | 50 | IPsec ESP |

---

## ACL Placement Rules

### Standard ACLs
- Place **close to destination** (only filters source)

### Extended ACLs  
- Place **close to source** (more specific, saves bandwidth)

```
Source ──────────────> Destination
        Extended ACL    Standard ACL
        (place here)    (place here)
```

---

## ACL Direction

| Direction | Meaning |
|-----------|---------|
| **in** | Filter traffic entering interface |
| **out** | Filter traffic exiting interface |

```
         Router
           │
    ┌──────┼──────┐
    │      │      │
   in   routing  out
    │      │      │
    └──────┼──────┘
           │
```

---

## Common ACL Examples

### Block Specific Host
```cisco
access-list 101 deny ip host 192.168.1.50 any
access-list 101 permit ip any any
```

### Allow Only SSH/HTTPS to Server
```cisco
ip access-list extended SECURE-ACCESS
  permit tcp any host 192.168.1.100 eq 22
  permit tcp any host 192.168.1.100 eq 443
  deny ip any host 192.168.1.100
  permit ip any any
```

### Block Social Media (by IP range)
```cisco
access-list 150 deny ip any 157.240.0.0 0.0.255.255 log    ! Facebook
access-list 150 permit ip any any
```

### VTY Access Control
```cisco
access-list 5 permit 192.168.1.0 0.0.0.255
access-list 5 deny any log

line vty 0 15
  access-class 5 in
  transport input ssh
```

### Reflexive ACL (Session Tracking)
```cisco
ip access-list extended OUTBOUND
  permit tcp any any reflect TCP-TRAFFIC
  permit udp any any reflect UDP-TRAFFIC
  permit icmp any any reflect ICMP-TRAFFIC

ip access-list extended INBOUND
  evaluate TCP-TRAFFIC
  evaluate UDP-TRAFFIC
  evaluate ICMP-TRAFFIC
  deny ip any any

interface GigabitEthernet0/1
  ip access-group OUTBOUND out
  ip access-group INBOUND in
```

---

## Editing ACLs

### Numbered ACLs
Cannot edit individual lines - must recreate.

```cisco
! View current ACL
show access-lists 10

! Delete and recreate
no access-list 10
access-list 10 permit 192.168.1.0 0.0.0.255
access-list 10 permit 192.168.2.0 0.0.0.255
```

### Named ACLs (Preferred)
Can add/remove specific lines.

```cisco
! View with sequence numbers
show access-lists

! Edit named ACL
ip access-list extended WEB-FILTER
  no 20                              ! Remove line 20
  15 permit tcp any host 10.0.0.1 eq 80   ! Insert at position 15
```

### Resequencing
```cisco
ip access-list resequence WEB-FILTER 10 10
! First line becomes 10, increment by 10
```

---

## ACL Logging

```cisco
! Log matches
access-list 110 deny ip any any log
access-list 110 deny ip any any log-input    ! Include interface

! View logs
show logging | include access-list
```

---

## ACL Verification

```cisco
! Show all ACLs
show access-lists

! Show specific ACL
show access-lists 110
show ip access-lists WEB-FILTER

! Show ACL on interface
show ip interface GigabitEthernet0/0 | include access

! Show ACL statistics
show access-lists 110
! Look for "matches" count

! Clear counters
clear access-list counters
clear access-list counters 110
```

---

## IPv6 ACLs

```cisco
! Create IPv6 ACL
ipv6 access-list BLOCK-TELNET
  deny tcp any any eq 23
  permit ipv6 any any

! Apply to interface
interface GigabitEthernet0/0
  ipv6 traffic-filter BLOCK-TELNET in

! Verify
show ipv6 access-list
```

---

## ACL Best Practices

1. **Document ACLs** with remarks
   ```cisco
   access-list 110 remark ### Allow web traffic ###
   ```

2. **Most specific entries first**

3. **Implicit deny reminder** - add explicit deny for logging
   ```cisco
   access-list 110 deny ip any any log
   ```

4. **Use named ACLs** for easier management

5. **Test before production**

6. **Plan placement** carefully

7. **Regular review** and cleanup

8. **Consider performance** - most matched rules first

---

## Quick Reference

| Task | Command |
|------|---------|
| Standard ACL | `access-list [1-99] permit/deny [source] [wildcard]` |
| Extended ACL | `access-list [100-199] permit/deny [proto] [src] [dst] [port]` |
| Named standard | `ip access-list standard [name]` |
| Named extended | `ip access-list extended [name]` |
| Apply inbound | `ip access-group [acl] in` |
| Apply outbound | `ip access-group [acl] out` |
| VTY access | `access-class [acl] in` |
| Show ACLs | `show access-lists` |
| Remove ACL | `no access-list [number]` |
| Remark | `access-list [#] remark [text]` |
