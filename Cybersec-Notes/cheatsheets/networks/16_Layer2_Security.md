# Layer 2 Security

## Layer 2 Attack Types

| Attack | Description | Mitigation |
|--------|-------------|------------|
| **MAC Flooding** | Overflow switch CAM table | Port Security |
| **DHCP Starvation** | Exhaust DHCP pool | DHCP Snooping |
| **DHCP Spoofing** | Rogue DHCP server | DHCP Snooping |
| **ARP Spoofing** | Fake ARP replies | DAI, Static ARP |
| **VLAN Hopping** | Access other VLANs | DTP disable, native VLAN |
| **STP Attacks** | Become root bridge | BPDU Guard, Root Guard |
| **CDP/LLDP Recon** | Gather network info | Disable on edge ports |

---

## Port Security

Limits MAC addresses per port, preventing MAC flooding.

### Configuration
```cisco
interface GigabitEthernet0/1
  switchport mode access
  switchport port-security
  switchport port-security maximum 2              ! Max 2 MACs
  switchport port-security mac-address sticky     ! Learn MACs
  switchport port-security violation restrict     ! Violation action

! Static MAC assignment
interface GigabitEthernet0/2
  switchport port-security mac-address AAAA.BBBB.CCCC
```

### Violation Modes

| Mode | Action | Log | Counter |
|------|--------|-----|---------|
| **Protect** | Drop violating frames | No | No |
| **Restrict** | Drop + log + increment | Yes | Yes |
| **Shutdown** | err-disable port | Yes | Yes |

### Recovery from err-disabled
```cisco
! Manual recovery
interface GigabitEthernet0/1
  shutdown
  no shutdown

! Automatic recovery
errdisable recovery cause psecure-violation
errdisable recovery interval 300            ! 5 minutes
```

### Verification
```cisco
show port-security
show port-security interface Gi0/1
show port-security address
show interfaces status err-disabled
```

---

## DHCP Snooping

Filters untrusted DHCP messages, prevents rogue servers.

### Configuration
```cisco
! Enable globally
ip dhcp snooping
ip dhcp snooping vlan 10,20,30

! Trust uplink to legitimate DHCP server
interface GigabitEthernet0/24
  ip dhcp snooping trust

! Rate limit on access ports (untrusted by default)
interface range GigabitEthernet0/1 - 23
  ip dhcp snooping limit rate 15        ! packets per second

! Optional: Insert Option 82
ip dhcp snooping information option
```

### DHCP Snooping Database
```cisco
ip dhcp snooping database flash:/dhcp-snoop.db
ip dhcp snooping database timeout 60

show ip dhcp snooping binding
```

### How It Works
- **Trusted ports**: Accept all DHCP messages
- **Untrusted ports**: Only allow client messages (DISCOVER, REQUEST)
- Builds **binding table**: MAC, IP, VLAN, Port, Lease

### Verification
```cisco
show ip dhcp snooping
show ip dhcp snooping binding
show ip dhcp snooping statistics
```

---

## Dynamic ARP Inspection (DAI)

Validates ARP packets against DHCP snooping binding table.

### Configuration
```cisco
! DHCP snooping must be enabled first
ip dhcp snooping
ip dhcp snooping vlan 10

! Enable DAI
ip arp inspection vlan 10

! Trust uplinks
interface GigabitEthernet0/24
  ip arp inspection trust

! Rate limit ARP on untrusted (default 15 pps)
interface GigabitEthernet0/1
  ip arp inspection limit rate 20

! Optional: Additional validation
ip arp inspection validate src-mac dst-mac ip
```

### For Static IPs (ARP ACL)
```cisco
arp access-list STATIC-ARP
  permit ip host 192.168.1.50 mac host AAAA.BBBB.CCCC

ip arp inspection filter STATIC-ARP vlan 10
```

### Verification
```cisco
show ip arp inspection
show ip arp inspection vlan 10
show ip arp inspection interfaces
show ip arp inspection statistics
```

---

## IP Source Guard

Filters traffic based on DHCP snooping binding table.

### Configuration
```cisco
! Enables both IP and MAC filtering
interface GigabitEthernet0/1
  ip verify source port-security

! IP only
interface GigabitEthernet0/1
  ip verify source
```

### For Static IPs
```cisco
ip source binding AAAA.BBBB.CCCC vlan 10 192.168.1.50 interface Gi0/5
```

### Verification
```cisco
show ip source binding
show ip verify source
```

---

## Storm Control

Limits broadcast, multicast, or unicast traffic.

### Configuration
```cisco
interface GigabitEthernet0/1
  storm-control broadcast level 20          ! 20% of bandwidth
  storm-control multicast level 30
  storm-control unicast level 50
  storm-control action shutdown             ! Or trap
```

### Verification
```cisco
show storm-control
show storm-control broadcast
```

---

## Private VLANs (Edge)

Isolates ports within same VLAN (protected ports).

```cisco
! Simple port isolation (protected)
interface GigabitEthernet0/1
  switchport protected

interface GigabitEthernet0/2
  switchport protected

! Protected ports cannot communicate with each other
! But can communicate with non-protected (uplink)
```

---

## VLAN Hopping Prevention

### Disable DTP
```cisco
interface GigabitEthernet0/1
  switchport mode access
  switchport nonegotiate
```

### Secure Trunk Configuration
```cisco
interface GigabitEthernet0/24
  switchport mode trunk
  switchport nonegotiate
  switchport trunk native vlan 999          ! Unused VLAN
  switchport trunk allowed vlan 10,20,30    ! Only needed VLANs
```

### Native VLAN Security
```cisco
! Tag native VLAN
vlan dot1q tag native

! Or use unused VLAN as native
switchport trunk native vlan 999
```

---

## STP Security Features

### BPDU Guard
Disables port if BPDU received.
```cisco
! Per interface
interface GigabitEthernet0/1
  spanning-tree bpduguard enable

! Global on all PortFast ports
spanning-tree portfast bpduguard default
```

### Root Guard
Prevents port from becoming root.
```cisco
interface GigabitEthernet0/1
  spanning-tree guard root
```

### Loop Guard
Prevents alternate ports from forwarding.
```cisco
interface GigabitEthernet0/1
  spanning-tree guard loop

! Global
spanning-tree loopguard default
```

---

## Disable Unused Ports

```cisco
interface range GigabitEthernet0/20 - 24
  shutdown
  switchport mode access
  switchport access vlan 999                ! Unused/black-hole VLAN
```

---

## CDP/LLDP Security

```cisco
! Disable globally
no cdp run
no lldp run

! Disable per interface (edge ports)
interface GigabitEthernet0/1
  no cdp enable
  no lldp transmit
  no lldp receive
```

---

## 802.1X Port-Based Authentication

See AAA section for full 802.1X configuration.

```cisco
! Basic setup
aaa new-model
aaa authentication dot1x default group radius

dot1x system-auth-control

interface GigabitEthernet0/1
  switchport mode access
  authentication port-control auto
  dot1x pae authenticator
```

---

## Layer 2 Security Best Practices

1. **Enable port security** on access ports
2. **Enable DHCP snooping** on all VLANs
3. **Enable DAI** to prevent ARP attacks
4. **Enable IP Source Guard** for tight control
5. **Disable DTP** on all ports
6. **Change native VLAN** from default
7. **Restrict allowed VLANs** on trunks
8. **Enable BPDU Guard** on access ports
9. **Disable CDP/LLDP** on edge ports
10. **Shutdown unused ports**
11. **Use 802.1X** for authentication
12. **Monitor security logs** regularly

---

## Quick Reference

| Feature | Enable Command |
|---------|----------------|
| Port Security | `switchport port-security` |
| Sticky MAC | `switchport port-security mac-address sticky` |
| Violation mode | `switchport port-security violation [protect\|restrict\|shutdown]` |
| DHCP Snooping | `ip dhcp snooping` + `ip dhcp snooping vlan [id]` |
| Trust port | `ip dhcp snooping trust` |
| DAI | `ip arp inspection vlan [id]` |
| DAI trust | `ip arp inspection trust` |
| IP Source Guard | `ip verify source [port-security]` |
| Storm Control | `storm-control broadcast level [%]` |
| BPDU Guard | `spanning-tree bpduguard enable` |
| Root Guard | `spanning-tree guard root` |
