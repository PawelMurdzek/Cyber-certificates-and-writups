# VLANs and Trunking

## What is a VLAN?

A **Virtual LAN (VLAN)** is a logical grouping of devices on one or more switches, creating separate broadcast domains. VLANs provide:
- **Segmentation**: Separates traffic logically
- **Security**: Isolates sensitive data
- **Performance**: Reduces broadcast traffic
- **Flexibility**: Group users by function, not location

---

## VLAN Types

| VLAN Type | Description |
|-----------|-------------|
| **Default VLAN** | VLAN 1 - all ports by default (don't use for traffic!) |
| **Data VLAN** | User traffic |
| **Native VLAN** | Untagged traffic on trunk (default VLAN 1) |
| **Management VLAN** | Switch management access (SVI) |
| **Voice VLAN** | IP phones (QoS prioritized) |

### Reserved VLANs
- **VLAN 1**: Default, cannot be deleted
- **VLANs 1002-1005**: Reserved for Token Ring/FDDI
- **VLANs 1006-4094**: Extended range (VTP transparent mode)

---

## VLAN Configuration

### Creating VLANs
```cisco
! Create VLAN
vlan 10
  name Sales
vlan 20
  name Engineering
vlan 30
  name Management
vlan 99
  name Native

! Verify VLANs
show vlan brief
show vlan id 10
show vlan summary
```

### Assigning Ports to VLANs
```cisco
! Single interface
interface GigabitEthernet0/1
  switchport mode access
  switchport access vlan 10
  no shutdown

! Range of interfaces
interface range GigabitEthernet0/1 - 12
  switchport mode access
  switchport access vlan 10
  no shutdown

! Verify
show interfaces switchport
show interfaces GigabitEthernet0/1 switchport
```

### Voice VLAN Configuration
```cisco
! Configure access port with voice VLAN
interface GigabitEthernet0/5
  switchport mode access
  switchport access vlan 10        ! Data VLAN
  switchport voice vlan 50         ! Voice VLAN
  mls qos trust cos                ! Trust QoS markings

! Verify
show interfaces Gi0/5 switchport
```

---

## Trunk Configuration

### What is a Trunk?
- Carries traffic for **multiple VLANs** between switches
- Uses **802.1Q tagging** to identify VLAN membership
- Essential for multi-switch VLAN deployments

### 802.1Q Frame Tagging
```
Normal Frame:
+----------+----------+------+------+-----+
| Dest MAC | Src MAC  | Type | Data | FCS |
+----------+----------+------+------+-----+

802.1Q Tagged Frame:
+----------+----------+--------+------+------+-----+
| Dest MAC | Src MAC  |802.1Q  | Type | Data | FCS |
|          |          | Tag    |      |      |     |
+----------+----------+--------+------+------+-----+
                      |
                  4 bytes: TPID (0x8100), Priority (3 bits), 
                           CFI (1 bit), VLAN ID (12 bits)
```

### Configure Trunk Port
```cisco
! Static trunk configuration
interface GigabitEthernet0/24
  switchport trunk encapsulation dot1q    ! Required on some switches
  switchport mode trunk
  switchport trunk native vlan 99         ! Set native VLAN (match both ends!)
  switchport trunk allowed vlan 10,20,30  ! Restrict VLANs
  no shutdown

! Verify trunk
show interfaces trunk
show interfaces Gi0/24 switchport
```

### Trunk Allowed VLANs
```cisco
! Allow specific VLANs
switchport trunk allowed vlan 10,20,30

! Add VLAN to allowed list
switchport trunk allowed vlan add 40

! Remove VLAN from allowed list  
switchport trunk allowed vlan remove 20

! Allow all VLANs except specific ones
switchport trunk allowed vlan except 100-200

! Allow all VLANs
switchport trunk allowed vlan all
```

---

## DTP (Dynamic Trunking Protocol)

Cisco proprietary protocol that auto-negotiates trunking.

| Mode | Description | Command |
|------|-------------|---------|
| **Access** | Never trunks | `switchport mode access` |
| **Trunk** | Always trunks | `switchport mode trunk` |
| **Dynamic Auto** | Trunks if other end initiates | `switchport mode dynamic auto` |
| **Dynamic Desirable** | Actively tries to trunk | `switchport mode dynamic desirable` |

### DTP Negotiation Matrix

| | Access | Trunk | Dynamic Auto | Dynamic Desirable |
|---|--------|-------|--------------|-------------------|
| **Access** | Access | ❌ | Access | Access |
| **Trunk** | ❌ | Trunk | Trunk | Trunk |
| **Dynamic Auto** | Access | Trunk | Access | Trunk |
| **Dynamic Desirable** | Access | Trunk | Trunk | Trunk |

### Disable DTP (Best Practice for Security)
```cisco
! On access ports
interface Gi0/1
  switchport mode access
  switchport nonegotiate

! On trunk ports
interface Gi0/24
  switchport mode trunk
  switchport nonegotiate
```

---

## Native VLAN

- **Untagged** traffic on a trunk
- **Must match** on both ends of trunk
- Default: VLAN 1
- **Security risk**: VLAN hopping attacks

### Best Practices
1. Change native VLAN from default (VLAN 1)
2. Use unused VLAN as native
3. Match on both ends
4. Don't use native VLAN for user traffic

```cisco
! Configure native VLAN
interface Gi0/24
  switchport trunk native vlan 99

! Tag native VLAN traffic (added security)
vlan dot1q tag native
```

---

## VTP (VLAN Trunking Protocol)

Cisco proprietary - synchronizes VLAN databases across switches.

### VTP Modes

| Mode | Creates VLANs | Forwards | Syncs |
|------|---------------|----------|-------|
| **Server** | ✅ | ✅ | ✅ |
| **Client** | ❌ | ✅ | ✅ |
| **Transparent** | ✅ (local) | ✅ | ❌ |
| **Off** (v3) | ✅ | ❌ | ❌ |

### VTP Versions
- **VTPv1**: Original, VLANs 1-1005
- **VTPv2**: Adds Token Ring support
- **VTPv3**: Enhanced security, extended VLANs, better authentication

### VTP Configuration
```cisco
! Set VTP domain and password
vtp domain MYDOMAIN
vtp password VTPsecret
vtp version 2

! Set VTP mode
vtp mode server      ! Default
vtp mode client
vtp mode transparent

! Verify
show vtp status
show vtp password
```

### VTP Pruning
- Restricts flooded traffic to trunks that need it
- Saves bandwidth
```cisco
vtp pruning
```

> **⚠️ VTP Warning**: Higher revision number overwrites VLAN database. Insert new switch in transparent mode first!

---

## Inter-VLAN Routing

VLANs are separate broadcast domains - need Layer 3 routing between them.

### Method 1: Router-on-a-Stick (ROAS)

Single physical interface, multiple subinterfaces.

**Router Configuration:**
```cisco
interface GigabitEthernet0/0
  no ip address
  no shutdown

interface GigabitEthernet0/0.10
  encapsulation dot1Q 10
  ip address 192.168.10.1 255.255.255.0

interface GigabitEthernet0/0.20
  encapsulation dot1Q 20
  ip address 192.168.20.1 255.255.255.0

interface GigabitEthernet0/0.99
  encapsulation dot1Q 99 native        ! Native VLAN
  ip address 192.168.99.1 255.255.255.0
```

**Switch Configuration:**
```cisco
interface GigabitEthernet0/24
  switchport trunk encapsulation dot1q
  switchport mode trunk
  switchport trunk native vlan 99
  switchport trunk allowed vlan 10,20,99
```

### Method 2: Layer 3 Switch (SVI)

More efficient - no external router needed.

```cisco
! Enable IP routing
ip routing

! Create SVIs
interface vlan 10
  ip address 192.168.10.1 255.255.255.0
  no shutdown

interface vlan 20
  ip address 192.168.20.1 255.255.255.0
  no shutdown

! Verify
show ip route
show ip interface brief
```

### Method 3: Routed Ports

Convert switch port to Layer 3.

```cisco
interface GigabitEthernet0/1
  no switchport
  ip address 10.0.0.1 255.255.255.252
```

---

## VLAN Troubleshooting

### Common Issues

| Problem | Possible Cause | Solution |
|---------|----------------|----------|
| Can't ping across VLANs | No inter-VLAN routing | Configure ROAS or L3 switch |
| Trunk not forming | DTP mode mismatch | Check/force trunk mode |
| Native VLAN mismatch | Different native VLANs | Match on both ends |
| VLAN not in database | VLAN not created | Create VLAN or check VTP |
| Port in wrong VLAN | Misconfiguration | Verify port assignment |

### Troubleshooting Commands
```cisco
! VLAN verification
show vlan brief
show vlan id [vlan-id]

! Trunk verification
show interfaces trunk
show interfaces [interface] switchport

! VTP verification
show vtp status

! Interface status
show interfaces status

! IP verification (L3 switch)
show ip interface brief
show ip route
```

---

## VLAN Best Practices

1. **Never use VLAN 1** for user traffic
2. **Change native VLAN** from default
3. **Disable DTP** on access ports
4. **Restrict allowed VLANs** on trunks
5. **Use VTP transparent** or **VTPv3** for security
6. **Document VLAN assignments**
7. **Shutdown unused ports**
8. **Use descriptive VLAN names**
9. **Consistent VLAN IDs** across network
10. **Separate management, voice, and data VLANs**

---

## Quick Reference

| Task | Command |
|------|---------|
| Create VLAN | `vlan [id]` → `name [name]` |
| Assign access port | `switchport mode access` → `switchport access vlan [id]` |
| Configure trunk | `switchport mode trunk` |
| Set native VLAN | `switchport trunk native vlan [id]` |
| Limit trunk VLANs | `switchport trunk allowed vlan [list]` |
| Disable DTP | `switchport nonegotiate` |
| Show VLANs | `show vlan brief` |
| Show trunks | `show interfaces trunk` |
| Show port mode | `show interfaces [if] switchport` |
