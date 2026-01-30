# EtherChannel (Link Aggregation)

## What is EtherChannel?

**EtherChannel** bundles multiple physical links into one logical link, providing:
- **Increased bandwidth**: Combined capacity of all links
- **Redundancy**: Traffic redistributes if link fails
- **Load balancing**: Traffic distributed across links
- **Single logical interface**: Simplified management

> **Important**: All member ports must have identical configuration (speed, duplex, VLAN, trunk mode)

---

## EtherChannel Protocols

| Protocol | Standard | Description |
|----------|----------|-------------|
| **LACP** | IEEE 802.3ad | Industry standard, preferred |
| **PAgP** | Cisco | Cisco proprietary |
| **Static** | - | No negotiation (on) |

### LACP (Link Aggregation Control Protocol)

| Mode | Description | Pairs With |
|------|-------------|------------|
| **Active** | Actively initiates LACP | Active, Passive |
| **Passive** | Waits for LACP packets | Active only |

```
LACP Negotiation:
Active  ↔ Active  = Channel forms
Active  ↔ Passive = Channel forms
Passive ↔ Passive = NO channel (both waiting)
```

### PAgP (Port Aggregation Protocol)

| Mode | Description | Pairs With |
|------|-------------|------------|
| **Desirable** | Actively initiates PAgP | Desirable, Auto |
| **Auto** | Waits for PAgP packets | Desirable only |

```
PAgP Negotiation:
Desirable ↔ Desirable = Channel forms
Desirable ↔ Auto      = Channel forms
Auto      ↔ Auto      = NO channel (both waiting)
```

### Static (On Mode)
- No negotiation protocol
- Forces channel without negotiation
- **Must be "on" on both ends**
- **Not recommended** - no error detection

---

## EtherChannel Configuration

### LACP Configuration (Recommended)
```cisco
! Switch A
interface range GigabitEthernet0/1 - 2
  channel-group 1 mode active
  
interface port-channel 1
  switchport mode trunk
  switchport trunk allowed vlan 10,20,30

! Switch B  
interface range GigabitEthernet0/1 - 2
  channel-group 1 mode active
  
interface port-channel 1
  switchport mode trunk
  switchport trunk allowed vlan 10,20,30
```

### PAgP Configuration
```cisco
interface range GigabitEthernet0/1 - 2
  channel-group 1 mode desirable

interface port-channel 1
  switchport mode trunk
```

### Static EtherChannel
```cisco
interface range GigabitEthernet0/1 - 2
  channel-group 1 mode on

interface port-channel 1
  switchport mode trunk
```

### Layer 3 EtherChannel
```cisco
interface range GigabitEthernet0/1 - 2
  no switchport
  channel-group 1 mode active

interface port-channel 1
  no switchport
  ip address 10.0.0.1 255.255.255.252
```

---

## Load Balancing

EtherChannel distributes traffic based on hash of selected fields.

### Load Balancing Methods

| Method | Description | Command |
|--------|-------------|---------|
| **src-mac** | Source MAC address | `port-channel load-balance src-mac` |
| **dst-mac** | Destination MAC address | `port-channel load-balance dst-mac` |
| **src-dst-mac** | Source and destination MAC | `port-channel load-balance src-dst-mac` |
| **src-ip** | Source IP address | `port-channel load-balance src-ip` |
| **dst-ip** | Destination IP address | `port-channel load-balance dst-ip` |
| **src-dst-ip** | Source and destination IP | `port-channel load-balance src-dst-ip` |
| **src-port** | Source TCP/UDP port | `port-channel load-balance src-port` |
| **dst-port** | Destination TCP/UDP port | `port-channel load-balance dst-port` |
| **src-dst-port** | Both ports | `port-channel load-balance src-dst-port` |

```cisco
! Configure load balancing (global)
port-channel load-balance src-dst-ip

! Verify
show etherchannel load-balance
```

### Load Balancing Best Practices
- **L2 only**: Use MAC-based
- **L3 traffic**: Use IP-based
- **Server farms**: Use src-dst-ip or src-dst-port
- **Consider traffic patterns** - choose method that maximizes distribution

---

## LACP System Priority and Port Priority

### System Priority
- Determines which switch controls port selection
- Lower = higher priority
- Default: 32768

```cisco
! Set LACP system priority
lacp system-priority 4096
```

### Port Priority  
- Determines which ports are active (max 8 active, 8 standby)
- Lower = higher priority
- Default: 32768

```cisco
interface GigabitEthernet0/1
  lacp port-priority 100
```

---

## EtherChannel Verification

```cisco
! Show EtherChannel summary
show etherchannel summary

! Show EtherChannel detail
show etherchannel detail
show etherchannel 1 detail

! Show port-channel interface
show interfaces port-channel 1

! Show member ports
show etherchannel port-channel

! Show load balancing
show etherchannel load-balance

! Show LACP info
show lacp neighbor
show lacp internal

! Show PAgP info
show pagp neighbor
show pagp internal
```

### Understanding EtherChannel Summary Output
```
Group  Port-channel  Protocol    Ports
------+-------------+-----------+---------------------------------------
1      Po1(SU)       LACP       Gi0/1(P) Gi0/2(P)

Flags:
S = L2 (switchport)      D = Down
U = in use               P = bundled in port-channel
I = stand-alone          s = suspended
H = Hot-standby (LACP)   R = Layer3
```

---

## EtherChannel Guidelines

### Requirements for Member Ports
All ports in a channel **must have identical**:
- Speed and duplex
- Access/Trunk mode
- Native VLAN (if trunk)
- Allowed VLANs (if trunk)
- Access VLAN (if access)
- STP settings
- QoS settings

### Configuration Order
1. Configure channel-group on physical interfaces
2. Configure Port-channel (inherits from physical)
3. Or configure Port-channel first (applies to members)

### Maximum Links
- **Up to 8 active links** per EtherChannel
- **Up to 16 links total** (8 active + 8 standby with LACP)

---

## Troubleshooting EtherChannel

### Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| Channel not forming | Mode mismatch | Check LACP/PAgP modes on both ends |
| Ports suspended | Configuration mismatch | Ensure identical port config |
| Individual mode | Wrong mode | Use active/passive or desirable/auto |
| Ports err-disabled | STP issues | Check for BPDU issues |
| Load not balanced | Poor hash selection | Change load-balance method |

### Troubleshooting Commands
```cisco
! Check if channel formed
show etherchannel summary

! Check port status flags
! (P) = bundled, (I) = individual, (s) = suspended

! Check misconfigurations
show interfaces GigabitEthernet0/1 switchport
show running-config interface GigabitEthernet0/1

! Compare configurations
show running-config interface range Gi0/1 - 2

! Check LACP neighbor
show lacp neighbor

! Debug EtherChannel
debug etherchannel events
```

### Suspended Ports
If ports show "(s)" suspended:
1. Check speed/duplex match
2. Check VLAN configuration
3. Check STP port type consistency
4. Check native VLAN match

---

## EtherChannel with STP

- Port-channel treated as **single logical link** by STP
- STP cost based on combined bandwidth
- If all member links fail, STP reconverges

### STP Port Cost with EtherChannel

| Bundle Bandwidth | STP Cost |
|------------------|----------|
| Fast EtherChannel | 12 (2x100Mbps) or 6 (4x100Mbps) |
| Gigabit EtherChannel | 3 (2x1G) or 2 (4x1G) |

---

## Layer 3 EtherChannel

Used for routing between switches or to routers.

```cisco
! Configure L3 EtherChannel
interface range GigabitEthernet0/1 - 2
  no switchport
  no ip address
  channel-group 1 mode active

interface port-channel 1
  no switchport
  ip address 10.0.0.1 255.255.255.252

! Verify
show ip interface brief
show etherchannel summary
```

---

## Best Practices

1. **Use LACP** over PAgP (industry standard)
2. **Avoid "on" mode** - no error detection
3. **Use active-active** for fastest negotiation
4. **Verify configurations match** before bundling
5. **Document EtherChannel assignments**
6. **Use appropriate load balancing**
7. **Monitor member link status**
8. **Configure port-channel first** for consistency
9. **Consider growth** - add links as needed
10. **Test failover** periodically

---

## Quick Reference

| Task | Command |
|------|---------|
| LACP active | `channel-group [n] mode active` |
| LACP passive | `channel-group [n] mode passive` |
| PAgP desirable | `channel-group [n] mode desirable` |
| PAgP auto | `channel-group [n] mode auto` |
| Static | `channel-group [n] mode on` |
| Load balance | `port-channel load-balance [method]` |
| LACP priority | `lacp system-priority [value]` |
| Show summary | `show etherchannel summary` |
| Show LACP | `show lacp neighbor` |

---

## Protocol Comparison

| Feature | LACP | PAgP | Static |
|---------|------|------|--------|
| Standard | IEEE 802.3ad | Cisco | N/A |
| Negotiation | Yes | Yes | No |
| Error Detection | Yes | Yes | No |
| Hot Standby | Yes (8+8) | No | No |
| Recommended | ✅ | Cisco-only | ❌ |
