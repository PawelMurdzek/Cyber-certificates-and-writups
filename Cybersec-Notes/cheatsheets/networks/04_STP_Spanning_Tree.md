# Spanning Tree Protocol (STP)

## Why STP?

**Problem**: Layer 2 loops cause:
- **Broadcast storms**: Broadcasts loop infinitely
- **MAC table instability**: Same MAC learned on multiple ports
- **Multiple frame copies**: Duplicate frames delivered

**Solution**: STP (IEEE 802.1D) blocks redundant paths to prevent loops while maintaining backup links.

---

## STP Versions

| Protocol | Standard | Convergence | Description |
|----------|----------|-------------|-------------|
| **STP** | 802.1D | 30-50 sec | Original, one tree for all VLANs |
| **PVST+** | Cisco | 30-50 sec | Per-VLAN STP (Cisco proprietary) |
| **RSTP** | 802.1w | 1-2 sec | Rapid STP, faster convergence |
| **Rapid PVST+** | Cisco | 1-2 sec | Per-VLAN RSTP (Cisco default) |
| **MSTP** | 802.1s | 1-2 sec | Multiple instances, VLANs mapped to instances |

---

## STP Operation

### Root Bridge Election
1. All switches claim to be root initially
2. **Lowest Bridge ID wins** (becomes root)
3. Bridge ID = **Priority (2 bytes) + MAC Address (6 bytes)**

```
Bridge ID Format:
+----------+------------------+
| Priority |    MAC Address   |
| (4 bits) |    (48 bits)     |
+----------+------------------+
     |
Priority + Extended System ID (VLAN ID)
```

### Default Priority
- **Default**: 32768 (+ VLAN ID for PVST+)
- Must be **multiples of 4096**
- Valid range: 0, 4096, 8192, 12288, 16384, 20480, 24576, 28672, 32768...

### Root Bridge Selection
```cisco
! Set as root (lowers priority)
spanning-tree vlan 10 root primary     ! Priority 24576 or lower
spanning-tree vlan 10 root secondary   ! Priority 28672

! Or manually set priority
spanning-tree vlan 10 priority 4096    ! Must be multiple of 4096

! Verify
show spanning-tree vlan 10
show spanning-tree root
```

---

## STP Port Roles

| Role | Description |
|------|-------------|
| **Root Port (RP)** | Best path to root bridge (one per non-root switch) |
| **Designated Port (DP)** | Best port on each segment toward root (forwards traffic) |
| **Non-Designated/Blocked** | Backup port, blocks traffic to prevent loops |
| **Disabled** | Administratively down |

### Path Selection Criteria (in order)
1. **Lowest Root Bridge ID** (becomes root)
2. **Lowest Root Path Cost** (to root)
3. **Lowest Sender Bridge ID**
4. **Lowest Sender Port ID**

### STP Port Costs

| Speed | IEEE Cost (Short) | Long Path Cost |
|-------|------------------|----------------|
| 10 Mbps | 100 | 2,000,000 |
| 100 Mbps | 19 | 200,000 |
| 1 Gbps | 4 | 20,000 |
| 10 Gbps | 2 | 2,000 |

```cisco
! Modify port cost
interface Gi0/1
  spanning-tree cost 10

! Or use port priority (for equal cost paths)
interface Gi0/1
  spanning-tree port-priority 64    ! Default 128, lower wins
```

---

## STP Port States (802.1D)

| State | Duration | Learning | Forwarding | Receives BPDUs |
|-------|----------|----------|------------|----------------|
| **Disabled** | - | No | No | No |
| **Blocking** | - | No | No | Yes |
| **Listening** | 15 sec | No | No | Yes |
| **Learning** | 15 sec | Yes | No | Yes |
| **Forwarding** | - | Yes | Yes | Yes |

**Total convergence time**: ~30-50 seconds (listening + learning + possible MaxAge)

---

## BPDU (Bridge Protocol Data Unit)

Switches exchange BPDUs to:
- Elect root bridge
- Determine port roles
- Detect topology changes

### BPDU Types
- **Configuration BPDU**: Normal operation
- **TCN (Topology Change Notification)**: Signals change
- **TCA (Topology Change Acknowledgment)**: Confirms TCN

### BPDU Timers

| Timer | Default | Description |
|-------|---------|-------------|
| **Hello** | 2 sec | BPDU transmission interval |
| **Forward Delay** | 15 sec | Time in listening/learning |
| **Max Age** | 20 sec | BPDU timeout |

```cisco
! Modify timers (on root bridge only!)
spanning-tree vlan 10 hello-time 1
spanning-tree vlan 10 forward-time 10
spanning-tree vlan 10 max-age 15
```

---

## Rapid STP (RSTP) - 802.1w

### RSTP Port States

| 802.1D State | RSTP State | Active |
|--------------|------------|--------|
| Disabled | Discarding | No |
| Blocking | Discarding | No |
| Listening | Discarding | No |
| Learning | Learning | Yes |
| Forwarding | Forwarding | Yes |

### RSTP Port Roles

| Role | Description |
|------|-------------|
| **Root** | Best path to root |
| **Designated** | Forwarding port on segment |
| **Alternate** | Backup to root port (blocked) |
| **Backup** | Backup to designated port (blocked) |

### RSTP Port Types

| Type | Description |
|------|-------------|
| **Edge** | Connected to end device (fast transition) |
| **Point-to-Point** | Full-duplex link between switches |
| **Shared** | Half-duplex, hub-connected |

### RSTP Fast Convergence Features
- **Edge ports**: Immediately forwarding (like PortFast)
- **Proposal/Agreement**: Fast handshake for designated ports
- **Inferior BPDU handling**: Faster failure detection

---

## STP Protection Features

### PortFast
- **Purpose**: Skip listening/learning for access ports
- **Use on**: Edge ports connected to end devices
- **Never on**: Ports connected to switches

```cisco
! Per-interface
interface Gi0/1
  spanning-tree portfast

! Global default for access ports
spanning-tree portfast default

! Edge port (RSTP)
interface Gi0/1
  spanning-tree portfast edge
```

### BPDU Guard
- **Purpose**: Disables port if BPDU received
- **Use with**: PortFast ports
- **Prevents**: Unauthorized switch connections

```cisco
! Per-interface
interface Gi0/1
  spanning-tree bpduguard enable

! Global (for PortFast ports)
spanning-tree portfast bpduguard default

! Recovery from err-disabled
errdisable recovery cause bpduguard
errdisable recovery interval 300
```

### BPDU Filter
- **Purpose**: Stops sending/receiving BPDUs
- **Caution**: Can cause loops!

```cisco
! Per-interface (disables STP completely)
interface Gi0/1
  spanning-tree bpdufilter enable

! Global (sends 10 BPDUs, then stops)
spanning-tree portfast bpdufilter default
```

### Root Guard
- **Purpose**: Prevents port from becoming root port
- **Use on**: Ports that should never receive superior BPDUs
- Puts port in "root-inconsistent" state

```cisco
interface Gi0/24
  spanning-tree guard root
```

### Loop Guard
- **Purpose**: Prevents alternate/root ports from becoming designated
- **Use on**: Non-designated ports
- Prevents loops from unidirectional link failures

```cisco
interface Gi0/1
  spanning-tree guard loop

! Global
spanning-tree loopguard default
```

### UDLD (Unidirectional Link Detection)
- **Purpose**: Detects unidirectional links
- **Modes**: Normal (alert), Aggressive (err-disable)

```cisco
! Global
udld enable
udld aggressive

! Per-interface
interface Gi0/1
  udld port aggressive
```

---

## STP Configuration Summary

### Basic Configuration
```cisco
! Set STP mode
spanning-tree mode rapid-pvst     ! Rapid PVST+ (recommended)
spanning-tree mode pvst           ! PVST+

! Configure root bridge
spanning-tree vlan 10 root primary
spanning-tree vlan 20 root secondary

! Or set priority manually
spanning-tree vlan 10 priority 0    ! Lowest, guaranteed root

! Configure interface
interface Gi0/1
  spanning-tree portfast
  spanning-tree bpduguard enable
```

### Verification Commands
```cisco
! Show STP for all VLANs
show spanning-tree

! Show STP for specific VLAN
show spanning-tree vlan 10
show spanning-tree vlan 10 detail

! Show root bridge info
show spanning-tree root

! Show port-specific info
show spanning-tree interface Gi0/1
show spanning-tree interface Gi0/1 detail

! Show STP summary
show spanning-tree summary

! Show blocked ports
show spanning-tree blockedports

! Show inconsistent ports
show spanning-tree inconsistentports
```

---

## Per-VLAN Spanning Tree (PVST+)

- Cisco proprietary
- Separate STP instance per VLAN
- Allows load balancing across trunks
- Different root bridge per VLAN possible

```cisco
! Example: Load balancing
! Switch A: Root for VLANs 1-50
spanning-tree vlan 1-50 root primary
spanning-tree vlan 51-100 root secondary

! Switch B: Root for VLANs 51-100
spanning-tree vlan 51-100 root primary
spanning-tree vlan 1-50 root secondary
```

---

## MST (Multiple Spanning Tree)

- IEEE 802.1s
- Maps VLANs to STP instances
- Reduces STP overhead vs PVST+

```cisco
! Configure MST
spanning-tree mode mst

! MST configuration
spanning-tree mst configuration
  name REGION1
  revision 1
  instance 1 vlan 1-50
  instance 2 vlan 51-100

! Set root for instance
spanning-tree mst 1 root primary
spanning-tree mst 2 root secondary

! Verify
show spanning-tree mst
show spanning-tree mst configuration
```

---

## STP Best Practices

1. **Design root bridge location** - Central, stable, high-performance switch
2. **Use Rapid PVST+** for faster convergence
3. **Enable PortFast** on access ports
4. **Enable BPDU Guard** on PortFast ports
5. **Use Root Guard** on edge ports
6. **Document STP topology**
7. **Never disable STP** unless absolutely necessary
8. **Use consistent STP mode** across network
9. **Monitor for topology changes**
10. **Test redundant paths** periodically

---

## Troubleshooting STP

### Common Issues

| Problem | Symptom | Solution |
|---------|---------|----------|
| Root bridge incorrect | Suboptimal paths | Set proper priorities |
| Slow convergence | Long outages | Use RSTP, PortFast |
| err-disabled ports | Port down | Check BPDU Guard, fix root issue |
| Unidirectional link | Loops despite STP | Enable UDLD |
| TCN storms | Frequent MAC flushes | Identify flapping link |

### Debugging
```cisco
! Debug STP events
debug spanning-tree events

! Show STP counters
show spanning-tree detail | include changes

! Clear counters
clear spanning-tree counters
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Set STP mode | `spanning-tree mode [pvst\|rapid-pvst\|mst]` |
| Set root | `spanning-tree vlan [id] root primary` |
| Set priority | `spanning-tree vlan [id] priority [value]` |
| PortFast | `spanning-tree portfast` |
| BPDU Guard | `spanning-tree bpduguard enable` |
| Root Guard | `spanning-tree guard root` |
| Show STP | `show spanning-tree [vlan id]` |
| Show root | `show spanning-tree root` |
