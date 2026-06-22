# Ethernet and Switching Fundamentals

## How Switches Work

### Switch Functions
1. **Learning**: Records source MAC addresses in MAC address table
2. **Flooding**: Forwards unknown unicast/broadcast to all ports (except source)
3. **Forwarding**: Sends frame out specific port based on MAC table
4. **Filtering**: Drops frames when source and destination are on same port
5. **Aging**: Removes unused MAC entries (default 300 seconds)

### MAC Address Table
```cisco
! View MAC address table
show mac address-table
show mac address-table dynamic
show mac address-table interface Gi0/1
show mac address-table address AAAA.BBBB.CCCC

! Clear MAC table
clear mac address-table dynamic
```

### Frame Forwarding Methods

| Method | Description | Latency | Error Detection |
|--------|-------------|---------|-----------------|
| **Store-and-Forward** | Receives entire frame, checks CRC, then forwards | Higher | Yes |
| **Cut-Through** | Forwards after reading destination MAC (14 bytes) | Lower | No |
| **Fragment-Free** | Forwards after reading first 64 bytes | Medium | Partial (collision fragments) |

> **Cisco Default**: Store-and-Forward

---

## Ethernet Frame Structure

```
+----------+-----+----------+----------+------+------+-----+
| Preamble | SFD | Dest MAC | Src MAC  | Type | Data | FCS |
+----------+-----+----------+----------+------+------+-----+
| 7 bytes  | 1B  | 6 bytes  | 6 bytes  | 2B   |46-1500|4B  |
```

### EtherType Values
| Value | Protocol |
|-------|----------|
| 0x0800 | IPv4 |
| 0x0806 | ARP |
| 0x86DD | IPv6 |
| 0x8100 | 802.1Q VLAN Tag |
| 0x88CC | LLDP |

---

## Switch Memory Types

| Memory | Stores | Volatile |
|--------|--------|----------|
| **ROM** | POST, Bootstrap, ROMMON | No |
| **Flash** | IOS image | No |
| **NVRAM** | startup-config | No |
| **RAM** | running-config, MAC table, ARP cache | Yes |

---

## Cisco IOS Basics

### Boot Sequence
1. POST (Power-On Self-Test)
2. Load bootstrap from ROM
3. Locate and load IOS from Flash
4. Load startup-config from NVRAM to running-config in RAM

### CLI Modes

| Mode | Prompt | Access Command |
|------|--------|----------------|
| User EXEC | `Switch>` | Login |
| Privileged EXEC | `Switch#` | `enable` |
| Global Config | `Switch(config)#` | `configure terminal` |
| Interface Config | `Switch(config-if)#` | `interface [type/number]` |
| Line Config | `Switch(config-line)#` | `line [type] [number]` |
| VLAN Config | `Switch(config-vlan)#` | `vlan [id]` |

### Navigation Commands
```cisco
! Move between modes
enable                  ! User → Privileged
configure terminal      ! Privileged → Global Config
exit                    ! Go back one level
end                     ! Return to Privileged EXEC
Ctrl+Z                  ! Same as end

! Get help
?                       ! Show available commands
command ?               ! Show options for command
```

---

## Basic Switch Configuration

### Initial Setup
```cisco
! Enter privileged mode
enable

! Enter global configuration
configure terminal

! Set hostname
hostname Switch1

! Disable DNS lookup (prevents typo delays)
no ip domain-lookup

! Set passwords
enable secret Cisco123          ! Encrypted privileged password
service password-encryption     ! Encrypt all passwords

! Configure console
line console 0
  password console123
  login
  logging synchronous          ! Prevents log messages interrupting input
  exec-timeout 5 0             ! 5 minutes timeout

! Configure VTY (Telnet/SSH)
line vty 0 15
  password vty123
  login
  transport input ssh          ! SSH only (more secure)
  exec-timeout 5 0

! Set MOTD banner
banner motd # Unauthorized access prohibited! #

! Save configuration
end
copy running-config startup-config
! or
write memory
```

### Interface Configuration
```cisco
! Configure interface
interface GigabitEthernet0/1
  description Uplink to Core
  no shutdown

! Configure range of interfaces
interface range GigabitEthernet0/1 - 24
  description Access Ports
  switchport mode access
  switchport access vlan 10
  no shutdown

! Disable unused interfaces (security)
interface range GigabitEthernet0/20 - 24
  shutdown
```

### Management VLAN and SVI
```cisco
! Create management VLAN
vlan 99
  name Management

! Configure SVI (Switch Virtual Interface)
interface vlan 99
  ip address 192.168.99.10 255.255.255.0
  no shutdown

! Set default gateway
ip default-gateway 192.168.99.1

! Assign management VLAN to interface
interface GigabitEthernet0/24
  switchport mode access
  switchport access vlan 99
```

---

## SSH Configuration

```cisco
! Prerequisites
hostname Switch1
ip domain-name example.com

! Generate RSA keys
crypto key generate rsa modulus 2048

! Create local user
username admin privilege 15 secret AdminPass123

! Configure VTY lines for SSH
line vty 0 15
  transport input ssh
  login local

! Verify
show ip ssh
show ssh
```

---

## Show Commands Reference

```cisco
! Interface information
show interfaces                        ! Detailed interface info
show interfaces status                 ! Quick port status
show ip interface brief                ! IP and status summary
show interfaces GigabitEthernet0/1     ! Specific interface

! MAC and ARP
show mac address-table                 ! MAC table
show arp                               ! ARP cache

! Configuration
show running-config                    ! Current config
show startup-config                    ! Saved config
show running-config interface Gi0/1    ! Specific interface config

! System information
show version                           ! IOS version, uptime, memory
show flash                             ! Flash contents
show inventory                         ! Hardware inventory
show processes cpu                     ! CPU utilization
show logging                           ! System logs

! Connectivity
show cdp neighbors                     ! Cisco Discovery Protocol
show cdp neighbors detail              ! Detailed CDP info
show lldp neighbors                    ! LLDP neighbor info
```

---

## CDP and LLDP

### CDP (Cisco Discovery Protocol)
- Cisco proprietary, Layer 2
- Enabled by default on Cisco devices
- Sends updates every 60 seconds, holdtime 180 seconds

```cisco
! Verify CDP
show cdp neighbors
show cdp neighbors detail
show cdp interface

! Configure CDP
cdp run                     ! Enable globally
no cdp run                  ! Disable globally

interface Gi0/1
  cdp enable                ! Enable on interface
  no cdp enable             ! Disable on interface

! Modify timers
cdp timer 30                ! Advertisement interval
cdp holdtime 120            ! Holdtime
```

### LLDP (Link Layer Discovery Protocol)
- IEEE 802.1AB, industry standard
- Not enabled by default on Cisco

```cisco
! Enable LLDP
lldp run

! Per-interface
interface Gi0/1
  lldp transmit
  lldp receive

! Verify
show lldp neighbors
show lldp neighbors detail
```

---

## Interface Errors and Troubleshooting

### Error Types

| Counter | Indicates |
|---------|-----------|
| **CRC** | Frame corruption, cable issue, duplex mismatch |
| **Runts** | Frames < 64 bytes (collisions, bad NIC) |
| **Giants** | Frames > 1518 bytes (MTU mismatch) |
| **Collisions** | Normal on half-duplex, problem on full-duplex |
| **Late Collisions** | Collision after 64 bytes (duplex mismatch!) |
| **Input Errors** | Total receive errors |
| **Output Errors** | Total transmit errors |

### Interpreting Show Interface Output
```
GigabitEthernet0/1 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is aaaa.bbbb.cccc
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec
  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX
  ...
  5 minute input rate 1000 bits/sec, 2 packets/sec
  5 minute output rate 2000 bits/sec, 3 packets/sec
     1000 packets input, 64000 bytes, 0 no buffer
     0 broadcasts, 0 multicasts
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     500 packets output, 32000 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
```

### Interface Status Combinations

| Line 1 | Line 2 | Meaning |
|--------|--------|---------|
| up | up | Working |
| down | down | Cable/port issue, no connection |
| up | down | Protocol issue (encapsulation, keepalives) |
| administratively down | down | Interface shutdown |

---

## Speed and Duplex Configuration

```cisco
! Auto-negotiation (default)
interface GigabitEthernet0/1
  speed auto
  duplex auto

! Manual configuration
interface GigabitEthernet0/1
  speed 1000
  duplex full

! Verify
show interfaces GigabitEthernet0/1 | include duplex
```

> **Best Practice**: Use auto-negotiation on both ends, or manually configure both ends the same

---

## Port Types

| Port Type | Function |
|-----------|----------|
| **Access** | Connects to end devices, single VLAN |
| **Trunk** | Carries multiple VLANs between switches |
| **EtherChannel** | Bundled links for bandwidth/redundancy |
| **Routed** | L3 port on multilayer switch |

---

## Important Switch Security Best Practices

1. **Change default passwords**
2. **Disable unused ports** (`shutdown`)
3. **Use SSH instead of Telnet**
4. **Configure banners**
5. **Disable CDP on edge ports**
6. **Enable port security**
7. **Use VLANs to segment traffic**
8. **Configure DHCP snooping**
9. **Enable storm control**
10. **Keep IOS updated**

---

## Quick Reference Commands

| Task | Command |
|------|---------|
| Save config | `copy run start` or `wr` |
| Erase config | `write erase` |
| Reload device | `reload` |
| Show all interfaces | `show ip int brief` |
| Clear counters | `clear counters` |
| View logs | `show logging` |
| Debug | `debug [feature]` |
| Stop debug | `undebug all` |
