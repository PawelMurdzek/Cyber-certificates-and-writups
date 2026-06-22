# Network Fundamentals

## OSI Model (7 Layers)

| Layer | Name | PDU | Devices | Protocols/Standards |
|-------|------|-----|---------|---------------------|
| 7 | Application | Data | - | HTTP, HTTPS, FTP, SMTP, DNS, DHCP, Telnet, SSH, SNMP, POP3, IMAP |
| 6 | Presentation | Data | - | SSL/TLS, JPEG, GIF, MPEG, ASCII, EBCDIC |
| 5 | Session | Data | - | NetBIOS, PPTP, RPC, NFS |
| 4 | Transport | Segment/Datagram | - | TCP, UDP |
| 3 | Network | Packet | Router, L3 Switch | IP, ICMP, ARP, OSPF, EIGRP, BGP |
| 2 | Data Link | Frame | Switch, Bridge | Ethernet (802.3), Wi-Fi (802.11), PPP, HDLC, STP |
| 1 | Physical | Bits | Hub, Repeater, Cables | Ethernet cables, Fiber, RS-232 |

### Mnemonic
- **Top to Bottom**: All People Seem To Need Data Processing
- **Bottom to Top**: Please Do Not Throw Sausage Pizza Away

---

## TCP/IP Model (4 Layers)

| TCP/IP Layer | OSI Equivalent | Protocols |
|--------------|----------------|-----------|
| Application | 7, 6, 5 | HTTP, FTP, DNS, DHCP, SSH, SMTP |
| Transport | 4 | TCP, UDP |
| Internet | 3 | IP, ICMP, ARP, OSPF |
| Network Access | 2, 1 | Ethernet, Wi-Fi, PPP |

---

## TCP vs UDP

| Feature | TCP | UDP |
|---------|-----|-----|
| Connection | Connection-oriented (3-way handshake) | Connectionless |
| Reliability | Guaranteed delivery, acknowledgments | Best-effort, no ACKs |
| Ordering | Maintains sequence | No ordering |
| Speed | Slower (overhead) | Faster |
| Header Size | 20-60 bytes | 8 bytes |
| Use Cases | HTTP, FTP, SSH, Email, File transfer | DNS, DHCP, VoIP, Video streaming, TFTP |

### TCP 3-Way Handshake
```
Client → Server: SYN (seq=x)
Server → Client: SYN-ACK (seq=y, ack=x+1)
Client → Server: ACK (seq=x+1, ack=y+1)
```

### TCP 4-Way Termination
```
Client → Server: FIN
Server → Client: ACK
Server → Client: FIN
Client → Server: ACK
```

### TCP Flags
| Flag | Purpose |
|------|---------|
| SYN | Synchronize - initiate connection |
| ACK | Acknowledge received data |
| FIN | Finish - terminate connection |
| RST | Reset - abort connection |
| PSH | Push - send data immediately |
| URG | Urgent - prioritize data |

---

## Well-Known Ports (Must Memorize!)

| Port | Protocol | Service |
|------|----------|---------|
| 20 | TCP | FTP Data |
| 21 | TCP | FTP Control |
| 22 | TCP | SSH, SFTP, SCP |
| 23 | TCP | Telnet |
| 25 | TCP | SMTP |
| 53 | TCP/UDP | DNS |
| 67 | UDP | DHCP Server |
| 68 | UDP | DHCP Client |
| 69 | UDP | TFTP |
| 80 | TCP | HTTP |
| 110 | TCP | POP3 |
| 123 | UDP | NTP |
| 143 | TCP | IMAP |
| 161 | UDP | SNMP |
| 162 | UDP | SNMP Trap |
| 443 | TCP | HTTPS |
| 514 | UDP | Syslog |
| 520 | UDP | RIP |
| 3389 | TCP | RDP |

**Port Ranges:**
- **Well-Known**: 0-1023 (system/privileged)
- **Registered**: 1024-49151 (user applications)
- **Dynamic/Ephemeral**: 49152-65535 (client-side)

---

## Network Topologies

### Physical Topologies

| Topology | Description | Pros | Cons |
|----------|-------------|------|------|
| **Bus** | Single cable, all devices share | Simple, cheap | Single point of failure, collisions |
| **Star** | Central device (switch/hub) | Easy management, fault isolation | Central device failure affects all |
| **Ring** | Circular, data travels one direction | Predictable performance | Single break disrupts network |
| **Mesh** | Every device connected to every other | Redundancy, fault tolerance | Expensive, complex |
| **Full Mesh** | All nodes connected | Maximum redundancy | Very expensive (n(n-1)/2 links) |
| **Partial Mesh** | Some nodes connected | Balance of cost/redundancy | Less redundant than full mesh |
| **Hybrid** | Combination of topologies | Flexible | Complex design |

### Logical Topologies
- How data flows regardless of physical layout
- Example: Physically star, logically bus (old Ethernet with hub)

---

## Cabling Standards

### Ethernet Cable Categories

| Category | Speed | Bandwidth | Max Length | Standard |
|----------|-------|-----------|------------|----------|
| Cat 5 | 100 Mbps | 100 MHz | 100m | 100BASE-TX |
| Cat 5e | 1 Gbps | 100 MHz | 100m | 1000BASE-T |
| Cat 6 | 1 Gbps (10G at 55m) | 250 MHz | 100m/55m | 1000BASE-T, 10GBASE-T |
| Cat 6a | 10 Gbps | 500 MHz | 100m | 10GBASE-T |
| Cat 7 | 10 Gbps | 600 MHz | 100m | 10GBASE-T |
| Cat 8 | 25/40 Gbps | 2000 MHz | 30m | Data centers |

### Cable Types

**Straight-Through Cable (T568B-T568B or T568A-T568A)**
- Used for: PC to Switch, Router to Switch, PC to Hub
- Different device types

**Crossover Cable (T568A-T568B)**
- Used for: Switch to Switch, PC to PC, Router to Router
- Same device types
- **Note**: Modern devices with Auto-MDIX detect and adjust automatically

**Rollover/Console Cable**
- Used for: PC to Router/Switch console port
- Pin 1 connects to Pin 8, Pin 2 to Pin 7, etc.

### T568A vs T568B Pin-out

| Pin | T568A | T568B |
|-----|-------|-------|
| 1 | White/Green | White/Orange |
| 2 | Green | Orange |
| 3 | White/Orange | White/Green |
| 4 | Blue | Blue |
| 5 | White/Blue | White/Blue |
| 6 | Orange | Green |
| 7 | White/Brown | White/Brown |
| 8 | Brown | Brown |

### Fiber Optic Cables

| Type | Description | Distance | Use Case |
|------|-------------|----------|----------|
| **SMF (Single-Mode)** | Small core (9μm), laser | Up to 100+ km | Long distance, WAN, campus |
| **MMF (Multi-Mode)** | Large core (50/62.5μm), LED | Up to 2 km | Short distance, LAN |

**Fiber Connectors:**
- **SC**: Square Connector, push-pull
- **ST**: Straight Tip, bayonet twist
- **LC**: Lucent Connector, small form factor
- **MTRJ**: Mechanical Transfer Registered Jack

---

## Ethernet Standards

| Standard | Speed | Cable Type | Max Distance |
|----------|-------|------------|--------------|
| 10BASE-T | 10 Mbps | Cat 3+ UTP | 100m |
| 100BASE-TX | 100 Mbps | Cat 5+ UTP | 100m |
| 100BASE-FX | 100 Mbps | MMF | 400m (HD), 2km (FD) |
| 1000BASE-T | 1 Gbps | Cat 5e+ UTP | 100m |
| 1000BASE-SX | 1 Gbps | MMF | 220-550m |
| 1000BASE-LX | 1 Gbps | SMF/MMF | 5km SMF, 550m MMF |
| 10GBASE-T | 10 Gbps | Cat 6a+ UTP | 100m |
| 10GBASE-SR | 10 Gbps | MMF | 26-400m |
| 10GBASE-LR | 10 Gbps | SMF | 10 km |

---

## Duplex and Speed

### Duplex Modes
- **Half-Duplex**: Can send OR receive, not both (uses CSMA/CD)
- **Full-Duplex**: Can send AND receive simultaneously (no collisions)

### Auto-Negotiation
- Devices negotiate highest common speed and duplex
- If one side has auto-negotiation disabled:
  - Speed: Sensed
  - Duplex: Defaults to half-duplex (potential mismatch!)

### Duplex Mismatch
- Causes: Late collisions, CRC errors, slow performance
- Fix: Manually configure both ends or ensure both use auto-negotiation

---

## Collision and Broadcast Domains

| Device | Collision Domains | Broadcast Domains |
|--------|------------------|-------------------|
| Hub | 1 (shared) | 1 |
| Switch | 1 per port | 1 (unless VLANs) |
| Router | 1 per interface | 1 per interface |

- **Collision Domain**: Network segment where collisions can occur
- **Broadcast Domain**: Network segment where broadcast frames are forwarded

---

## Binary and Hexadecimal

### Binary to Decimal
| Bit Position | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
|--------------|---|---|---|---|---|---|---|---|
| Value | 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |

Example: `11001010` = 128+64+8+2 = **202**

### Hexadecimal
- Base 16: 0-9, A-F (A=10, B=11, C=12, D=13, E=14, F=15)
- Used in: MAC addresses, IPv6 addresses
- Example: `0xCA` = 12×16 + 10 = **202**

### MAC Address Format
- 48 bits (6 bytes)
- Format: `AA:BB:CC:DD:EE:FF` or `AA-BB-CC-DD-EE-FF` or `AABB.CCDD.EEFF`
- First 24 bits: OUI (Organizationally Unique Identifier) - vendor
- Last 24 bits: Device identifier

---

## Network Types

| Type | Description | Example |
|------|-------------|---------|
| **LAN** | Local Area Network | Single building/campus |
| **WAN** | Wide Area Network | Multiple locations, internet |
| **MAN** | Metropolitan Area Network | City-wide |
| **PAN** | Personal Area Network | Bluetooth devices |
| **WLAN** | Wireless LAN | Wi-Fi network |
| **SAN** | Storage Area Network | Fiber Channel storage |
| **CAN** | Campus Area Network | University campus |

---

## Data Flow Types

- **Unicast**: One-to-one (single source to single destination)
- **Broadcast**: One-to-all (single source to all devices)
- **Multicast**: One-to-many (single source to selected group)

---

## Encapsulation Process

```
Application Layer: DATA
Transport Layer: TCP/UDP Header + DATA = SEGMENT
Network Layer: IP Header + SEGMENT = PACKET
Data Link Layer: Frame Header + PACKET + Frame Trailer = FRAME
Physical Layer: BITS
```

### Frame Components
- **Preamble**: 7 bytes synchronization
- **SFD**: Start Frame Delimiter (1 byte)
- **Destination MAC**: 6 bytes
- **Source MAC**: 6 bytes
- **Type/Length**: 2 bytes (EtherType or length)
- **Data/Payload**: 46-1500 bytes
- **FCS**: Frame Check Sequence (4 bytes, CRC)

---

## Important Concepts

### Bandwidth vs Throughput vs Latency
- **Bandwidth**: Maximum theoretical data rate (e.g., 1 Gbps link)
- **Throughput**: Actual measured data rate
- **Latency**: Delay in transmission (measured in ms)
- **Jitter**: Variation in latency

### MTU (Maximum Transmission Unit)
- Maximum frame size that can be transmitted
- Ethernet default: 1500 bytes (payload)
- Jumbo frames: Up to 9000 bytes

### PoE (Power over Ethernet)
| Standard | Power | Pairs Used |
|----------|-------|------------|
| 802.3af | 15.4W | 2 |
| 802.3at (PoE+) | 30W | 2 |
| 802.3bt (PoE++) | 60-100W | 4 |

---

## Key IOS Commands

```cisco
! Show interface status
show interfaces status
show interfaces [interface]
show ip interface brief

! Configure interface
interface GigabitEthernet0/1
  description Link to Server
  speed 1000
  duplex full
  no shutdown

! Verify connectivity
ping [ip-address]
traceroute [ip-address]
```
