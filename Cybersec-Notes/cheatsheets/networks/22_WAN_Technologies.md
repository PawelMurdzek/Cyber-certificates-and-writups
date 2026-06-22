# WAN Technologies

## WAN Overview

**WAN (Wide Area Network)** connects geographically dispersed networks.

### WAN Connection Types

| Type | Description | Speed | Cost |
|------|-------------|-------|------|
| **Leased Line** | Dedicated point-to-point | T1/E1 to OC-x | High |
| **Packet Switched** | Shared infrastructure | Variable | Medium |
| **Internet VPN** | Encrypted over public internet | Variable | Low |
| **MPLS** | Label-based forwarding | Variable | Medium |

---

## WAN Topologies

| Topology | Description | Use Case |
|----------|-------------|----------|
| **Point-to-Point** | Direct link between two sites | Simple connectivity |
| **Hub-and-Spoke** | Central hub, branch spokes | Centralized apps |
| **Full Mesh** | All sites connected | Maximum redundancy |
| **Partial Mesh** | Some direct connections | Balance cost/redundancy |

---

## VPN Technologies

### IPsec VPN

- **Site-to-Site**: Connect networks
- **Remote Access**: Individual clients
- **Encryption**: ESP (layer 3)
- **Authentication**: IKE

### GRE (Generic Routing Encapsulation)

- **Tunneling**: Encapsulates any protocol
- **No encryption**: Add IPsec for security
- **Use case**: Routing over internet

```cisco
interface Tunnel0
  ip address 10.0.0.1 255.255.255.252
  tunnel source GigabitEthernet0/0
  tunnel destination 203.0.113.2
  
! Add IPsec for encryption (GRE over IPsec)
```

### DMVPN (Dynamic Multipoint VPN)

- **Hub-and-spoke** with dynamic spoke-to-spoke
- **Components**: mGRE, NHRP, IPsec
- **Scalable**: Dynamic tunnel creation

### SSL/TLS VPN

- **Clientless**: Browser-based (port 443)
- **Full tunnel**: AnyConnect client
- **Advantage**: Works through firewalls

---

## MPLS (Multiprotocol Label Switching)

### MPLS Concepts

| Term | Description |
|------|-------------|
| **Label** | Short identifier, added to packet |
| **LSR** | Label Switch Router |
| **LER** | Label Edge Router |
| **LSP** | Label Switched Path |
| **FEC** | Forwarding Equivalence Class |

### MPLS Operation
```
            ┌─────┐      ┌─────┐      ┌─────┐
Packet ──>  │ LER │ ──>  │ LSR │ ──>  │ LER │ ──> Packet
            │Push │      │Swap │      │Pop  │
            │Label│      │Label│      │Label│
            └─────┘      └─────┘      └─────┘
```

### MPLS VPN Types

| Type | Layer | Description |
|------|-------|-------------|
| **L3VPN** | 3 | Routes between sites |
| **L2VPN (VPLS)** | 2 | Extends L2 domain |

---

## SD-WAN

### SD-WAN Benefits
- **Transport agnostic**: MPLS, internet, LTE
- **Centralized control**: Orchestration
- **Cost reduction**: Use cheaper links
- **Dynamic path selection**: Based on policy
- **Built-in security**: Encryption

### Cisco SD-WAN Components

| Component | Function |
|-----------|----------|
| **vManage** | Management, monitoring |
| **vBond** | Orchestration, authentication |
| **vSmart** | Policy, routing |
| **vEdge/WAN Edge** | Data plane |

---

## WAN Protocols

### PPP (Point-to-Point Protocol)

- **Layer 2**: Serial links
- **Authentication**: PAP, CHAP
- **Features**: Multilink, LCP, NCP

```cisco
interface Serial0/0
  encapsulation ppp
  ppp authentication chap
  ppp chap hostname Router1
  ppp chap password MyPassword
```

### HDLC (High-Level Data Link Control)

- **Cisco default** on serial
- **Simple**: No authentication
- **Proprietary**: Cisco version

```cisco
interface Serial0/0
  encapsulation hdlc
```

### PPPoE (PPP over Ethernet)

- **DSL connections**
- **Authentication**: ISP uses
- **Common**: Residential

```cisco
interface Dialer1
  encapsulation ppp
  ppp chap hostname user@isp.com
  ppp chap password MyPassword
  dialer pool 1
  ip address negotiated

interface GigabitEthernet0/0
  pppoe-client dial-pool-number 1
```

---

## WAN Link Types

### Leased Lines (TDM)

| Type | Speed | Notes |
|------|-------|-------|
| T1 | 1.544 Mbps | US, 24 DS0 channels |
| E1 | 2.048 Mbps | Europe, 32 channels |
| T3/DS3 | 44.736 Mbps | 28 T1s |
| OC-3 | 155 Mbps | SONET |
| OC-12 | 622 Mbps | SONET |

### Broadband

| Type | DL Speed | UL Speed | Medium |
|------|----------|----------|--------|
| **DSL** | 1-100 Mbps | 1-10 Mbps | Phone line |
| **Cable** | 10-1000 Mbps | 5-50 Mbps | Coax |
| **Fiber** | 100-10000 Mbps | 100-10000 Mbps | Fiber |
| **LTE/5G** | 10-1000 Mbps | 5-100 Mbps | Cellular |

---

## Metro Ethernet

| Service Type | Description | Layer |
|--------------|-------------|-------|
| **E-Line** | Point-to-point | 2 |
| **E-LAN** | Multipoint | 2 |
| **E-Tree** | Hub-and-spoke | 2 |

---

## Choosing WAN Technology

| Requirement | Recommendation |
|-------------|----------------|
| Low cost, moderate reliability | Internet VPN |
| High reliability, SLA | MPLS |
| Flexibility, multiple transports | SD-WAN |
| Dedicated bandwidth | Leased line |
| Remote workers | SSL VPN |

---

## Quick Reference

| Technology | Use Case |
|------------|----------|
| Leased Line | Dedicated, guaranteed bandwidth |
| MPLS | Enterprise WAN, QoS guaranteed |
| IPsec VPN | Secure site-to-site over internet |
| GRE | Tunnel any protocol |
| DMVPN | Scalable hub-and-spoke VPN |
| SD-WAN | Modern, flexible WAN |
| PPPoE | DSL/broadband authentication |
