# IPv4 Addressing and Subnetting

## IPv4 Address Structure

- **32 bits** total (4 octets of 8 bits each)
- Format: `X.X.X.X` where X = 0-255
- Example: `192.168.1.100`

```
Binary:    11000000.10101000.00000001.01100100
Decimal:   192     .168     .1       .100
```

---

## Address Classes (Classful - Historical)

| Class | First Octet | Range | Default Mask | Networks | Hosts |
|-------|-------------|-------|--------------|----------|-------|
| **A** | 1-126 | 1.0.0.0 - 126.255.255.255 | /8 (255.0.0.0) | 126 | 16,777,214 |
| **B** | 128-191 | 128.0.0.0 - 191.255.255.255 | /16 (255.255.0.0) | 16,384 | 65,534 |
| **C** | 192-223 | 192.0.0.0 - 223.255.255.255 | /24 (255.255.255.0) | 2,097,152 | 254 |
| **D** | 224-239 | 224.0.0.0 - 239.255.255.255 | Multicast | - | - |
| **E** | 240-255 | 240.0.0.0 - 255.255.255.255 | Experimental | - | - |

> **Note**: 127.0.0.0 - 127.255.255.255 is reserved for loopback

---

## Private IP Address Ranges (RFC 1918)

| Class | Range | CIDR | Addresses |
|-------|-------|------|-----------|
| A | 10.0.0.0 - 10.255.255.255 | 10.0.0.0/8 | 16,777,216 |
| B | 172.16.0.0 - 172.31.255.255 | 172.16.0.0/12 | 1,048,576 |
| C | 192.168.0.0 - 192.168.255.255 | 192.168.0.0/16 | 65,536 |

### Other Special Addresses

| Address/Range | Purpose |
|---------------|---------|
| 0.0.0.0/8 | Current network |
| 127.0.0.0/8 | Loopback |
| 169.254.0.0/16 | Link-local (APIPA) |
| 224.0.0.0/4 | Multicast |
| 255.255.255.255 | Broadcast |

---

## Subnet Mask

Identifies network vs host portion of IP address.

### CIDR Notation

| CIDR | Subnet Mask | Binary | Hosts |
|------|-------------|--------|-------|
| /8 | 255.0.0.0 | 11111111.00000000.00000000.00000000 | 16,777,214 |
| /16 | 255.255.0.0 | 11111111.11111111.00000000.00000000 | 65,534 |
| /24 | 255.255.255.0 | 11111111.11111111.11111111.00000000 | 254 |
| /25 | 255.255.255.128 | 11111111.11111111.11111111.10000000 | 126 |
| /26 | 255.255.255.192 | 11111111.11111111.11111111.11000000 | 62 |
| /27 | 255.255.255.224 | 11111111.11111111.11111111.11100000 | 30 |
| /28 | 255.255.255.240 | 11111111.11111111.11111111.11110000 | 14 |
| /29 | 255.255.255.248 | 11111111.11111111.11111111.11111000 | 6 |
| /30 | 255.255.255.252 | 11111111.11111111.11111111.11111100 | 2 |
| /31 | 255.255.255.254 | 11111111.11111111.11111111.11111110 | 2 (P2P) |
| /32 | 255.255.255.255 | 11111111.11111111.11111111.11111111 | 1 (host) |

---

## Subnetting Formulas

```
Subnets = 2^n         (n = borrowed bits)
Hosts = 2^h - 2       (h = host bits, minus network & broadcast)
Block Size = 256 - subnet mask octet value
```

### Quick Reference Table

| CIDR | Mask | Block | Subnets | Hosts |
|------|------|-------|---------|-------|
| /24 | 255.255.255.0 | 256 | 1 | 254 |
| /25 | 255.255.255.128 | 128 | 2 | 126 |
| /26 | 255.255.255.192 | 64 | 4 | 62 |
| /27 | 255.255.255.224 | 32 | 8 | 30 |
| /28 | 255.255.255.240 | 16 | 16 | 14 |
| /29 | 255.255.255.248 | 8 | 32 | 6 |
| /30 | 255.255.255.252 | 4 | 64 | 2 |

---

## Subnetting Steps

### Method 1: Magic Number/Block Size

1. Identify subnet mask value: `256 - mask value = block size`
2. Start at 0 and increment by block size
3. Find which block the IP falls in
4. Network = start of block, Broadcast = end of block - 1

**Example**: 192.168.1.140/26

1. Mask = 255.255.255.192, block = 256-192 = 64
2. Subnets: 0, 64, 128, 192
3. 140 falls in 128-191 block
4. Network: 192.168.1.128, Broadcast: 192.168.1.191
5. Usable: 192.168.1.129 - 192.168.1.190

### Method 2: Binary

1. Convert IP and mask to binary
2. AND them together to get network address
3. All host bits = 0 → Network address
4. All host bits = 1 → Broadcast address

---

## Subnetting Practice Examples

### Example 1: 10.0.0.0/8, need 500 hosts per subnet

```
Hosts needed: 500
2^9 = 512 (≥ 500+2)
Host bits: 9
Subnet bits: 32 - 8 - 9 = 15
New mask: /23 (255.255.254.0)
Hosts per subnet: 510
```

### Example 2: 172.16.0.0/16, need 50 subnets

```
Subnets needed: 50
2^6 = 64 (≥ 50)
Subnet bits: 6
New mask: /22 (255.255.252.0)
Subnets: 64
Hosts per subnet: 1022
```

### Example 3: What subnet is 192.168.10.75/28?

```
/28 = 255.255.255.240
Block size = 256 - 240 = 16
Subnets: 0, 16, 32, 48, 64, 80...
75 falls between 64 and 80
Network: 192.168.10.64
Broadcast: 192.168.10.79
Usable: 192.168.10.65 - 192.168.10.78
```

---

## VLSM (Variable Length Subnet Masking)

Allows different subnet sizes within the same network.

### VLSM Steps
1. List requirements from largest to smallest
2. Assign subnets starting with largest
3. Use next available address block for each

### VLSM Example

Network: 192.168.1.0/24
Requirements:
- Network A: 100 hosts
- Network B: 50 hosts
- Network C: 25 hosts
- WAN links: 2 hosts each (3 links)

**Solution:**
```
Network A: 192.168.1.0/25    (126 hosts, .1-.126)
Network B: 192.168.1.128/26  (62 hosts, .129-.190)
Network C: 192.168.1.192/27  (30 hosts, .193-.222)
WAN 1:     192.168.1.224/30  (2 hosts, .225-.226)
WAN 2:     192.168.1.228/30  (2 hosts, .229-.230)
WAN 3:     192.168.1.232/30  (2 hosts, .233-.234)
```

---

## Address Types

For any subnet:
- **Network Address**: All host bits = 0 (first address)
- **Broadcast Address**: All host bits = 1 (last address)
- **Usable Range**: Everything between network and broadcast
- **Default Gateway**: Usually first or last usable address

---

## Binary Conversion Chart

| Bit Position | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
|--------------|---|---|---|---|---|---|---|---|
| **Value** | 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |

### Common Conversions

| Decimal | Binary |
|---------|--------|
| 0 | 00000000 |
| 128 | 10000000 |
| 192 | 11000000 |
| 224 | 11100000 |
| 240 | 11110000 |
| 248 | 11111000 |
| 252 | 11111100 |
| 254 | 11111110 |
| 255 | 11111111 |

---

## IPv4 Configuration

### Router Interface
```cisco
interface GigabitEthernet0/0
  ip address 192.168.1.1 255.255.255.0
  no shutdown

! Secondary address
interface GigabitEthernet0/0
  ip address 192.168.2.1 255.255.255.0 secondary
```

### Switch SVI
```cisco
interface vlan 10
  ip address 192.168.10.1 255.255.255.0
  no shutdown
  
ip default-gateway 192.168.1.1
```

### DHCP Configuration
```cisco
! Exclude addresses (for static assignments)
ip dhcp excluded-address 192.168.1.1 192.168.1.10

! Create DHCP pool
ip dhcp pool LAN
  network 192.168.1.0 255.255.255.0
  default-router 192.168.1.1
  dns-server 8.8.8.8 8.8.4.4
  lease 7

! Verify
show ip dhcp binding
show ip dhcp pool
```

---

## Verification Commands

```cisco
! Interface IP info
show ip interface brief
show ip interface GigabitEthernet0/0

! Routing table
show ip route

! ARP table
show ip arp

! DHCP bindings
show ip dhcp binding
```

---

## Subnetting Cheat Sheet

### Powers of 2
| 2^n | Value |
|-----|-------|
| 2^1 | 2 |
| 2^2 | 4 |
| 2^3 | 8 |
| 2^4 | 16 |
| 2^5 | 32 |
| 2^6 | 64 |
| 2^7 | 128 |
| 2^8 | 256 |
| 2^9 | 512 |
| 2^10 | 1024 |

### Quick Subnet Lookup (/24 base)

| Need Hosts | Use Mask | Block |
|------------|----------|-------|
| 2 | /30 | 4 |
| 6 | /29 | 8 |
| 14 | /28 | 16 |
| 30 | /27 | 32 |
| 62 | /26 | 64 |
| 126 | /25 | 128 |
| 254 | /24 | 256 |

---

## Troubleshooting IP Configuration

### Common Issues
| Problem | Cause | Solution |
|---------|-------|----------|
| No connectivity | Wrong mask | Verify subnet mask |
| Can't reach gateway | Different subnet | Check IP/mask combination |
| Duplicate IP | DHCP conflict | Check for static/DHCP overlap |
| Wrong subnet | Miscalculation | Recalculate and reconfigure |

### Troubleshooting Steps
1. `ping` default gateway
2. Check `show ip interface brief`
3. Verify subnet mask matches other devices
4. Check ARP table: `show ip arp`
5. Trace route: `traceroute [destination]`
