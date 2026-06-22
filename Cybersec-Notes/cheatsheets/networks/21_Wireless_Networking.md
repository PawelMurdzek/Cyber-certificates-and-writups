# Wireless Networking

## WLAN Architecture Types

### Autonomous AP
- Standalone operation
- Each AP configured individually
- No central management
- Suitable for very small deployments

### Lightweight AP (Controller-Based)
- Central WLC (Wireless LAN Controller)
- APs are "dumb" - controller handles intelligence
- CAPWAP tunnel to controller
- Scalable, enterprise-grade

### Cloud-Managed (e.g., Meraki)
- Central cloud management
- APs connect to cloud
- Simplified deployment
- Subscription-based

---

## CAPWAP (Control and Provisioning of Wireless Access Points)

- **Protocol**: UDP ports 5246 (control), 5247 (data)
- **Tunnel**: Between AP and WLC
- **Functions**: AP discovery, configuration, management

### AP States (Join Process)
```
1. AP boots → 2. Discover WLC → 3. Join WLC → 4. Download config → 5. Run
```

### WLC Discovery Methods
1. **DHCP Option 43**: Vendor-specific WLC IP
2. **DNS**: Resolve `CISCO-CAPWAP-CONTROLLER.domain`
3. **Broadcast**: Local network
4. **Static**: Manually configured
5. **Previously learned**: Stored in memory

---

## Wireless Standards (802.11)

| Standard | Band | Max Speed | Channel Width | Technology |
|----------|------|-----------|---------------|------------|
| 802.11b | 2.4 GHz | 11 Mbps | 22 MHz | DSSS |
| 802.11a | 5 GHz | 54 Mbps | 20 MHz | OFDM |
| 802.11g | 2.4 GHz | 54 Mbps | 20 MHz | OFDM |
| 802.11n (Wi-Fi 4) | 2.4/5 GHz | 600 Mbps | 20/40 MHz | MIMO |
| 802.11ac (Wi-Fi 5) | 5 GHz | 6.9 Gbps | 20-160 MHz | MU-MIMO |
| 802.11ax (Wi-Fi 6) | 2.4/5/6 GHz | 9.6 Gbps | 20-160 MHz | OFDMA |

---

## Frequency Bands

### 2.4 GHz Band
- **Channels**: 1-14 (varies by country)
- **Non-overlapping**: 1, 6, 11 (in US)
- **Pros**: Better range, wall penetration
- **Cons**: More interference, fewer channels

### 5 GHz Band
- **Channels**: Many (36-165+)
- **Non-overlapping**: Many more options
- **Pros**: Less interference, more bandwidth
- **Cons**: Shorter range, less penetration

### 6 GHz Band (Wi-Fi 6E)
- **Channels**: 1200 MHz of spectrum
- **New**: Clean, no legacy devices
- **Requires**: Wi-Fi 6 devices

---

## Channel Bonding

| Width | Channels Combined | Use Case |
|-------|-------------------|----------|
| 20 MHz | 1 | Congested areas |
| 40 MHz | 2 | Moderate density |
| 80 MHz | 4 | High throughput |
| 160 MHz | 8 | Very high throughput |

---

## Wireless Components

### Access Point (AP)
- Provides wireless access
- Connects to wired network
- May be autonomous or lightweight

### Wireless LAN Controller (WLC)
- Manages multiple APs
- Centralizes configuration
- Handles roaming, security

### Antenna Types

| Type | Pattern | Use Case |
|------|---------|----------|
| **Omnidirectional** | 360° horizontal | General coverage |
| **Directional** | Focused beam | Point-to-point, specific areas |
| **Sector** | Pie slice | Outdoor, high-density |

---

## WLC Configuration

### WLAN Configuration
```
# Create WLAN
config wlan create [wlan-id] [profile-name] [ssid]
config wlan enable [wlan-id]

# Security
config wlan security wpa akm 802.1x enable [wlan-id]
config wlan security wpa wpa2 ciphers aes enable [wlan-id]

# VLAN mapping
config wlan interface [wlan-id] [interface-name]
```

### Interface Configuration
```
# Create dynamic interface
config interface create [name] [vlan-id]
config interface address dynamic-interface [name] [ip] [mask] [gateway]
config interface dhcp dynamic-interface [name] primary [dhcp-server]
```

---

## Roaming

### Layer 2 Roaming
- Same VLAN/subnet
- Fast handoff
- No IP change needed

### Layer 3 Roaming
- Different subnet
- May require mobility tunnel
- Complex, slower

### Fast Roaming Methods

| Method | Description |
|--------|-------------|
| **802.11r (FT)** | Fast BSS Transition |
| **802.11k** | Radio Resource Management |
| **802.11v** | BSS Transition Management |
| **OKC** | Opportunistic Key Caching |
| **Cisco CCKM** | Centralized Key Management |

---

## RF Concepts

### RSSI (Received Signal Strength Indicator)
- Measured in dBm
- Higher (less negative) = better
- -30 dBm = excellent, -70 dBm = good, -80 dBm = weak

### SNR (Signal-to-Noise Ratio)
- Signal strength vs noise floor
- Higher = better
- 25+ dB = good, 20 dB = acceptable, < 15 dB = poor

### Interference Sources
- Microwave ovens (2.4 GHz)
- Bluetooth (2.4 GHz)
- Cordless phones
- Other APs on same channel

---

## WLAN Design Best Practices

### Channel Planning
- **2.4 GHz**: Use only 1, 6, 11
- **5 GHz**: Use non-overlapping channels
- **Co-channel interference**: APs on same channel hear each other
- **Adjacent channel interference**: Overlapping frequencies

### Power Levels
- Lower power = smaller cell = more APs = better density
- Higher power = larger cell = fewer APs = more interference

### AP Placement
- 20-30% overlap for roaming
- Consider walls, obstacles
- High-density: more APs, lower power
- Survey before deployment

---

## Wireless Verification

```cisco
# Show WLC status
show sysinfo

# Show APs
show ap summary
show ap config general [ap-name]

# Show WLANs
show wlan summary
show wlan [wlan-id]

# Show clients
show client summary
show client detail [mac-address]

# Show RF information
show ap auto-rf 802.11a [ap-name]
show ap auto-rf 802.11b [ap-name]
```

---

## Troubleshooting Wireless

### Common Issues

| Issue | Possible Cause | Solution |
|-------|----------------|----------|
| Can't see SSID | Wrong band/channel | Check AP config |
| Can't connect | Security mismatch | Verify settings |
| Slow speeds | Interference | Channel survey |
| Dropped connections | Coverage gap | Add APs |
| Roaming issues | PMK caching | Enable fast roaming |

### Troubleshooting Steps
1. Verify AP is joined to WLC
2. Check WLAN is enabled
3. Verify security settings
4. Check VLAN/interface mapping
5. Verify DHCP on VLAN
6. Check for RF interference
7. Monitor client status on WLC

---

## Quick Reference

| Term | Description |
|------|-------------|
| SSID | Network name |
| BSSID | AP MAC address |
| BSS | Basic Service Set (one AP) |
| ESS | Extended Service Set (multiple APs) |
| CAPWAP | AP-to-WLC protocol |
| RSSI | Signal strength |
| SNR | Signal quality |
| DFS | Dynamic Frequency Selection |
| TPC | Transmit Power Control |
| RRM | Radio Resource Management |
