# Wireless Security

## Wireless Security Evolution

| Protocol | Year | Encryption | Status |
|----------|------|------------|--------|
| **WEP** | 1999 | RC4 (weak) | Deprecated, cracked |
| **WPA** | 2003 | TKIP | Legacy, weak |
| **WPA2** | 2004 | AES-CCMP | Current standard |
| **WPA3** | 2018 | AES-GCMP, SAE | Latest, recommended |

---

## WPA2 Security

### WPA2 Modes

| Mode | Authentication | Use Case |
|------|----------------|----------|
| **WPA2-Personal (PSK)** | Pre-shared key | Home, small office |
| **WPA2-Enterprise** | 802.1X/RADIUS | Corporate |

### WPA2-Personal
- Shared password (PSK)
- Key derived from passphrase + SSID
- Same key for all users
- **Weakness**: Key sharing, offline attack possible

### WPA2-Enterprise (802.1X)
- Individual credentials per user
- RADIUS authentication
- Dynamic per-session keys
- Supports certificates (EAP-TLS)

---

## EAP Methods

| Method | Credentials | Certificates | Security |
|--------|-------------|--------------|----------|
| **EAP-TLS** | Certificate | Server + Client | Highest |
| **PEAP** | Username/Password | Server only | High |
| **EAP-TTLS** | Username/Password | Server only | High |
| **EAP-FAST** | Username/Password | Optional | High |
| **LEAP** | Username/Password | None | Weak (deprecated) |

### Recommended: EAP-TLS or PEAP

---

## WPA3 Improvements

| Feature | Improvement |
|---------|-------------|
| **SAE** | Simultaneous Authentication of Equals (replaces PSK) |
| **Forward Secrecy** | Past traffic safe if key compromised |
| **192-bit Security** | Enterprise mode option |
| **Protected Management Frames** | Required |
| **Open Network Encryption** | OWE (Opportunistic Wireless Encryption) |

### WPA3-Personal
- SAE (Dragonfly handshake)
- Resistant to offline dictionary attacks
- Forward secrecy

### WPA3-Enterprise
- 192-bit minimum security suite
- CNSA (Commercial National Security Algorithm)

---

## Wireless Attacks and Mitigations

| Attack | Description | Mitigation |
|--------|-------------|------------|
| **Rogue AP** | Unauthorized access point | WIPS, rogue detection |
| **Evil Twin** | Fake AP mimicking legitimate | Certificate validation, WIPS |
| **Deauth Attack** | Force clients to disconnect | PMF (802.11w) |
| **WPS Attack** | Brute force WPS PIN | Disable WPS |
| **KRACK** | WPA2 key reinstallation | Patching, WPA3 |
| **Dictionary Attack** | Crack PSK offline | Strong passwords, WPA3-SAE |
| **Jamming** | RF interference | Spectrum analysis |

---

## Management Frame Protection (PMF)

IEEE 802.11w - protects management frames from spoofing.

| Frame Type | Without PMF | With PMF |
|------------|-------------|----------|
| Deauth | Spoofable | Protected |
| Disassoc | Spoofable | Protected |
| Action | Spoofable | Protected |

### PMF Options
- **Disabled**: No protection
- **Optional**: Support if client capable
- **Required**: Mandatory (recommended)

---

## Wireless Controller Security Configuration

### WPA2-Enterprise with RADIUS
```
# WLC Configuration (CLI example)
config wlan security wpa akm 802.1x enable [wlan-id]
config wlan security wpa wpa2 ciphers aes enable [wlan-id]
config wlan radius_server auth add [wlan-id] [radius-server-index]
```

### RADIUS Server Configuration
```cisco
! Router/WLC as RADIUS client
radius-server host 192.168.1.100 key RadiusSecret
aaa group server radius WIRELESS-RADIUS
  server 192.168.1.100

aaa authentication dot1x default group WIRELESS-RADIUS
```

---

## Wireless Best Practices

### Authentication
1. **Use WPA3** where possible
2. **WPA2-Enterprise** for corporate
3. **Strong PSK** if WPA2-Personal (20+ chars)
4. **Disable WEP and WPA**
5. **Disable WPS**

### Network Protection
1. **Enable PMF** (802.11w)
2. **Use WIPS/WIDS** for rogue detection
3. **Segment wireless** from wired (VLAN)
4. **Use separate SSIDs** for guest/corporate
5. **MAC filtering** (supplementary only)

### Encryption
1. **AES-CCMP** minimum (WPA2)
2. **AES-GCMP** preferred (WPA3)
3. **Disable TKIP**

### Infrastructure
1. **Secure controller** management
2. **Use HTTPS** for management
3. **Regular firmware updates**
4. **Audit configurations**
5. **Monitor for rogue APs**

---

## Guest Wireless Security

```
Recommendations:
- Separate VLAN/network
- Internet access only
- Captive portal authentication
- Rate limiting
- Time-limited access
- Client isolation (AP isolation)
- No access to internal resources
```

---

## WLAN Security Checklist

- [ ] WPA2-Enterprise or WPA3
- [ ] Strong RADIUS server configuration
- [ ] PMF enabled (optional or required)
- [ ] SSID broadcast: consider hiding for sensitive networks
- [ ] Guest network isolated
- [ ] Rogue AP detection enabled
- [ ] Regular security audits
- [ ] Firmware updated
- [ ] Logging enabled
- [ ] WPS disabled

---

## Wireless Security Models

### Open System
- No authentication
- No encryption (or OWE in WPA3)
- Guest networks, hotspots

### Personal (PSK)
- Shared password
- Home, small office
- All users have same key

### Enterprise (802.1X)
- Individual authentication
- RADIUS integration
- Per-user/per-session keys
- Certificate support

---

## Quick Reference

| Security Level | Recommended Settings |
|----------------|---------------------|
| **Minimum** | WPA2-PSK (AES) + strong password |
| **Standard** | WPA2-Enterprise (PEAP) |
| **High** | WPA2-Enterprise (EAP-TLS) + PMF |
| **Maximum** | WPA3-Enterprise (192-bit) + EAP-TLS |

---

## Troubleshooting Wireless Security

| Issue | Possible Cause | Solution |
|-------|----------------|----------|
| Can't connect | Wrong password | Verify PSK |
| Can't connect | Certificate issue | Check cert validity |
| Frequent disconnects | Deauth attack | Enable PMF |
| Slow speeds | Interference | Channel analysis |
| Auth failures | RADIUS unreachable | Check RADIUS config |
