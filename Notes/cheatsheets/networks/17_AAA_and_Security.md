# AAA and Network Security

## AAA Overview

| Component | Purpose | Example |
|-----------|---------|---------|
| **Authentication** | Who are you? | Username/password, certificate |
| **Authorization** | What can you do? | Privilege levels, commands |
| **Accounting** | What did you do? | Logging, billing |

---

## Authentication Protocols

### RADIUS vs TACACS+

| Feature | RADIUS | TACACS+ |
|---------|--------|---------|
| **Developer** | IETF (open) | Cisco |
| **Transport** | UDP 1812/1813 | TCP 49 |
| **Encryption** | Password only | Entire payload |
| **AAA** | Combined | Separate (flexible) |
| **Use Case** | Network access (802.1X, VPN) | Device admin |

---

## AAA Configuration

### Enable AAA
```cisco
aaa new-model
```

### Local Authentication
```cisco
! Create local users
username admin privilege 15 secret AdminPass123
username operator privilege 5 secret OperPass123

! AAA authentication using local database
aaa authentication login default local
aaa authentication login CONSOLE local
aaa authentication login VTY-AUTH local

! Apply to lines
line console 0
  login authentication CONSOLE

line vty 0 15
  login authentication VTY-AUTH
```

### RADIUS Configuration
```cisco
! Define RADIUS server
radius server RAD-SERVER1
  address ipv4 192.168.1.100 auth-port 1812 acct-port 1813
  key RadiusSecret123

! Create server group
aaa group server radius RADIUS-GROUP
  server name RAD-SERVER1

! Use RADIUS with local fallback
aaa authentication login default group RADIUS-GROUP local

! Accounting
aaa accounting exec default start-stop group RADIUS-GROUP
```

### TACACS+ Configuration
```cisco
! Define TACACS+ server
tacacs server TAC-SERVER1
  address ipv4 192.168.1.101
  key TacacsSecret123

! Create server group
aaa group server tacacs+ TACACS-GROUP
  server name TAC-SERVER1

! Authentication
aaa authentication login default group TACACS-GROUP local

! Authorization
aaa authorization exec default group TACACS-GROUP local
aaa authorization commands 15 default group TACACS-GROUP local

! Accounting
aaa accounting exec default start-stop group TACACS-GROUP
aaa accounting commands 15 default start-stop group TACACS-GROUP
```

---

## 802.1X Port-Based Authentication

### Components
- **Supplicant**: Client software
- **Authenticator**: Switch (NAS)
- **Authentication Server**: RADIUS

### 802.1X Configuration
```cisco
! Enable AAA
aaa new-model
aaa authentication dot1x default group radius
aaa authorization network default group radius

! Define RADIUS server
radius server RAD-SERVER1
  address ipv4 192.168.1.100
  key RadiusKey123

! Enable 802.1X globally
dot1x system-auth-control

! Configure interface
interface GigabitEthernet0/1
  switchport mode access
  switchport access vlan 10
  authentication port-control auto
  dot1x pae authenticator
  authentication host-mode single-host
```

### 802.1X Options
```cisco
interface GigabitEthernet0/1
  ! Host modes
  authentication host-mode single-host         ! One client
  authentication host-mode multi-host          ! Multiple clients, one auth
  authentication host-mode multi-auth          ! Each client authenticates
  authentication host-mode multi-domain        ! Voice + data

  ! Guest VLAN (no 802.1X client)
  authentication event no-response action authorize vlan 100

  ! Auth-fail VLAN
  authentication event fail action authorize vlan 200

  ! Re-authentication
  authentication periodic
  authentication timer reauthenticate 3600

  ! MAB fallback (for devices without 802.1X)
  mab
```

### Verification
```cisco
show dot1x all
show dot1x interface Gi0/1
show authentication sessions
show authentication sessions interface Gi0/1
```

---

## Password Security

### Password Types

| Type | Description | Security |
|------|-------------|----------|
| **Type 0** | Plaintext | None |
| **Type 5** | MD5 hash | Moderate |
| **Type 7** | Vigenère cipher | Weak (reversible) |
| **Type 8** | PBKDF2-SHA256 | Strong |
| **Type 9** | Scrypt | Strong |

### Best Practices
```cisco
! Use secret (Type 5+) not password
enable secret MyEnableSecret
username admin secret MySecret

! Encrypt all passwords in config
service password-encryption

! Minimum password length
security passwords min-length 12

! Password management
! Use type 9 (if supported)
enable algorithm-type scrypt secret MySecret
username admin algorithm-type scrypt secret MySecret
```

---

## SSH Configuration

```cisco
! Prerequisites
hostname Router1
ip domain-name example.com

! Generate RSA keys
crypto key generate rsa modulus 2048

! SSH version 2
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3

! Create local user
username admin privilege 15 secret AdminPass123

! Configure VTY
line vty 0 15
  transport input ssh
  login local
  exec-timeout 5 0

! Verify
show ip ssh
show ssh
```

---

## VPN Fundamentals

### VPN Types

| Type | Description | Use Case |
|------|-------------|----------|
| **Site-to-Site** | Connects networks | Branch offices |
| **Remote Access** | Individual clients | Remote workers |
| **DMVPN** | Dynamic mesh | Multiple sites |
| **SSL VPN** | Browser-based | Clientless access |

### IPsec Phases

| Phase | Purpose | Protocols |
|-------|---------|-----------|
| **Phase 1 (IKE)** | Authenticate peers, establish secure channel | IKEv1, IKEv2 |
| **Phase 2 (IPsec)** | Negotiate encryption for data | ESP, AH |

### IPsec Protocols

| Protocol | Function | Header |
|----------|----------|--------|
| **ESP** | Encrypts + authenticates payload | Protocol 50 |
| **AH** | Authenticates only (no encryption) | Protocol 51 |
| **IKE** | Key exchange | UDP 500 |
| **NAT-T** | NAT traversal | UDP 4500 |

### Site-to-Site VPN Configuration (Basic)
```cisco
! Phase 1 (ISAKMP Policy)
crypto isakmp policy 10
  encryption aes 256
  hash sha256
  authentication pre-share
  group 14
  lifetime 86400

! Pre-shared key
crypto isakmp key MyPSK123 address 203.0.113.2

! Phase 2 (IPsec Transform Set)
crypto ipsec transform-set MYSET esp-aes 256 esp-sha256-hmac
  mode tunnel

! ACL for interesting traffic
access-list 100 permit ip 192.168.1.0 0.0.0.255 192.168.2.0 0.0.0.255

! Crypto map
crypto map MYMAP 10 ipsec-isakmp
  set peer 203.0.113.2
  set transform-set MYSET
  match address 100

! Apply to interface
interface GigabitEthernet0/0
  crypto map MYMAP
```

### Verification
```cisco
show crypto isakmp sa
show crypto ipsec sa
show crypto map
```

---

## Security Zones and Concepts

### Defense in Depth
Multiple layers of security:
1. Physical security
2. Network perimeter (firewall)
3. Network segmentation (VLANs)
4. Host security (endpoint protection)
5. Application security
6. Data protection

### Firewall Types

| Type | Layer | Description |
|------|-------|-------------|
| **Packet Filter** | 3-4 | ACL-based |
| **Stateful** | 3-4 | Tracks connections |
| **Application** | 7 | Deep inspection |
| **NGFW** | 3-7 | Combined, IPS, URL filtering |

### IDS vs IPS

| Feature | IDS | IPS |
|---------|-----|-----|
| **Position** | Out of band | Inline |
| **Action** | Alert only | Block + alert |
| **Impact** | No latency | Some latency |
| **Failure** | Network continues | Bypass or block |

---

## Common Security Threats

| Threat | Description | Mitigation |
|--------|-------------|------------|
| **DoS/DDoS** | Overwhelm resources | Rate limiting, scrubbing |
| **MITM** | Intercept communications | Encryption, certificates |
| **Phishing** | Social engineering | User training |
| **Malware** | Viruses, ransomware | Endpoint protection |
| **SQL Injection** | Database attacks | Input validation |
| **XSS** | Browser script injection | Input sanitization |

---

## Security Best Practices

1. **Use AAA** for all device access
2. **Implement TACACS+** for admin access
3. **Use RADIUS** for network access (802.1X)
4. **SSH only**, disable Telnet
5. **Strong passwords** with complexity
6. **Encrypt sensitive data** in transit
7. **Segment networks** with VLANs
8. **Regular patching** and updates
9. **Monitor and log** all access
10. **Least privilege** principle

---

## Verification Commands

```cisco
! AAA
show aaa servers
show aaa sessions

! 802.1X
show dot1x all
show authentication sessions

! SSH
show ip ssh
show ssh

! VPN
show crypto isakmp sa
show crypto ipsec sa

! Logging
show logging
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Enable AAA | `aaa new-model` |
| Local auth | `aaa authentication login default local` |
| RADIUS server | `radius server [name]` |
| TACACS+ server | `tacacs server [name]` |
| 802.1X enable | `dot1x system-auth-control` |
| 802.1X interface | `authentication port-control auto` |
| Generate SSH keys | `crypto key generate rsa modulus 2048` |
| SSH version 2 | `ip ssh version 2` |
| Encrypt passwords | `service password-encryption` |
