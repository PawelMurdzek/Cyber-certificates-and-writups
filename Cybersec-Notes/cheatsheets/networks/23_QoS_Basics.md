# QoS (Quality of Service) Basics

## Why QoS?

Without QoS, all traffic is treated equally (best-effort). QoS is needed when:
- **Bandwidth is limited**
- **Real-time traffic** exists (voice, video)
- **Mission-critical apps** need priority
- **Congestion** occurs

---

## QoS Models

| Model | Description | Scalability |
|-------|-------------|-------------|
| **Best Effort** | No QoS, FIFO | Unlimited |
| **IntServ** | Per-flow reservation (RSVP) | Limited |
| **DiffServ** | Class-based marking | Highly scalable |

> **CCNA Focus**: DiffServ (most common)

---

## QoS Actions

| Action | Description |
|--------|-------------|
| **Classification** | Identify traffic type |
| **Marking** | Set QoS field values |
| **Policing** | Drop or mark excess traffic |
| **Shaping** | Buffer and delay excess traffic |
| **Queuing** | Order packets for transmission |
| **Congestion Avoidance** | Drop before queue fills |

---

## Marking Fields

### Layer 2 - CoS (Class of Service)
- **Location**: 802.1Q VLAN tag
- **Bits**: 3 bits (0-7)
- **Only on trunks**

### Layer 3 - IP Precedence / DSCP

| Field | Bits | Values | Location |
|-------|------|--------|----------|
| **IP Precedence** | 3 | 0-7 | ToS byte (legacy) |
| **DSCP** | 6 | 0-63 | ToS byte (current) |
| **ECN** | 2 | 0-3 | ToS byte |

### DSCP Values - Per-Hop Behaviors (PHB)

| PHB | DSCP Name | DSCP Value | Drop Probability |
|-----|-----------|------------|------------------|
| **Default** | BE | 0 | Best effort |
| **EF** | EF | 46 | Low latency (voice) |
| **AF Class 1** | AF11/AF12/AF13 | 10/12/14 | Low/Med/High |
| **AF Class 2** | AF21/AF22/AF23 | 18/20/22 | Low/Med/High |
| **AF Class 3** | AF31/AF32/AF33 | 26/28/30 | Low/Med/High |
| **AF Class 4** | AF41/AF42/AF43 | 34/36/38 | Low/Med/High |
| **CS (Class Selector)** | CS0-CS7 | 0,8,16,24,32,40,48,56 | Backward compatible |

### DSCP to IP Precedence

| DSCP | IP Prec | Use |
|------|---------|-----|
| 0-7 | 0 | Best effort |
| 8-15 | 1 | Priority |
| 16-23 | 2 | Immediate |
| 24-31 | 3 | Flash |
| 32-39 | 4 | Flash Override |
| 40-47 | 5 | Critical (voice) |
| 48-55 | 6 | Internetwork Control |
| 56-63 | 7 | Network Control |

---

## Trust Boundaries

Where to trust/verify QoS markings:
- **Trust at access layer**: For IP phones, trusted endpoints
- **Remark at access layer**: For untrusted endpoints
- **Trust at distribution**: Aggregate traffic

```cisco
! Trust CoS from IP phone
interface GigabitEthernet0/1
  mls qos trust cos
  
! Trust DSCP
interface GigabitEthernet0/2
  mls qos trust dscp
```

---

## Classification and Marking

### Class Maps (Classification)
```cisco
! Match by DSCP
class-map match-all VOICE
  match dscp ef

! Match by ACL
class-map match-any WEB-TRAFFIC
  match access-group 101
  match protocol http

access-list 101 permit tcp any any eq 80
```

### Policy Maps (Marking/Actions)
```cisco
policy-map MARK-TRAFFIC
  class VOICE
    set dscp ef
  class WEB-TRAFFIC
    set dscp af31
  class class-default
    set dscp default
```

### Apply Policy
```cisco
interface GigabitEthernet0/1
  service-policy input MARK-TRAFFIC
```

---

## Policing and Shaping

### Policing
- **Drops or remarks** excess traffic
- **No buffering**
- Applied at ingress or egress

```cisco
policy-map POLICE-TRAFFIC
  class VOICE
    police 128000 8000 conform-action transmit exceed-action drop
```

### Shaping
- **Buffers** excess traffic
- **Smooths** bursts
- Applied at egress

```cisco
policy-map SHAPE-TRAFFIC
  class class-default
    shape average 1000000    ! 1 Mbps
```

---

## Queuing Mechanisms

| Mechanism | Description | Use Case |
|-----------|-------------|----------|
| **FIFO** | First In, First Out | Default, no QoS |
| **PQ** | Priority Queue | Legacy voice |
| **WFQ** | Weighted Fair Queue | Fair bandwidth |
| **CBWFQ** | Class-Based WFQ | Class-based bandwidth |
| **LLQ** | Low Latency Queue | Voice + guaranteed BW |

### LLQ Configuration
```cisco
policy-map LLQ-POLICY
  class VOICE
    priority 256                ! Strict priority, max 256 kbps
  class VIDEO
    bandwidth 1000              ! Guaranteed 1 Mbps
  class class-default
    fair-queue
```

---

## Congestion Avoidance

### WRED (Weighted Random Early Detection)
- Drops packets **before** queue fills
- Higher drop probability for lower priority
- Avoids tail drop

```cisco
policy-map WRED-POLICY
  class class-default
    random-detect
```

---

## QoS for Voice

### Voice Requirements
- **Bandwidth**: ~100 kbps per call
- **Latency**: < 150 ms one-way
- **Jitter**: < 30 ms
- **Packet loss**: < 1%

### Recommended Markings

| Traffic | DSCP | CoS |
|---------|------|-----|
| Voice bearer | EF (46) | 5 |
| Voice signaling | CS3 (24) or AF31 | 3 |
| Video | AF41 (34) | 4 |
| Interactive | AF21 (18) | 2 |
| Best effort | 0 | 0 |

---

## MQC (Modular QoS CLI)

Three-step process:
1. **Class Map**: Classify traffic
2. **Policy Map**: Define actions
3. **Service Policy**: Apply to interface

```cisco
! Step 1: Classification
class-map match-all VOICE
  match dscp ef

class-map match-any BULK
  match protocol ftp
  match protocol smtp

! Step 2: Policy
policy-map WAN-QOS
  class VOICE
    priority percent 20
  class BULK
    bandwidth percent 10
  class class-default
    bandwidth percent 70
    fair-queue

! Step 3: Apply
interface GigabitEthernet0/0
  service-policy output WAN-QOS
```

---

## Auto-QoS

Simplified voice QoS configuration.

```cisco
! Enable globally
mls qos

! On interface with IP phone
interface GigabitEthernet0/1
  auto qos voip cisco-phone

! Or trust DSCP
auto qos voip trust
```

---

## Verification

```cisco
show policy-map
show policy-map interface [interface]
show class-map
show mls qos interface [interface]
show auto qos
```

---

## QoS Best Practices

1. **Classify close to source**
2. **Mark at trust boundary**
3. **Use LLQ for voice** (strict priority)
4. **Limit priority traffic** to 33% of link
5. **Reserve bandwidth** for critical apps
6. **Monitor and tune** policies
7. **End-to-end** QoS required for effectiveness

---

## Quick Reference

| Task | Command/Value |
|------|---------------|
| Voice DSCP | EF (46) |
| Video DSCP | AF41 (34) |
| Signaling DSCP | CS3 (24) |
| Trust CoS | `mls qos trust cos` |
| Trust DSCP | `mls qos trust dscp` |
| Priority queue | `priority [kbps]` |
| Bandwidth guarantee | `bandwidth [kbps]` |
| Apply policy | `service-policy [in\|out] [name]` |
