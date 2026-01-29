# Network Automation and Programmability

## Why Network Automation?

- **Consistency**: Eliminate human errors
- **Speed**: Deploy changes faster
- **Scalability**: Manage many devices
- **Documentation**: Automatic change tracking
- **Compliance**: Enforce standards

---

## Automation Concepts

### Configuration Management
- **Desired State**: Define what config should be
- **Drift Detection**: Identify config changes
- **Remediation**: Restore desired state

### Infrastructure as Code (IaC)
- Configurations stored as code
- Version controlled (git)
- Testable and repeatable

---

## Data Formats

### JSON (JavaScript Object Notation)

```json
{
  "hostname": "Router1",
  "interfaces": [
    {
      "name": "GigabitEthernet0/0",
      "ip_address": "192.168.1.1",
      "subnet_mask": "255.255.255.0",
      "enabled": true
    },
    {
      "name": "GigabitEthernet0/1",
      "ip_address": "10.0.0.1",
      "subnet_mask": "255.255.255.0",
      "enabled": true
    }
  ]
}
```

**Key Points**:
- Curly braces `{}` for objects
- Square brackets `[]` for arrays
- Key-value pairs with colons
- Strings in double quotes
- No trailing commas

### YAML (Yet Another Markup Language)

```yaml
hostname: Router1
interfaces:
  - name: GigabitEthernet0/0
    ip_address: 192.168.1.1
    subnet_mask: 255.255.255.0
    enabled: true
  - name: GigabitEthernet0/1
    ip_address: 10.0.0.1
    subnet_mask: 255.255.255.0
    enabled: true
```

**Key Points**:
- Indentation-based (spaces, not tabs)
- Lists with dashes `-`
- No quotes needed for most strings
- More human-readable than JSON

### XML (eXtensible Markup Language)

```xml
<device>
  <hostname>Router1</hostname>
  <interfaces>
    <interface>
      <name>GigabitEthernet0/0</name>
      <ip_address>192.168.1.1</ip_address>
      <subnet_mask>255.255.255.0</subnet_mask>
      <enabled>true</enabled>
    </interface>
  </interfaces>
</device>
```

**Key Points**:
- Tag-based structure
- Opening and closing tags
- Attributes also possible
- More verbose than JSON/YAML

---

## REST APIs

### HTTP Methods

| Method | Action | CRUD |
|--------|--------|------|
| **GET** | Read data | Read |
| **POST** | Create new | Create |
| **PUT** | Replace/Update | Update |
| **PATCH** | Partial update | Update |
| **DELETE** | Remove | Delete |

### HTTP Response Codes

| Code | Meaning |
|------|---------|
| 200 | OK (success) |
| 201 | Created |
| 204 | No Content |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 500 | Internal Server Error |

### API Authentication
- **API Keys**: Token in header
- **Basic Auth**: Username:password (Base64)
- **OAuth**: Token-based, delegated auth
- **Certificate**: Mutual TLS

### REST API Example (Python)
```python
import requests

# GET request
url = "https://192.168.1.1/api/interfaces"
headers = {
    "Content-Type": "application/json",
    "X-Auth-Token": "your-api-key"
}

response = requests.get(url, headers=headers, verify=False)
data = response.json()
print(data)

# POST request (create)
new_vlan = {
    "vlan_id": 100,
    "name": "NewVLAN"
}
response = requests.post(url, json=new_vlan, headers=headers, verify=False)
```

---

## Configuration Management Tools

### Comparison

| Tool | Type | Language | Agentless |
|------|------|----------|-----------|
| **Ansible** | Push | YAML | Yes |
| **Puppet** | Pull | Ruby DSL | No |
| **Chef** | Pull | Ruby | No |
| **Salt** | Both | YAML/Python | Optional |
| **Terraform** | IaC | HCL | Yes |

### Ansible Basics

```yaml
# Playbook: configure_vlans.yml
---
- name: Configure VLANs on switches
  hosts: switches
  gather_facts: no
  
  tasks:
    - name: Create VLAN 100
      cisco.ios.ios_vlans:
        config:
          - vlan_id: 100
            name: Marketing
            state: active
        state: merged

    - name: Configure interface
      cisco.ios.ios_interfaces:
        config:
          - name: GigabitEthernet0/1
            description: Marketing LAN
            enabled: true
        state: merged
```

### Ansible Inventory
```yaml
# inventory.yml
all:
  children:
    switches:
      hosts:
        switch1:
          ansible_host: 192.168.1.1
          ansible_network_os: cisco.ios.ios
        switch2:
          ansible_host: 192.168.1.2
          ansible_network_os: cisco.ios.ios
      vars:
        ansible_user: admin
        ansible_password: secret
        ansible_connection: network_cli
```

---

## Software-Defined Networking (SDN)

### Traditional vs SDN

| Traditional | SDN |
|-------------|-----|
| Distributed control | Centralized control |
| Per-device management | Controller-based |
| CLI/SNMP configuration | API-driven |
| Vendor-specific | Open standards |

### SDN Planes

| Plane | Function | SDN Location |
|-------|----------|--------------|
| **Data/Forwarding** | Move packets | Network devices |
| **Control** | Routing decisions | SDN Controller |
| **Management** | Configuration | Orchestration |

### SDN Controllers
- **Cisco DNA Center**: Enterprise WAN/LAN
- **Cisco SD-WAN (vManage)**: WAN optimization
- **Cisco ACI (APIC)**: Data center
- **OpenDaylight**: Open source
- **VMware NSX**: Virtual networks

### Northbound vs Southbound APIs

```
     ┌─────────────────────┐
     │    Applications     │
     └──────────┬──────────┘
                │ Northbound API (REST)
     ┌──────────┴──────────┐
     │   SDN Controller    │
     └──────────┬──────────┘
                │ Southbound API (OpenFlow, NETCONF)
     ┌──────────┴──────────┐
     │   Network Devices   │
     └─────────────────────┘
```

---

## Cisco DNA Center

### DNA Center Features
- **Automation**: Template-based provisioning
- **Assurance**: AI-driven analytics
- **Policy**: Intent-based networking
- **Security**: Microsegmentation

### Intent-Based Networking
1. **Translate**: Business intent to network config
2. **Activate**: Deploy across network
3. **Assure**: Monitor and verify
4. **Remediate**: Auto-correct issues

---

## NETCONF and RESTCONF

### NETCONF (Network Configuration Protocol)
- **Transport**: SSH (port 830)
- **Data format**: XML
- **Operations**: Get-config, edit-config, copy-config
- **Uses YANG** data models

```xml
<!-- NETCONF get-config -->
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <get-config>
    <source>
      <running/>
    </source>
    <filter>
      <interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"/>
    </filter>
  </get-config>
</rpc>
```

### RESTCONF
- **Transport**: HTTPS
- **Data format**: JSON or XML
- **REST-like**: Uses HTTP methods
- **Uses YANG** data models

```
GET https://192.168.1.1/restconf/data/ietf-interfaces:interfaces
Content-Type: application/yang-data+json
```

---

## YANG Data Models

- **Defines structure** of configuration/operational data
- **Vendor-neutral** (IETF, OpenConfig)
- **Vendor-specific** (Cisco, Juniper)

```yang
module example-interface {
  namespace "http://example.com/interface";
  prefix if;

  container interfaces {
    list interface {
      key "name";
      leaf name { type string; }
      leaf ip-address { type string; }
      leaf enabled { type boolean; }
    }
  }
}
```

---

## Python for Network Automation

### Libraries

| Library | Purpose |
|---------|---------|
| **Netmiko** | SSH connections to devices |
| **Paramiko** | Low-level SSH |
| **NAPALM** | Multi-vendor abstraction |
| **Nornir** | Automation framework |
| **Requests** | REST API calls |
| **pyATS** | Testing framework |

### Netmiko Example
```python
from netmiko import ConnectHandler

device = {
    'device_type': 'cisco_ios',
    'host': '192.168.1.1',
    'username': 'admin',
    'password': 'secret',
}

connection = ConnectHandler(**device)
output = connection.send_command('show ip interface brief')
print(output)

# Configuration
config_commands = [
    'interface GigabitEthernet0/1',
    'description Configured by Python',
    'no shutdown'
]
connection.send_config_set(config_commands)
connection.disconnect()
```

---

## Best Practices

1. **Version control** all configurations
2. **Test in lab** before production
3. **Use templates** for consistency
4. **Document** automation workflows
5. **Start small**, scale gradually
6. **Maintain rollback capability**
7. **Monitor** automated changes
8. **Secure API credentials**

---

## Quick Reference

| Concept | Description |
|---------|-------------|
| JSON | Data format, widely used in APIs |
| YAML | Human-readable data format |
| REST API | HTTP-based interface |
| NETCONF | XML over SSH, uses YANG |
| RESTCONF | REST + YANG |
| Ansible | Agentless automation tool |
| SDN | Centralized network control |
| DNA Center | Cisco SDN controller |
