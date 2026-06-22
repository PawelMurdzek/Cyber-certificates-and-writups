# APIs and Data Formats

## Data Serialization Formats

### JSON (JavaScript Object Notation)

**Structure**:
```json
{
  "router": {
    "hostname": "R1",
    "interfaces": [
      {
        "name": "GigabitEthernet0/0",
        "ip": "192.168.1.1",
        "mask": "255.255.255.0",
        "enabled": true
      }
    ],
    "routes": 15,
    "temperature": 45.5
  }
}
```

**Data Types**:
| Type | Example |
|------|---------|
| String | `"hello"` |
| Number | `42`, `3.14` |
| Boolean | `true`, `false` |
| Null | `null` |
| Array | `[1, 2, 3]` |
| Object | `{"key": "value"}` |

**Rules**:
- Objects: `{ }` with key:value pairs
- Arrays: `[ ]` with comma-separated values
- Keys must be strings in double quotes
- No trailing commas
- No comments allowed

---

### YAML (YAML Ain't Markup Language)

**Structure**:
```yaml
router:
  hostname: R1
  interfaces:
    - name: GigabitEthernet0/0
      ip: 192.168.1.1
      mask: 255.255.255.0
      enabled: true
  routes: 15
  temperature: 45.5
```

**Rules**:
- Indentation: spaces only (2 spaces common)
- Lists: dashes `-`
- Key-value: `key: value`
- Strings: usually no quotes needed
- Comments: `#`
- Multi-line strings: `|` or `>`

**Data Types**:
```yaml
string: Hello World
quoted_string: "Hello: World"  # Quotes when special chars
integer: 42
float: 3.14
boolean: true  # or yes, on
null_value: null  # or ~
list:
  - item1
  - item2
inline_list: [item1, item2]
```

---

### XML (eXtensible Markup Language)

**Structure**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<router>
  <hostname>R1</hostname>
  <interfaces>
    <interface>
      <name>GigabitEthernet0/0</name>
      <ip>192.168.1.1</ip>
      <mask>255.255.255.0</mask>
      <enabled>true</enabled>
    </interface>
  </interfaces>
  <routes>15</routes>
  <temperature>45.5</temperature>
</router>
```

**Rules**:
- Opening and closing tags: `<tag></tag>`
- Self-closing: `<tag/>`
- Attributes: `<tag attr="value">`
- Case-sensitive
- Comments: `<!-- comment -->`

---

### Format Comparison

| Feature | JSON | YAML | XML |
|---------|------|------|-----|
| Readability | Good | Best | Moderate |
| Verbosity | Low | Low | High |
| Comments | No | Yes | Yes |
| Data types | Limited | Rich | String-based |
| Schema | JSON Schema | YAML Schema | XSD |
| Use case | APIs | Config files | Documents |

---

## REST APIs

### What is REST?

**RE**presentational **S**tate **T**ransfer
- Stateless client-server communication
- Uses HTTP methods
- Resource-based URIs
- Typically JSON for data

### HTTP Methods (CRUD)

| Method | Action | Idempotent | Request Body |
|--------|--------|------------|--------------|
| **GET** | Read | Yes | No |
| **POST** | Create | No | Yes |
| **PUT** | Replace | Yes | Yes |
| **PATCH** | Update | Yes | Yes |
| **DELETE** | Delete | Yes | No |

### URL Structure
```
https://api.example.com/v1/devices/router1/interfaces/ge0

Protocol  Domain        Version Resource  Instance  Sub-resource
```

### HTTP Status Codes

| Code | Category | Examples |
|------|----------|----------|
| 1xx | Informational | 100 Continue |
| 2xx | Success | 200 OK, 201 Created, 204 No Content |
| 3xx | Redirect | 301 Moved, 304 Not Modified |
| 4xx | Client Error | 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found |
| 5xx | Server Error | 500 Internal Error, 503 Service Unavailable |

### Common Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 204 | No content (successful delete) |
| 400 | Bad request (client error) |
| 401 | Unauthorized (no auth) |
| 403 | Forbidden (no permission) |
| 404 | Not found |
| 500 | Server error |

---

### REST Headers

```
Content-Type: application/json
Accept: application/json
Authorization: Bearer <token>
X-Auth-Token: <api-key>
```

### Common Content Types
- `application/json` - JSON data
- `application/xml` - XML data
- `application/yang-data+json` - RESTCONF JSON
- `text/plain` - Plain text

---

## Authentication Methods

### API Key
```
GET /api/devices
X-API-Key: abc123xyz
```

### Basic Authentication
```
Authorization: Basic base64(username:password)
# Example: admin:secret becomes YWRtaW46c2VjcmV0
```

### Bearer Token (OAuth)
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Certificate-Based
- Mutual TLS
- Client presents certificate
- Most secure

---

## Working with APIs

### cURL Examples
```bash
# GET request
curl -X GET "https://api.example.com/devices" \
  -H "Accept: application/json" \
  -H "X-Auth-Token: mytoken"

# POST request (create)
curl -X POST "https://api.example.com/devices" \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: mytoken" \
  -d '{"hostname": "router1", "ip": "192.168.1.1"}'

# PUT request (update)
curl -X PUT "https://api.example.com/devices/router1" \
  -H "Content-Type: application/json" \
  -d '{"hostname": "router1", "ip": "192.168.1.2"}'

# DELETE request
curl -X DELETE "https://api.example.com/devices/router1" \
  -H "X-Auth-Token: mytoken"
```

### Python Examples
```python
import requests
import json

# Base configuration
base_url = "https://api.example.com"
headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Auth-Token": "mytoken"
}

# GET - Read devices
response = requests.get(f"{base_url}/devices", 
                        headers=headers, 
                        verify=False)
devices = response.json()

# POST - Create device
new_device = {
    "hostname": "router1",
    "ip": "192.168.1.1",
    "type": "router"
}
response = requests.post(f"{base_url}/devices",
                         headers=headers,
                         json=new_device,
                         verify=False)
print(response.status_code)  # 201 if created

# PUT - Update device
update_data = {
    "hostname": "router1-updated",
    "ip": "192.168.1.2"
}
response = requests.put(f"{base_url}/devices/router1",
                        headers=headers,
                        json=update_data,
                        verify=False)

# DELETE - Remove device
response = requests.delete(f"{base_url}/devices/router1",
                           headers=headers,
                           verify=False)
```

---

## Parsing Data

### Python JSON
```python
import json

# Parse JSON string
json_string = '{"hostname": "R1", "ip": "192.168.1.1"}'
data = json.loads(json_string)
print(data["hostname"])  # R1

# Read from file
with open("config.json") as f:
    data = json.load(f)

# Write to file
with open("output.json", "w") as f:
    json.dump(data, f, indent=2)
```

### Python YAML
```python
import yaml

# Parse YAML string
yaml_string = """
hostname: R1
interfaces:
  - name: Gi0/0
    ip: 192.168.1.1
"""
data = yaml.safe_load(yaml_string)
print(data["hostname"])  # R1

# Read from file
with open("config.yaml") as f:
    data = yaml.safe_load(f)

# Write to file
with open("output.yaml", "w") as f:
    yaml.dump(data, f, default_flow_style=False)
```

### Python XML
```python
import xml.etree.ElementTree as ET

# Parse XML
xml_string = "<router><hostname>R1</hostname></router>"
root = ET.fromstring(xml_string)
hostname = root.find("hostname").text
print(hostname)  # R1
```

---

## Cisco API Examples

### DNA Center API
```python
# Get token
auth_url = "https://dnacenter/dna/system/api/v1/auth/token"
response = requests.post(auth_url,
                         auth=("admin", "password"),
                         verify=False)
token = response.json()["Token"]

# Use token for API calls
headers = {"X-Auth-Token": token}
devices_url = "https://dnacenter/dna/intent/api/v1/network-device"
response = requests.get(devices_url, headers=headers, verify=False)
devices = response.json()
```

### Meraki API
```python
api_key = "your-meraki-api-key"
headers = {
    "X-Cisco-Meraki-API-Key": api_key,
    "Content-Type": "application/json"
}
url = "https://api.meraki.com/api/v1/organizations"
response = requests.get(url, headers=headers)
orgs = response.json()
```

---

## Best Practices

1. **Handle errors** gracefully
   ```python
   try:
       response = requests.get(url, headers=headers)
       response.raise_for_status()
   except requests.exceptions.HTTPError as err:
       print(f"HTTP Error: {err}")
   ```

2. **Validate data** before sending

3. **Use environment variables** for credentials
   ```python
   import os
   api_key = os.environ.get("API_KEY")
   ```

4. **Implement retry logic** for reliability

5. **Log API calls** for debugging

6. **Use pagination** for large datasets

7. **Rate limit** requests appropriately

---

## Quick Reference

| Task | Example |
|------|---------|
| JSON parse | `json.loads(string)` |
| JSON dump | `json.dumps(obj)` |
| YAML parse | `yaml.safe_load(string)` |
| HTTP GET | `requests.get(url)` |
| HTTP POST | `requests.post(url, json=data)` |
| Get JSON response | `response.json()` |
| Check status | `response.status_code` |
