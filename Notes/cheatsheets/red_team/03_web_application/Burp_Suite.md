# Burp Suite

Essential web application security testing proxy.

## Setup

### Proxy Configuration
1. **Burp Proxy**: Runs on `127.0.0.1:8080` by default
2. **Browser**: Configure proxy to `127.0.0.1:8080`
3. **HTTPS**: Install Burp CA certificate (http://burp)

### FoxyProxy (Browser Extension)
Create a profile for Burp:
- IP: `127.0.0.1`
- Port: `8080`

---

## Core Tools

### Proxy
Intercept and modify HTTP/HTTPS traffic.

| Feature | Description |
|:--------|:------------|
| **Intercept** | Pause and modify requests/responses |
| **HTTP History** | View all proxied traffic |
| **WebSockets** | Intercept WebSocket messages |

**Shortcut**: `Ctrl+I` - Toggle intercept on/off

### Repeater
Manually modify and resend requests.

```
Right-click request → "Send to Repeater"
```

| Action | Shortcut |
|:-------|:---------|
| Send request | `Ctrl+Space` |
| New tab | `Ctrl+T` |

### Intruder
Automate customized attacks (fuzzing, brute-forcing).

**Attack Types**:
| Type | Description |
|:-----|:------------|
| **Sniper** | Single payload, one position at a time |
| **Battering Ram** | Same payload, all positions simultaneously |
| **Pitchfork** | Different payloads, parallel positions |
| **Cluster Bomb** | All combinations of payloads |

**Workflow**:
1. Right-click request → "Send to Intruder"
2. Mark injection points with `§` markers
3. Configure payloads
4. Start attack

### Decoder
Encode/decode data in various formats.

Supported formats: URL, HTML, Base64, Hex, Gzip, etc.

### Comparer
Compare two pieces of data (responses, requests).

---

## Essential Techniques

### Finding Hidden Content
```
1. Browse the application with proxy on
2. Right-click target in Sitemap → "Spider this host"
3. Review discovered content
```

### Testing for SQL Injection
```
1. Find parameter (e.g., ?id=1)
2. Send to Repeater
3. Test payloads:
   - ' (single quote)
   - " (double quote)
   - ' OR '1'='1
   - 1' AND '1'='1
   - 1' AND '1'='2
```

### Testing for XSS
```
1. Find input field
2. Send to Repeater
3. Test payloads:
   - <script>alert(1)</script>
   - <img src=x onerror=alert(1)>
   - javascript:alert(1)
```

### Brute-Force Login
```
1. Capture login request
2. Send to Intruder
3. Mark username/password with §markers§
4. Attack type: Cluster Bomb (for both) or Sniper (single field)
5. Load wordlists
6. Start attack
7. Look for different response length/status
```

---

## Useful Extensions

Install from BApp Store (Extender → BApp Store):

| Extension | Purpose |
|:----------|:--------|
| **Autorize** | Authorization testing |
| **Logger++** | Enhanced logging |
| **Param Miner** | Find hidden parameters |
| **Turbo Intruder** | Fast fuzzing |
| **ActiveScan++** | Enhanced scanning |
| **JWT Editor** | JWT manipulation |
| **Hackvertor** | Encoding/obfuscation |
| **Upload Scanner** | File upload testing |

---

## Keyboard Shortcuts

| Action | Shortcut |
|:-------|:---------|
| Toggle intercept | `Ctrl+I` |
| Forward intercepted request | `Ctrl+F` |
| Send to Repeater | `Ctrl+R` |
| Send to Intruder | `Ctrl+I` |
| Go to next tab | `Ctrl+Tab` |
| Search | `Ctrl+S` |

---

## Tips & Tricks

### Scope Control
```
Target → Scope → Add target to scope
Proxy → Options → Enable "Use advanced scope control"
```

### Faster Intruder (Community Edition)
```
Project Options → HTTP → 
  - Reduce throttle
  - Increase concurrent connections
```

### Match and Replace
```
Proxy → Options → Match and Replace
Add rules to automatically modify requests/responses
```

### Session Handling
```
Project Options → Sessions → Session Handling Rules
Configure automatic re-authentication
```

---

## Quick Reference Workflow

```
1. Set up proxy (127.0.0.1:8080)
2. Browse target manually (map the application)
3. Review Sitemap for interesting endpoints
4. Test parameters with Repeater
5. Automate with Intruder for fuzzing/brute-force
6. Check Scanner results (Pro only for active scanning)
```

---

## Resources

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
