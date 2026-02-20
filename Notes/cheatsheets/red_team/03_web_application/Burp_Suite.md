# Burp Suite Toolguide & Cheatsheet

Burp Suite is the industry standard web application security testing platform. It acts as an intercepting proxy, allowing you to capture, analyze, and manipulate HTTP/HTTPS traffic between your browser and the target application.

---

## Setup & Configuration

### Basic Proxy Setup
1. **Burp Proxy**: Listens on `127.0.0.1:8080` by default.
2. **Browser Extension**: Use **FoxyProxy** (or similar) to quickly toggle traffic forwarding to Burp.
   - Profile: `127.0.0.1`, Port: `8080`
3. **HTTPS Interception**: Download and install the Burp CA Certificate.
   - Start Burp -> configure proxy in browser -> visit `http://burp` -> Click **CA Certificate**.
   - Import the downloaded `.der` file into your browser's Certificate Manager as a "Trusted Root Certification Authority" and check "Trust this CA to identify websites".

### Advanced Scope Configuration
Restricting your scope ensures you do not inadvertently attack third-party services (e.g., analytics, CDNs) and keeps your HTTP History clean.

1. Navigate to **Target -> Scope settings**.
2. Add target URLs or use Regex (e.g., `.*\.target\.com$`).
3. To hide out-of-scope traffic: Go to **Proxy -> HTTP history**, click the filter bar, and check **Show only in-scope items**.

---

## Core Tools Deep Dive

### Proxy
The heart of Burp Suite. Used to intercept and modify requests/responses.
- **Intercept**: Pause requests/responses mid-flight to manipulate parameters, headers, or bypass client-side validation.
- **HTTP History**: A log of all proxied traffic. Essential for finding endpoints, hidden parameters, and analyzing typical application behavior.
- **WebSockets**: View and intercept WebSocket communications.

**Shortcut**: `Ctrl+I` - Toggle intercept on/off | `Ctrl+F` - Forward intercepted request

### Repeater
Used for manual, iterative testing. Send a request to Repeater, manipulate inputs, and observe the application's response without navigating the browser.
- **Workflow**: `Right-click request -> Send to Repeater` (`Ctrl+R`).
- **Use Cases**: Testing SQLi, XSS, IDORs, bypassing parameter tampering protections, or stepping through multi-step vulnerabilities.
- **Shortcut**: `Ctrl+Space` - Send request.

### Intruder
Burp's custom fuzzing and brute-forcing engine.
**Workflow**: `Right-click request -> Send to Intruder` (`Ctrl+I`). Define injection points with `§` markers.

| Attack Type | Description | Best For |
|:------------|:------------|:---------|
| **Sniper** | Iterates through multiple injection points one by one with a single payload set. | Fuzzing multiple parameters for SQLi/XSS. |
| **Battering Ram** | Places the exact same payload in all injection points simultaneously. | Discovering global WAF bypasses or identical headers. |
| **Pitchfork** | Iterates through payload sets in parallel (Set 1 with Set 2). | Testing known username/password pairs (e.g., admin + password). |
| **Cluster Bomb** | Tries all possible combinations of the given payload sets. | True brute-forcing (every user with every password). |

**Intruder Tips**:
- **Grep - Match**: Define regex or strings to search for in responses (e.g., searching for "Login Failed" or "Welcome").
- **Grep - Extract**: Extract CSRF tokens or useful data from the response to use in manual analysis.
- **Performance tuning**: Adjust concurrent requests under Intruder's **Resource Pool** settings based on the target server's limitations.

### Sequencer
Analyzes the quality of randomness in sample data items.
- **Use Case**: Testing session tokens, anti-CSRF tokens, or password reset tokens to see if they are predictable or mathematically sound.

### Decoder & Comparer
- **Decoder**: Encodes/decodes data formats such as URL, HTML, Base64, Hex, ASCII, and Gzip. Essential for nested encodings (e.g., URL encoded Base64).
- **Comparer**: A visual diff tool. Send two responses (e.g., high privileged user vs. low privileged user) to highlight exact differences in HTML or response lengths.

---

## Methodology & Essential Techniques

### 1. Application Mapping (Discovery)
1. Configure Scope strictly.
2. Browse the application manually. Click every link, submit every form, use every feature.
3. Review the **Site map** (Target -> Site map) for unvisited but linked endpoints (greyed out).
4. *(Burp Pro only)* Active/Passive scan the application.

### 2. Testing for Injection (SQLi)
1. Identify all inputs (URL parameters, POST bodies, specific headers like User-Agent or Cookie).
2. Send the request to Repeater.
3. Inject syntax breakers to induce errors or time delays:
   - `'` (single quote)
   - `"` (double quote)
   - `' OR '1'='1`
   - `WAITFOR DELAY '0:0:5'` (SQL Server Time-based)
   - `pg_sleep(5)` (PostgreSQL Time-based)

### 3. Testing for XSS (Cross-Site Scripting)
1. Input generic tracking strings into fields (e.g., `XSS_TEST`).
2. Discover where that string reflects back in the HTTP response (Search in HTTP History).
3. Attempt to break out of the HTML context to execute JavaScript:
   - `<script>alert(1)</script>`
   - `"><img src=x onerror=prompt(document.cookie)>`
   - `javascript:alert(1)` (for `href` attributes)

### 4. Brute-Force & Credential Stuffing
1. Capture login POST request.
2. Send to **Intruder**.
3. Clear existing markers, highlight username and password values, and add `§`.
4. Select **Cluster Bomb** attack type.
5. In Payloads tab, set Payload set 1 (users) and Payload set 2 (passwords).
6. Start Attack. Sort results by **Length** or **Status** to identify successful logins.

---

## Powerful Match and Replace Rules

Under `Proxy -> Options -> Match and Replace`, you can automatically modify requests/responses passing through the proxy.

**Useful Rules**:
- Downgrade HTTPS to HTTP.
- Strip `HttpOnly` or `Secure` flags from `Set-Cookie` responses (useful for XSS exploitation).
- Change `User-Agent` headers automatically to bypass simple restrictions (e.g., mobile-only sites).
- Insert `X-Forwarded-For: 127.0.0.1` header globally to test for source IP validation bypasses.

---

## Session Handling & Macros (Advanced Automation)

Sometimes web applications use anti-CSRF tokens or implement aggressive session timeouts.
1. Navigate to **Project options -> Sessions**.
2. Add a **Session Handling Rule** and define the Scope.
3. Add an action, such as **Check session is valid** or **Run a macro** (a pre-recorded sequence of requests).
4. When you run Intruder or Scanner, Burp will automatically execute the macro to fetch a valid CSRF token and inject it into your payloads dynamically.

---

## Essential Extensions (BApp Store)

Access via `Extender -> BApp Store`. Note: Some extensions require Jython or JRuby configured in the Extender options.

| Extension | Purpose |
|:----------|:--------|
| **Autorize** | Essential for IDORs and broken access control testing. Feed it a low-privileged user's cookie, browse the app as an admin, and Autorize automatically re-plays all requests to test if the low-priv user has access. |
| **Logger++** | An advanced HTTP history log that captures traffic from *all* Burp modules (including Intruder and Scanner), equipped with powerful grep capabilities. |
| **Param Miner** | Identifies hidden unlinked parameters via active fuzzing. Essential for Web Cache Poisoning. |
| **Turbo Intruder** | Next-gen Intruder alternative written in Python. Capable of tens of thousands of requests per second for race condition testing. |
| **JSON Web Tokens (JWT)** | Adds a dedicated tab for decoding, tampering with, and forging JWTs (e.g., modifying the signature or "alg" field). |
| **Hackvertor** | Tag-based conversion tool. Example: `<@base64>admin<@/base64>` dynamically encodes payloads before sending the request. |
| **Upload Scanner** | File upload testing |
| **ActiveScan++** | Enhanced scanning |
| **Autorize** | Authorization testing |

---

## Keyboard Shortcuts Summary

| Action | Shortcut |
|:-------|:---------|
| Send to Repeater | `Ctrl+R` |
| Send to Intruder | `Ctrl+I` |
| Forward intercepted request | `Ctrl+F` |
| Toggle intercept | `Ctrl+T` (or `Ctrl+I` on some mappings) |
| Go to next/previous tab | `Ctrl+Tab` / `Ctrl+Shift+Tab` |
| Search | `Ctrl+S` |

---

## Resources for Mastery

- [PortSwigger Web Security Academy](https://portswigger.net/web-security) (Free labs created by the makers of Burp Suite - highly recommended).
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)

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

