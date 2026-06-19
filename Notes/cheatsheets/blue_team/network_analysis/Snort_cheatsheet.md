# Snort Cheatsheet

Snort is the most widely deployed open-source IDS/IPS. It inspects traffic against a set of **rules** and can run as a passive sniffer, a packet logger, a Network IDS (alert), or an inline IPS (drop/block). This note is the deep dive; for a side-by-side with Suricata/Zeek see [[IDS_IPS_Tools]].

> **Snort 2 vs Snort 3** — Snort 2 uses `snort.conf` and is what most TryHackMe rooms / legacy deployments run. Snort 3 is a rewrite using a Lua config (`snort.lua`), multithreading, and a new rule engine, but **rule syntax is largely backward compatible**. Differences are flagged inline below.

---

## Installation and Setup

```bash
# Install (Debian/Ubuntu) — Snort 2
sudo apt install snort

# Verify version / build info
snort -V
snort --version

# Common Snort 2 paths
/etc/snort/snort.conf        # Main config
/etc/snort/rules/            # Rule files (local.rules = your own rules)
/etc/snort/rules/local.rules # Write custom rules here
/var/log/snort/              # Default log/alert output
/usr/share/snort/            # Shared files

# Snort 3 paths
/usr/local/etc/snort/snort.lua   # Main Lua config
/usr/local/etc/snort/snort_defaults.lua
```

---

## Operating Modes

Snort has three classic modes. The flags stack: add `-d` for payload, `-e` for link-layer headers.

### 1. Sniffer Mode

```bash
snort -v          # Print packet headers to console
snort -vd         # Headers + application/payload data
snort -vde        # Headers + payload + data-link (Ethernet) headers
snort -X          # Full packet dump (hex + ascii), all layers
```

### 2. Packet Logger Mode

```bash
snort -dev -l ./log          # Log packets to ./log (ASCII, by host dir)
snort -l ./log -K ascii      # Force ASCII output format
snort -l ./log -b            # Log in binary/tcpdump (pcap) format — fast
snort -r snort.log.<ts>      # Read a logged binary file back
snort -r capture.pcap        # Replay any pcap through Snort
```

`-K` log format: `ascii` (human-readable, slow) · `pcap` (binary, default fast) · `none`.

### 3. NIDS Mode (detection against rules)

```bash
# Test the config WITHOUT running (always do this first)
snort -T -c /etc/snort/snort.conf

# Run NIDS, alerts to console
snort -A console -q -c /etc/snort/snort.conf -i eth0

# Run NIDS against a pcap (offline analysis)
snort -A console -q -c /etc/snort/snort.conf -r capture.pcap

# Run only your own rules file (no full config) — quick rule testing
snort -A console -q -c /etc/snort/rules/local.rules -r capture.pcap
```

### 4. IPS / Inline Mode

Requires Snort built with DAQ in inline mode (`afpacket`, `nfq`, etc.). Enables the `drop`/`reject`/`sdrop` actions.

```bash
snort -Q --daq afpacket -c /etc/snort/snort.conf -i eth0:eth1
```

---

## Key Command-Line Flags

| Flag | Purpose |
|------|---------|
| `-c <file>` | Use rules/config file |
| `-r <pcap>` | Read/replay a pcap (offline mode) |
| `-i <iface>` | Listen on interface |
| `-T` | Test configuration and exit |
| `-A <mode>` | Alert mode: `console`, `cmg`, `fast`, `full`, `none`, `unsock` |
| `-q` | Quiet — suppress banner/status |
| `-l <dir>` | Log directory |
| `-K <fmt>` | Log format: `ascii`, `pcap`, `none` |
| `-v` `-d` `-e` `-X` | Verbose / payload / link-layer / full hex dump |
| `-b` | Log packets in binary (pcap) format |
| `-n <N>` | Stop after processing N packets |
| `-s` | Send alerts to syslog |
| `-D` | Run as a daemon (background) |
| `-N` | Disable packet logging (alerts only) |

**Alert modes (`-A`)** — `fast` = one-line alerts to file; `full` = full alert with packet headers; `console` = fast format to stdout; `cmg` = console + payload hex dump (great for learning).

---

## Rule Anatomy

A Snort rule = **Rule Header** + **Rule Options**.

```text
action protocol src_ip src_port  direction  dst_ip dst_port  (option:value; option:value; ...)
└─────────────────── HEADER ───────────────────┘            └────────── OPTIONS ──────────┘
```

**Example:**

```text
alert tcp any any -> 192.168.1.0/24 22 (msg:"SSH Connection Attempt"; sid:1000001; rev:1;)
```

### Header fields

| Part | Meaning | Examples |
|------|---------|----------|
| **action** | What to do on a match | `alert`, `log`, `pass`, `drop`, `reject`, `sdrop` |
| **protocol** | Layer 3/4 protocol | `tcp`, `udp`, `icmp`, `ip` |
| **src/dst IP** | Address or CIDR; `!` negates; lists in `[ ]` | `any`, `192.168.1.0/24`, `!10.0.0.5`, `[10.0.0.0/8,172.16.0.0/12]`, `$HOME_NET` |
| **src/dst port** | Port, range, or `any`; `!` negates | `any`, `80`, `1:1024` (≤1024), `:1024`, `1025:`, `!22`, `[80,443]` |
| **direction** | `->` source→dest, `<>` bidirectional | (`<-` does **not** exist) |

### Actions

| Action | Effect |
|--------|--------|
| `alert` | Generate an alert **and** log the packet |
| `log` | Log the packet silently (no alert) |
| `pass` | Ignore the packet (whitelisting) |
| `drop` | (IPS) Block the packet **and** log it |
| `reject` | (IPS) Block + log + send TCP RST / ICMP unreachable |
| `sdrop` | (IPS) Silently block, no log |

`$HOME_NET` / `$EXTERNAL_NET` are variables set in `snort.conf` (`ipvar HOME_NET 192.168.1.0/24`). Prefer them over hard-coded IPs.

---

## Rule Options — General / Metadata

These describe the rule; they don't match traffic.

```text
msg:"text";          # Message shown with the alert
sid:1000001;         # Snort ID — unique. >=1,000,000 for local/custom rules
rev:1;               # Revision number of this rule
reference:cve,2021-44228;   # External reference (cve, url, bugtraq...)
classtype:trojan-activity;  # Category (sets default priority)
priority:1;          # Severity (1 = highest) — overrides classtype default
gid:1;               # Generator ID (1 = rules engine; usually omitted)
metadata:policy security-ips drop;  # Arbitrary key/value metadata
```

> **SID ranges:** `<100` reserved · `100–999,999` distributed with Snort / official rules · **`>=1,000,000` for your own rules.** Every rule needs a unique `sid`; bump `rev` when you edit one.

---

## Rule Options — Payload Detection

The core of content matching. Modifiers like `nocase`/`offset`/`depth` attach to the `content:` before them.

```text
content:"GET";              # Match bytes/string in payload (ASCII or |hex|)
content:"|90 90 90|";       # Hex content (NOP sled) — pipes delimit hex
content:!"password";        # Negated — match if NOT present
nocase;                     # Make the preceding content case-insensitive
rawbytes;                   # Match against raw packet, ignore decoders

# Positioning modifiers (relative to start of payload OR to last match)
offset:5;     # Start searching 5 bytes into the payload
depth:20;     # Only search the first 20 bytes (from offset)
distance:4;   # Skip 4 bytes after the PREVIOUS content match
within:10;    # Next match must be within 10 bytes of previous match

fast_pattern;     # Use this content for the fast-pattern matcher (perf)
```

### Pattern positioning — quick mental model

- **`offset` + `depth`** → absolute window from the start of the payload.
- **`distance` + `within`** → relative window measured from the **end of the previous `content` match** (used to chain multiple `content` strings in order).

### HTTP sticky/buffer modifiers (with HTTP inspect enabled)

```text
http_method;        # Restrict match to the HTTP method
http_uri;           # ... to the (normalized) request URI
http_raw_uri;       # ... to the raw URI
http_header;        # ... to HTTP headers
http_client_body;   # ... to the request body (POST data)
http_cookie;        # ... to the Cookie header
http_stat_code;     # ... to the response status code
```

Snort 3 expresses these as **sticky buffers** you set first, e.g. `http_uri; content:"/admin";`.

### PCRE (regex)

```text
pcre:"/admin\d+/i";          # Perl-compatible regex; flags after closing /
pcre:"/^POST/m";
```

Common PCRE flags: `i` case-insensitive · `s` dot matches newline · `m` multiline · and Snort extensions `R` (relative to last match), `U` (match URI buffer), `B` (raw bytes), `O` (override default `pcre` config).

### Byte tests

```text
byte_test:4,>,1000,0,relative;   # Test 4 bytes as a number vs 1000
byte_jump:2,0,relative,big;      # Read a length field and jump that many bytes
base64_decode; base64_data; content:"evil";  # Decode then match
```

---

## Rule Options — Non-Payload (header / flow)

Match on packet header fields and connection state.

```text
flow:established,to_server;   # Stateful: only established conns toward server
flow:to_client;              # Direction options below
dsize:>100;                  # Payload size (e.g. >100 bytes)
ttl:64;                      # IP Time-To-Live value
id:12345;                    # IP identification field
sameip;                      # Source IP == destination IP (spoofing)

# TCP
flags:S;                     # TCP flags set (SYN here) — see table
flags:SA;                    # SYN + ACK
seq:0;  ack:0;  window:1024; # TCP seq / ack / window values

# ICMP
itype:8;                     # ICMP type (8 = echo request / ping)
icode:0;                     # ICMP code
icmp_id:; icmp_seq:;         # ICMP id / sequence
```

### `flow` direction keywords

`to_server` / `from_client` · `to_client` / `from_server` · `established` · `stateless` · `not_established` · `no_stream` / `only_stream`.

### TCP `flags` letters

| Letter | Flag | | Letter | Flag |
|--------|------|---|--------|------|
| `F` | FIN | | `U` | URG |
| `S` | SYN | | `C` | CWR |
| `R` | RST | | `E` | ECE |
| `P` | PSH | | `0` | No flags set |
| `A` | ACK | | | |

Modifiers: `flags:SA+;` = SYN+ACK **and** any others · `flags:SA*;` = **any** of SYN/ACK · `flags:!R;` = RST **not** set.

---

## Rule Options — Post-Detection (rate limiting)

Stop one event from generating thousands of alerts, or only fire after N hits (brute-force / scan detection).

```text
# Fire only after a threshold is crossed — classic brute-force detection
detection_filter:track by_src, count 30, seconds 60;
# e.g. alert when one source makes 30+ matching connections within 60s

# Event suppression / rate limiting (config-level in Snort 2: event_filter)
#   type limit   — log first N per window
#   type threshold — log every Nth
#   type both    — log once per N per window
```

**Brute-force SSH example** (fires once a source exceeds the rate):

```text
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; \
  flow:to_server,established; \
  detection_filter:track by_src, count 5, seconds 30; \
  sid:1000010; rev:1;)
```

---

## Example Rules

```text
# 1. Detect ICMP ping (echo request) inbound
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; itype:8; sid:1000001; rev:1;)

# 2. Inbound SSH connection attempt
alert tcp any any -> $HOME_NET 22 (msg:"SSH Connection Attempt"; \
  flow:to_server; flags:S; sid:1000002; rev:1;)

# 3. Detect a cleartext password in FTP traffic
alert tcp any any -> $HOME_NET 21 (msg:"FTP USER command"; \
  content:"USER"; nocase; offset:0; depth:4; sid:1000003; rev:1;)

# 4. HTTP request to a suspicious URI
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Suspicious /admin access"; \
  flow:to_server,established; content:"GET"; http_method; \
  content:"/admin"; http_uri; nocase; sid:1000004; rev:1;)

# 5. Possible Log4Shell (JNDI) exploit string
alert tcp any any -> $HOME_NET any (msg:"Possible Log4j JNDI exploit"; \
  content:"jndi:"; nocase; reference:cve,2021-44228; \
  classtype:attempted-admin; sid:1000005; rev:1;)

# 6. Detect Nmap-style NULL scan (no flags set)
alert tcp any any -> $HOME_NET any (msg:"Nmap NULL Scan"; flags:0; sid:1000006; rev:1;)

# 7. Outbound to a known-bad IP (IOC block, IPS mode)
drop ip $HOME_NET any -> 203.0.113.66 any (msg:"C2 IP blocked"; sid:1000007; rev:1;)
```

---

## Reading Snort Alerts

A typical full/console alert:

```text
[**] [1:1000002:1] SSH Connection Attempt [**]
[Classification: Misc activity] [Priority: 3]
06/19-12:00:00.123456 10.10.0.5:54321 -> 10.10.0.20:22
TCP TTL:64 TOS:0x0 ID:54321 IpLen:20 DgmLen:60 DF
******S* Seq: 0x... Ack: 0x... Win: 0x... TcpLen: 40
```

- `[1:1000002:1]` = **gid:sid:rev** — the rule that fired.
- Line 2 = classtype-derived classification and priority.
- Line 3 = timestamp + `src_ip:port -> dst_ip:port`.
- Line 4+ = decoded packet headers; `******S*` shows which TCP flags are set.

```bash
# Default alert file in NIDS mode
/var/log/snort/alert

# Tail alerts live
tail -f /var/log/snort/alert
```

---

## Config & Operations

```bash
# Validate config + all rule files before deploying
snort -T -c /etc/snort/snort.conf

# Snort 3 equivalents
snort -c /usr/local/etc/snort/snort.lua --warn-all -T   # test config
snort -c snort.lua -R local.rules -r capture.pcap -A alert_fast   # run rules on pcap
snort --help-module http_inspect    # inspect a module's options
```

Custom rules go in `local.rules`, which must be included in `snort.conf`:

```text
include $RULE_PATH/local.rules
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Show version | `snort -V` |
| Sniffer (headers+payload) | `snort -vd` |
| Packet logger (pcap) | `snort -l ./log -b` |
| Replay a pcap through rules | `snort -A console -q -c snort.conf -r file.pcap` |
| NIDS on interface | `snort -A console -q -c snort.conf -i eth0` |
| Test config | `snort -T -c snort.conf` |
| Run only custom rules | `snort -A console -q -c local.rules -r file.pcap` |
| Tail alerts | `tail -f /var/log/snort/alert` |

### Rule cheat-line

```text
action proto SRC sport -> DST dport (msg:"..."; <detection>; sid:>=1000000; rev:1;)
```

---

## Resources

- [Snort Official Site](https://www.snort.org/)
- [Snort 3 User Manual](https://docs.snort.org/)
- [Snort 2 Rule Writing (Users Manual)](https://www.snort.org/documents)
- [Community & ET Open rule sets](https://www.snort.org/downloads)

---

## See Also

- [[IDS_IPS_Tools]] — Snort vs Suricata vs Zeek overview and quick commands
- [[Zeek_cheatsheet]] — Log-based network monitoring (complements signature detection)
- [[Wireshark_cheatsheet]] / [[Tshark_cheatsheet]] — Inspect the packets behind an alert
- [[Tcpdump_cheatsheet]] — Capture the PCAPs you replay through Snort
- [[Firewalls]] — Where an inline Snort/IPS sits in the network
- [[SIEM_and_YARA]] — Forward Snort alerts into a SIEM; YARA for file-based detection
- [[Threat_Hunting_Tools]] — Use Snort alerts as a hunting starting point
- [[Log_analysis]] — Correlate Snort alerts with host/app logs
