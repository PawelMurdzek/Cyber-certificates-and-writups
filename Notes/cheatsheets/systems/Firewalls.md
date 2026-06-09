# Firewalls

A firewall is a network security device (or software) that monitors incoming and outgoing traffic and permits or blocks it based on a defined set of rules. It enforces a boundary between trusted and untrusted networks.

## Firewall Types

### Stateless firewalls
- Basic packet filtering.
- No track of previous connections — each packet is evaluated in isolation.
- Efficient for high-speed networks.

### Stateful firewalls
- Recognize traffic by patterns and track the state of active sessions.
- Complex rules can be applicable.
- Monitor the network connections end to end.

### Proxy firewalls
- Inspect the data inside the packets as well (application-layer inspection).
- Provides content filtering options.
- Provides application control.
- Decrypts and inspects SSL/TLS data packets.

### Next-generation firewalls (NGFW)
- Provides advanced threat protection.
- Comes with an intrusion prevention system (IPS).
- Identify anomalies based on heuristic analysis.
- Decrypts and inspects SSL/TLS data packets.

## Linux Firewall Utilities

On Linux, firewalling is implemented in the kernel by **Netfilter**; the common command-line utilities are user-space front-ends that program its rules.

### Netfilter
- The packet-filtering framework built into the Linux kernel.
- Exposes hooks in the network stack for filtering, NAT, and packet mangling.
- The utilities below are all front-ends that configure Netfilter rules.

### iptables
- The most widely used utility in many Linux distributions.
- Uses the Netfilter framework, which provides various functionalities to control network traffic.

### nftables
- A successor to the `iptables` utility, with enhanced packet filtering and NAT capabilities.
- Also based on the Netfilter framework.

### firewalld
- Also operates on the Netfilter framework and has predefined rule sets.
- Works differently from the others and comes with different pre-built network zone configurations.

### ufw (Uncomplicated Firewall)
- A simplified, user-friendly front-end for managing firewall rules (built on top of iptables/nftables).
- Default on Ubuntu and Debian-based systems; designed to make basic configuration easy, e.g. `ufw allow 22/tcp`.

---

## See Also

- [[IDS_IPS_Tools]] — Intrusion detection/prevention engines (Snort, Suricata, Zeek)
- [[System_Logs]] — Log sources for monitoring firewall events
- [[Linux_commands_and_concepts]] — General Linux command reference
