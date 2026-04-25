# OSINT — Open Source Intelligence

Hub for open-source intelligence gathering: passive recon, social media analysis, geolocation, breach data, and regional / dark-web sources.

> **Phase:** Reconnaissance — passive only. Active recon (port scans, brute force) belongs in [[Nmap]], [[gobuster]], [[ffuf]], [[DNS_Enumeration]].

---

## What's in this folder

| File | Purpose |
|:-----|:--------|
| [[Browser_Extensions]] | Firefox/Chrome extensions used by TraceLabs and OSINT analysts |
| [[Tools_Kali_Tracelabs]] | CLI / GUI tools shipped with Kali and TraceLabs OSINT VM |
| [[Distros]] | OSINT-focused Linux distros (TraceLabs OSINT VM, CSI Linux, Tsurugi, Whonix, Tails) |
| [[VMs_and_Compartmentalization]] | Qubes / Whonix / VirtualBox setup, snapshot hygiene, fingerprint hardening |
| [[Darkweb_Forums]] | Tor / I2P primer, forum categories, threat-intel sourcing, OPSEC |
| [[Regional_RUNet]] | RUNet platforms — VK, Yandex, OK, Telegram, RU corporate registries |
| [[Regional_China]] | Chinese-net — Baidu, Weibo, WeChat, Douyin, Tianyancha / Qichacha |
| [[Regional_Arabic]] | Arabic-language platforms and country-specific resources |

---

## OPSEC Cardinal Rules

> [!IMPORTANT]
> Every OSINT investigation leaks data about **you**. Plan compartmentalization before you click anything.

1. **Never investigate from your daily-driver browser or account.** Use a dedicated VM / container per case.
2. **Assume sites log everything.** Visiting a target's site, querying a username, downloading their photo — all leave traces (IP, User-Agent, browser fingerprint, sometimes account-tied analytics).
3. **No personal accounts on investigation infrastructure.** A logged-in Google search is logged against your real identity.
4. **Use throwaway "sock puppet" accounts** with believable history if you need to access social platforms — see [[VMs_and_Compartmentalization]].
5. **Document as you go.** Hunchly or a dedicated screenshot tool — sources rot fast.
6. **Legal review** on any cross-border or dark-web work *before* you start. Some passive collection is illegal in some jurisdictions.

---

## Standard Methodology

```
1. Define scope and goal      → what question are we answering?
2. Choose investigation OS    → fresh VM snapshot, see [[Distros]]
3. Identify selectors         → emails, usernames, phone numbers, domains, names
4. Pivot through selectors    → each hit reveals new selectors
5. Capture continuously       → Hunchly / screenshots with hashes + timestamps
6. Cross-reference            → never trust a single source
7. Report                     → narrative + evidence chain
```

---

## Selector Cheat-Sheet

| Selector | Where to start |
|:---------|:---------------|
| **Email** | Holehe, EmailRep, Hunter.io, HaveIBeenPwned, DeHashed |
| **Username** | [[Tools_Kali_Tracelabs#Sherlock\|Sherlock]], WhatsMyName, NameCheckr, Maigret |
| **Phone** | PhoneInfoga, TrueCaller (regional), Sync.me |
| **Domain** | [[DNS_Enumeration]], crt.sh, SecurityTrails, ViewDNS, Whoisology |
| **IP** | Shodan, Censys, GreyNoise, AbuseIPDB |
| **Image** | Google Images, Yandex Images (best for faces), TinEye, PimEyes (commercial) |
| **Document** | Metagoofil, [[Tools_Kali_Tracelabs#ExifTool\|ExifTool]], FOCA |
| **Person (PL/EU)** | KRS, CEIDG, Companies House (UK), OpenCorporates |

---

## Common OSINT Frameworks & Lists

- **OSINT Framework** — [osintframework.com](https://osintframework.com/) — categorised tool list, the canonical starting point
- **TraceLabs OSINT VM** — preconfigured tooling and extensions, see [[Distros]]
- **Bellingcat Online Investigation Toolkit** — [bellingcat.com/resources](https://www.bellingcat.com/resources/) — curated by working investigators
- **IntelTechniques** — [inteltechniques.com/tools](https://inteltechniques.com/tools/) — Michael Bazzell's tools
- **Awesome OSINT** — [github.com/jivoi/awesome-osint](https://github.com/jivoi/awesome-osint)

---

## See Also

- [[DNS_Enumeration]] — passive DNS / cert transparency overlap
- [[Getting_Started]] — where OSINT fits in the kill chain
- [[Burp_Suite]] — once you pivot to active web recon
