# OSINT — Open Source Intelligence

Top-level hub for open-source intelligence: passive recon, social-media analysis, geolocation, breach data, regional / dark-web sources, and detective / investigator tooling.

> **Scope:** OSINT is dual-use — used by red teams, threat intel, brand protection, missing-persons CTFs, journalists, and private investigators. This folder is structured around capability rather than role.

---

## Folder Layout

### Methodology & Tradecraft
| File | Purpose |
|:-----|:--------|
| [[OSINT]] | This file — index and methodology |
| [[VMs_and_Compartmentalization]] | Qubes / Whonix / VirtualBox setup, snapshot hygiene, sock-puppet identity, browser fingerprint hardening |
| [[Geolocation]] | Pinpointing photo / video locations — Bellingcat methodology, sun position, satellite imagery, reverse image search |
| [[Darkweb_Forums]] | Tor / I2P primer, forum taxonomy, threat-intel sourcing, OPSEC (educational, no live `.onion` URLs) |

### Tooling
| File | Purpose |
|:-----|:--------|
| [[Browser_Extensions]] | Firefox / Chrome extensions used by TraceLabs and analysts |
| [[Tools_Kali_Tracelabs]] | CLI / GUI tools shipped with Kali and TraceLabs OSINT VM — Sherlock, Maigret, theHarvester, Recon-ng, etc. |
| [[Detective_Tools]] | Maltego, i2 Analyst's Notebook, LexisNexis Accurint, TLO, Skopenow, ShadowDragon — the gated PI / investigator stack |
| [[Social_Media_APIs]] | Extensive matrix: official APIs, scraping difficulty, account requirements, the locked-down landscape as of 2026, federated platforms (Mastodon, Bluesky, Lemmy) |

### Operating Systems
| File | Purpose |
|:-----|:--------|
| [[Distros]] | TraceLabs OSINT VM, Kali, CSI Linux, Tsurugi, Whonix, Tails, Qubes, Parrot |
| [[Parrot_OS]] | Deep-dive on Parrot Security tools that don't ship with TraceLabs / Kali (AnonSurf, Pandora, MAT2, Ricochet) |

### Regional Ecosystems
| File | Coverage |
|:-----|:---------|
| [[Regional_RUNet]] | Russia / Belarus / Kazakhstan / wider CIS — VK, Yandex, OK, Telegram, RU corporate registries |
| [[Regional_China]] | Chinese-language internet — Baidu, Weibo, WeChat, Douyin, Tianyancha / Qichacha |
| [[Regional_Arabic]] | Arabic-language internet across MENA — country-by-country, conflict OSINT, MSA vs dialect |

### Country Deep-Dives
| File | Country |
|:-----|:--------|
| [[Country_Iran]] | Persian-language ecosystem, Aparat, Eitaa, regime news vs exile |
| [[Country_Belarus]] | Distinct from RUNet — Cyber Partisans, NEXTA, exile media |
| [[Country_Poland]] | KRS / CEIDG / MSiG, Polish media, Wykop |
| [[Country_USA]] | PACER, SEC EDGAR, 50 state ecosystems, gated PI tools |
| [[Country_UK]] | Companies House (the gold standard), Land Registry, BAILII |
| [[Country_Japan]] | LINE, 5ch, Mixi, Niconico, Pixiv, Naver-Pawoo Mastodon |
| [[Country_SouthKorea]] | Naver / Kakao / DC Inside, real-name verification challenge |
| [[Country_NorthKorea]] | Outside-in methodology — KCNA, satellite imagery, defector sources |
| [[Country_India]] | Multilingual, Aadhaar context, MCA21, ShareChat |
| [[Country_Brazil]] | WhatsApp dominance, CNPJ open registry, election OSINT |

---

## OPSEC Cardinal Rules

> [!IMPORTANT]
> Every OSINT investigation leaks data about **you**. Plan compartmentalisation before you click anything. Full setup in [[VMs_and_Compartmentalization]].

1. **Never investigate from your daily-driver browser or account.** Use a dedicated VM / container per case.
2. **Assume sites log everything.** Visiting a target's site, querying a username, downloading their photo — all leave traces (IP, User-Agent, browser fingerprint, sometimes account-tied analytics).
3. **No personal accounts on investigation infrastructure.** A logged-in Google search is logged against your real identity.
4. **Use throwaway "sock puppet" accounts** with believable history if you need to access social platforms.
5. **Document as you go.** [[Browser_Extensions#Capture & Note-Taking|Hunchly]] or a dedicated screenshot tool — sources rot fast.
6. **Legal review** on any cross-border or dark-web work *before* you start. Some passive collection is illegal in some jurisdictions.

---

## Standard Methodology

```
1. Define scope and goal      → what question are we answering?
2. Choose investigation OS    → fresh VM snapshot, see [[Distros]]
3. Identify selectors         → emails, usernames, phone numbers, domains, names, images
4. Pivot through selectors    → each hit reveals new selectors
5. Capture continuously       → Hunchly / screenshots with hashes + timestamps
6. Cross-reference            → never trust a single source
7. Verify (esp. images)       → see [[Geolocation]] for visual cases
8. Report                     → narrative + evidence chain
```

---

## Selector Cheat-Sheet

| Selector | Where to start |
|:---------|:---------------|
| **Email** | Holehe, EmailRep, Hunter.io, HaveIBeenPwned, DeHashed |
| **Username** | [[Tools_Kali_Tracelabs#Sherlock\|Sherlock]], WhatsMyName, NameCheckr, Maigret |
| **Phone** | PhoneInfoga, TrueCaller (regional), Sync.me, OpenCellID |
| **Domain** | [[DNS_Enumeration]], crt.sh, SecurityTrails, ViewDNS, Whoisology |
| **IP** | Shodan, Censys, GreyNoise, AbuseIPDB |
| **Image** | Yandex Images (best for faces), Google, TinEye, PimEyes — see [[Geolocation]] |
| **Document** | Metagoofil, [[Tools_Kali_Tracelabs#ExifTool\|ExifTool]], FOCA |
| **Person (US)** | TLO, Accurint, BeenVerified — see [[Detective_Tools]] |
| **Person (UK)** | Companies House, electoral roll, 192.com — see [[Country_UK]] |
| **Person (PL)** | KRS, CEIDG, REGON — see [[Country_Poland]] |
| **Company (global)** | OpenCorporates, Sayari Graph, regional registries |

---

## Common OSINT Frameworks & Lists

- **OSINT Framework** — [osintframework.com](https://osintframework.com/) — categorised tool list, the canonical starting point
- **TraceLabs OSINT VM** — preconfigured tooling, see [[Distros]]
- **Bellingcat Online Investigation Toolkit** — [bellingcat.com/resources](https://www.bellingcat.com/resources/) — curated by working investigators
- **IntelTechniques** — [inteltechniques.com/tools](https://inteltechniques.com/tools/) — Michael Bazzell's tools
- **Awesome OSINT** — [github.com/jivoi/awesome-osint](https://github.com/jivoi/awesome-osint)

---

## See Also

- [[DNS_Enumeration]] — Passive DNS / cert transparency overlap
- [[Getting_Started]] — Where OSINT fits in the kill chain
- [[Burp_Suite]] — When you pivot to active web recon
