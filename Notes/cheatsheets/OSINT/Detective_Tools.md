# Detective / Criminology / Investigator Tooling

The professional-investigator and criminology toolchain. Some overlap with general [[Tools_Kali_Tracelabs|OSINT tools]], but this category emphasises:

- **Link analysis** at scale (graph databases, visual investigation)
- **Gated public-records aggregators** (LEO / PI / lawyer access only)
- **Commercial threat-intelligence platforms**
- **Digital forensics** (mobile / disk) adjacent to OSINT
- **Court / case-management** integrations

> [!IMPORTANT]
> Many tools below require **professional licensing** (PI licence, attorney bar, LEO badge) or **vetted-customer status** (KYC for sanctions / fraud / threat-intel applications). Do not attempt to register with false credentials — these vendors verify, and falsification has triggered civil and criminal cases against bad-faith subscribers.

---

## Link Analysis & Visual Investigation

### Maltego
The de-facto OSINT link-analysis tool. Visual graph; "transforms" pull data from external sources and add nodes/edges.

| Edition | Cost | Notes |
|:--------|:-----|:------|
| **Maltego CE** | Free, account required | Ships with Kali / [[Distros#TraceLabs OSINT VM\|TraceLabs OSINT VM]] / [[Parrot_OS]]. Limited transforms. 12-hour result expiry on free tier |
| **Maltego Classic** | Paid (~$1k/yr) | Full transform set, no result expiry |
| **Maltego XL** | Paid (more) | Larger graphs (10k+ entities), enterprise |
| **Maltego Pro / ITDS** | Enterprise | Threat-intel platform integration |

```bash
# Launch
maltego        # GUI

# Common transforms (Maltego CE):
# - Domain → DNS records, MX, NS
# - Email → social profiles, breaches (limited)
# - Person → related entities, social, employment
# - PhoneNumber → carrier, location guess
# - Document → metadata extraction
```

### IBM i2 Analyst's Notebook
Heavy enterprise / LEO favourite. Less OSINT-extensive than Maltego, deeper case-management. **i2 Connect** integrates external data.
- Interactive timeline, geospatial, social-network analysis
- Used by virtually every major LEO agency in the West

### Palantir Gotham / Foundry
Enterprise / government link analysis at scale. Deeply integrated with classified and operational systems — typically not for solo investigators. Mentioned because case studies frequently reference it.

### Sentinel Visualizer
Lightweight Maltego/i2 alternative — link analysis + temporal + geospatial. Niche but sometimes used in private investigation.

### IntelTechniques OSINT Tools
[Michael Bazzell's "OSINT Tools"](https://inteltechniques.com/tools/) — *not* a graphing tool, but a curated tool launcher. Free web app + the **IntelTechniques OSINT Workbook** (Bazzell's textbook).

### Open-source alternatives
- **OSINT Combine tools** — free workflows
- **Cyber Investigation tools** (community projects)
- **SpiderFoot HX** ([spiderfoot.net](https://www.spiderfoot.net/)) — automated, hosted, paid
- **OSINT Industries** ([osint.industries](https://osint.industries/)) — selector-pivoting service, paid

---

## Gated Public-Records Aggregators (PI / LEO / Attorney access)

These ingest credit-header data, voter rolls, court records, deed transfers, vehicle registrations, etc. They are **not free** and require professional credentials + signed compliance attestations (FCRA, GLBA, DPPA in the US).

### TLO / TransUnion TLOxp
- **Access:** US PIs, attorneys, LEO; vetted commercial fraud
- **Strengths:** Address history, relatives, vehicles, bankruptcies, civil cases
- **Cost:** Per-search or subscription

### LexisNexis Accurint
- **Access:** Same gating as TLO
- **Strengths:** Person/business search, real-property holdings, asset locator, criminal records
- **Variants:** Accurint for Investigations (PI), Accurint for Law Enforcement (LEO), Accurint for Legal Professionals
- Particularly strong on professional licences, business affiliations

### IDI Core / Cognyte LIRX
- **Access:** Vetted
- **Strengths:** Mobile phone analytics, TLO-comparable people search
- **Mobile-phone metadata access** is the differentiator

### CLEAR (Thomson Reuters)
- **Access:** Vetted
- **Strengths:** Litigation history, sanctions / PEP screening, deep court coverage
- **Usage:** Heavy in compliance / KYC

### IRBSearch
- **Access:** PI / LEO
- **Strengths:** Comparable to TLO, often lower cost

### LocatePLUS
- **Access:** PI / LEO
- **Strengths:** Skip-tracing

### Pipl Pro
- **Access:** Vetted business
- **Strengths:** Deep-web identity records, international scope (less US-centric than the above)

### Skopenow
- **Access:** Lower bar than TLO/Accurint, paid
- **Strengths:** Social-media-focused, automated reports
- **Usage:** Insurance investigations, employee due diligence, modern PI work

### ShadowDragon (SocialNet, Maltego transforms)
- **Access:** Vetted
- **Strengths:** Social-media and dark-web pivoting, Maltego integration
- **Usage:** Threat intelligence, missing persons, fraud

### Babel Street Babel X
- **Access:** Vetted government / enterprise
- **Strengths:** Multi-language social-media monitoring (180+ languages)
- **Usage:** National-security analysis, crisis monitoring

### IDIQ / SentryLink / Checkr
- **Access:** Various (FCRA-regulated for employment use)
- **Strengths:** Background-check workflow tools

---

## Threat Intelligence Platforms (commercial)

Used for cyber-threat OSINT — adversary tracking, dark-web monitoring, brand protection.

| Platform | Strength |
|:---------|:---------|
| **Recorded Future** | Largest TI platform; integrated dark-web/breach/IOC data, relationship graph |
| **Mandiant Advantage** (Google) | Adversary intelligence, especially nation-state |
| **Flashpoint** | Dark-web monitoring, illicit communities |
| **Intel471** | Underground actor tracking, cybercrime |
| **DarkOwl** | Dark-web data lake, more raw than aggregated |
| **CrowdStrike Falcon Intelligence** | Endpoint-tied TI |
| **Anomali** | TI platform / aggregator |
| **ZeroFox** | Brand protection, executive protection, social-media monitoring |
| **Echosec** | Geo-tagged social media |
| **Bluedot** | Public-health / outbreak OSINT |
| **Janes** | Defence / military OSINT (deep tradition) |

---

## Court / Case-Management Tools

| Tool | Use |
|:-----|:----|
| **PACER** | US federal court records — see [[Country_USA]] |
| **CourtListener / RECAP** | Free PACER mirror |
| **UniCourt** | Aggregated US state-court records |
| **CaseText / Westlaw / LexisNexis** | Legal research, case law |
| **Bloomberg Law** | Legal + corporate intel |
| **Casetext / vLex Fastcase** | Lower-cost legal databases |
| **Trellis / Docket Alarm** | US state court alerts |

---

## Mobile / Digital Forensics (OSINT-adjacent)

Strictly forensics rather than OSINT, but investigators frequently need both:

| Tool | Use |
|:-----|:----|
| **Cellebrite UFED / Inseyets** | Mobile-device forensics. Vetted LEO/government primarily |
| **Magnet AXIOM / Forensic Grayshift** | Comprehensive mobile + cloud forensics |
| **MSAB XRY** | Mobile forensics |
| **Oxygen Forensic Detective** | Mobile + cloud |
| **Belkasoft Evidence Center** | Cloud / device forensics |
| **Autopsy / Sleuth Kit** | Free / open-source disk forensics |
| **FTK Imager** | Free imaging tool |
| **Volatility** | Memory analysis — see [[Volatility_and_Linux_Forensics]] |

---

## Vehicle / Infrastructure Tracking

| Tool | Use |
|:-----|:----|
| **MarineTraffic / VesselFinder / Lloyd's List Intelligence** | Ship tracking, ownership chains |
| **FlightRadar24 / FlightAware** | Civilian aircraft |
| **ADS-B Exchange** | Uncensored ADS-B (military aircraft included) |
| **PenLink / GrayKey** | Telecom-records analysis (LEO) |
| **License-plate recognition (Vigilant Solutions, MotorolaSolutions Plate Hunter)** | LEO / repo industry, ethically contested |
| **Carfax / AutoCheck** | Vehicle history (US) |

---

## People-Search Aggregators (Consumer-tier)

> Lower bar than the gated PI tools above, but lower data quality and less suitable for evidence-grade work.

| Tool | Region |
|:-----|:-------|
| **BeenVerified** | US |
| **Spokeo** | US |
| **Intelius / PeopleFinders** | US |
| **TruePeopleSearch** | US, free ad-supported |
| **WhitePages Premium** | US |
| **192.com** | UK |
| **Findmypast / Ancestry** | UK / global genealogy |
| **AnyWho** | US |
| **Pipl (consumer)** | Global |

---

## Specialty / Niche

| Tool | Use |
|:-----|:----|
| **ShadowDragon Horizon** | Visual link analysis, social-media-aware |
| **Babel Street Babel X** | Multilingual social monitoring |
| **OpenSource.io / Sayari** | Corporate-network mapping (especially good for opaque jurisdictions) |
| **Sayari Graph** | Beneficial-ownership graph across 150+ jurisdictions |
| **Kharon** | Sanctions / PEP screening with corporate networks |
| **Quantexa** | Financial-crime entity resolution |
| **Castellum.AI** | Sanctions / regulatory monitoring |
| **Liferaft Navigator** | Threat / executive protection |
| **Brand24, Mention, Talkwalker** | Brand-monitoring (also OSINT-lite) |
| **Hunchly** | Capture / evidence chain for OSINT — see [[Browser_Extensions#Capture & Note-Taking]] |

---

## Free / Open-Source Detective-Style Tools

> When you're starting out and don't have $20k for Accurint:

- **OSINT Framework** ([osintframework.com](https://osintframework.com/)) — categorised tool launcher
- **IntelTechniques Tools** — Bazzell's free web tools
- **Maltego CE** — graph-based, free tier
- **SpiderFoot** — open-source automation
- **Recon-ng** — modular framework, see [[Tools_Kali_Tracelabs#Search-Engine Recon Frameworks]]
- **Sherlock / Maigret** — username enum, see [[Tools_Kali_Tracelabs#Username Enumeration]]
- **theHarvester / Amass** — domain/email harvesting
- **Hunchly** — capture (paid licence required, but standard analyst spend)
- **Bellingcat's Online Investigation Toolkit** ([bellingcat.com/resources](https://www.bellingcat.com/resources/))
- **SANS OSINT Cheat Sheet**
- **OSINT Industries** — paid selector-pivoting, generous free tier

---

## Toolkit Recipes (combinations)

### "Brand-protection / executive protection"
- ZeroFox or Liferaft + commercial dark-web feed (DarkOwl / Recorded Future) + Hunchly + Maltego

### "Missing persons (TraceLabs CTF)"
- TraceLabs OSINT VM + Sherlock/Maigret + Hunchly + IntelTechniques tools — see [[Distros]]

### "Corporate due diligence"
- Sayari Graph + OpenCorporates + LexisNexis Accurint (US) or Companies House (UK) + sanctions screening (Kharon / Castellum)

### "Cybercrime threat intelligence"
- Recorded Future + Intel471 + Flashpoint + Maltego + Hunchly + Whonix VM ([[Darkweb_Forums]] methodology)

### "Skip-tracing (PI)"
- TLO / Accurint + IDI + Skopenow + court records + social media via Sherlock/Maigret

---

## See Also

- [[Tools_Kali_Tracelabs]] — Free / OS-bundled OSINT toolkit
- [[Browser_Extensions]] — In-browser counterparts
- [[Distros]] — Where many of these tools come pre-configured
- [[Social_Media_APIs]] — API access models referenced by many of the platforms above
- [[VMs_and_Compartmentalization]] — Required hygiene for many of the workflows above
- [[OSINT]] — Folder index
