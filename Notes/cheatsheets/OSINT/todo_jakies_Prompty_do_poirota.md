ROLE
You are an OSINT research assistant. I maintain a personal cybersecurity knowledge vault (Obsidian) and have a cheatsheet at Notes/cheatsheets/OSINT/Public_Databases_APIs.md that catalogues PUBLIC databases and APIs useful for OSINT investigations on people, organisations, and assets.

GOAL
Find PUBLIC databases and APIs I have likely missed or under-covered, with emphasis on people-finding (especially academic researchers, scientists, doctors, lawyers, engineers, public officials, executives, journalists, defence/aerospace personnel). Prioritise sources that:
1. Are free OR have a usable free tier
2. Are accessible programmatically (REST/GraphQL/SPARQL/OAI/bulk download), or at minimum scriptable
3. Cover specific people / entities by name, ID, or selector — not just thematic data
4. Are international (don't just give me US-centric results)

WHAT I ALREADY HAVE (don't repeat — go deeper)
- Academic: ORCID, Google Scholar, Semantic Scholar, OpenAlex, CrossRef, DataCite, OpenAIRE, CORE, BASE, arXiv, bioRxiv, medRxiv, PubMed/PMC, ClinicalTrials.gov, EU CTR, WHO ICTRP, ROR, Lens.org, Dimensions, Scopus, WoS, ResearchGate, Academia.edu, DBLP, INSPIRE-HEP, NASA ADS, SSRN, RePEc, PhilPapers, HAL, DOAJ, Retraction Watch, PubPeer, Math Genealogy
- Funders: NIH RePORTER, NSF Awards, EU CORDIS, UKRI Gateway, DFG GEPRIS, JSPS KAKEN, NSERC/CIHR/SSHRC, ARC/NHMRC, ERC, Welcome Trust, Gates
- Sanctions/UBO: OFAC SDN+Consolidated, EU/UK/UN lists, OpenSanctions, OCCRP Aleph, ICIJ Offshore Leaks, OpenOwnership, OpenCorporates, GLEIF, EU Transparency Register, OpenSecrets, FollowTheMoney, Wikidata PEP, World Bank Debarred, Interpol/Europol/FBI Wanted
- Patents: Google Patents, USPTO PatFT/PEDS/PatentsView/TESS, EPO Espacenet, WIPO PATENTSCOPE, Lens, KIPRIS, J-PlatPat, TMView
- Courts: PACER, CourtListener/RECAP, Justia, Harvard CAP, BAILII, CanLII, AustLII, WorldLII, EUR-Lex/CURIA, HUDOC, ICC/ICTR/ICTY
- Maritime/Aviation: MarineTraffic, VesselFinder, Equasis, IMO GISIS, OpenSky, ADS-B Exchange, FlightAware, FAA Aircraft Registry, NHTSA vPIC
- Leaks/Investigative: DDoSecrets, WikiLeaks, GDELT, MediaCloud, Common Crawl, Pushshift/Arctic Shift, OSM/Overpass
- Crypto: Etherscan, Blockchair, Mempool.space, Chainabuse, Wallet Explorer, OXT
- Identity: Wikidata SPARQL, VIAF, ISNI, GeoNames, WorldCat
- Country-specific corporate registries are covered separately per country (KRS, Companies House, Handelsregister, KVK, CNPJ, MCA21, ASIC, etc.) — only mention if there's a powerful CROSS-JURISDICTION aggregator I'm missing.

WHAT I WANT YOU TO FIND
For each of these categories, list databases / APIs I have NOT covered, with depth across non-US jurisdictions:

1. **Academic / scholarly people-finding** — anything beyond what's listed: discipline-specific corpora (chemistry SciFinder open subsets, engineering IEEE Xplore tier, social-science Sociological Abstracts open replacements), national thesis registries (DART-Europe, NDLTD, ProQuest open subsets, Theses.fr, DissOnline, CINECA Italy, OATD), conference programme-committee scrapers, editorial-board scrapers, Sci-Hub / OpenAccessButton metadata, peer-review-tracking services (Publons/Web of Science Reviewer Recognition successor), grant-application databases beyond the 12 funders I listed (per-country research councils worldwide), academy/society membership rosters (NAS, Royal Society, CNRS, Max Planck — public fellow lists), Nobel/Turing/Fields/Abel laureate registries, university faculty directory aggregators
2. **Professional licensing & accreditation** — lawyers (per-jurisdiction bar lookups + cross-aggregators), doctors (NPI, GMC, equivalents per country — give me a complete EU+G20 list), engineers (PE registries), accountants (CPA), architects, teachers, financial advisers (FINRA BrokerCheck, FCA register, BaFin, KNF, equivalents), pilots (FAA airman registry, EASA), maritime crew, real-estate agents
3. **Education / degree verification** — accredited institution registries, degree-verification consortia (CHEA, ENIC-NARIC, China CHSI / CSSD), diploma-mill warning lists
4. **Charity / non-profit / foundation registries** — IRS 990 (ProPublica Nonprofit Explorer), UK Charity Commission, Scottish/NI equivalents, Australian ACNC, Canadian CRA, French RNA, German Vereinsregister, etc. — give me as complete a global list as possible
5. **Lobbying / influence** beyond what I have — national lobbying registries worldwide
6. **Procurement / public contracts** — TED (EU), SAM.gov, UK Contracts Finder, Polish BZP, German TED-equivalent, Australian AusTender, Canadian Buyandsell, Brazilian ComprasNet, Indian GeM — and any cross-jurisdiction aggregators (OpenContracting, Open Procurement EU)
7. **Trade / customs** — public bill-of-lading (US import data, ImportGenius open subset, Indian SEAIR open subset, Russian customs, Argentine Aduana), AIS-derived port-call data
8. **Defence / arms-export / dual-use licensing** — public portions: SIPRI Arms Transfers, US DDTC/AECA registers, UK ECJU, EU dual-use licences, German BAFA, Wassenaar info
9. **Real-estate & land registries** with cross-jurisdiction or surprising-coverage angle (UK Land Registry price-paid, Polish EKW partial, Dutch Kadaster, Sweden Lantmäteriet, FBI/FinCEN beneficial-ownership real-estate orders, Geographic-info real-estate aggregators)
10. **Spectrum / radio / amateur licences** — FCC ULS, Ofcom WTR, UKE Polish, EU equivalents, ham-radio QRZ-style aggregators
11. **Conference / event attendee data** — Eventbrite/Sched/Whova public pages, Schedule.com, conference proceedings sites with attendee rosters, programme-committee aggregators
12. **People-search & breach data** that's free / freemium and ETHICAL (HaveIBeenPwned-tier, Dehashed free tier, IntelX free tier, leak-lookup.com, Snusbase free, BreachDirectory) — list only those with documented free APIs, plus what each restricts
13. **Government FOIA / freedom-of-information request portals** worldwide — MuckRock (US), WhatDoTheyKnow (UK), FragDenStaat (DE), AsktheEU, Australian RTI, Mexican INAI, Brazil Acesso à Informação
14. **Cross-jurisdiction WHOIS / domain / cert** beyond the standard (RDAP servers, ICANN CZDS, DNS Coffee, Censys Universal Internet Dataset, Rapid7 Open Data, Common Crawl host index)
15. **Image / visual** — public face-search (PimEyes-class) with documented APIs, reverse-image with API access (Yandex via SerpAPI, TinEye API, SauceNAO, Karma Decay), image-EXIF cloud services
16. **Niche but high-value** — anything I clearly missed: think tank rosters, journalist directories (IFCN, Forbidden Stories, OCCRP member orgs), gov-employee rosters (USAJobs Federal Employee Viewer / FedScope, UK senior-civil-servant pay-band publications), military officer published-rosters (US DOPMA, defence ministry annual reports), aviation-incident NTSB/AAIB/BFU databases (often name PIC), corporate-officer "register of disqualified directors" per jurisdiction

OUTPUT FORMAT (important — match this exactly so I can paste back into my Markdown cheatsheet)
For each new source, give me one row in this Markdown table format, grouped under H2 headings that match my existing categories above:

| **Source name** ([url](url)) | Coverage in 8–20 words | Free API? Y/N + key/auth notes | One-line OSINT use-case |

After each grouped table, add a 2–4 line "patterns" paragraph describing how a researcher would chain these sources together for a person-target investigation.

CONSTRAINTS
- Deduplicate against the "WHAT I ALREADY HAVE" list above. Do not repeat anything I already have.
- Only include sources that are still alive as of your latest knowledge — note any that recently went paid / shut down / restricted (post-2023) so I don't waste time on them.
- Skip pure social-media APIs — I have a separate file for those.
- Skip country-specific company registries — I have those per-country.
- Be honest about access friction: "free but registration required", "academic-affiliation gated", "key by email only", "rate-limited to N/day".
- If you don't know a source's current status, say so rather than guess.
- Aim for at least 60 new sources across all categories combined. Quality > quantity, but I want breadth.

DELIVERABLE
A single Markdown document I can paste under the "Stub: things to add" section of Public_Databases_APIs.md.