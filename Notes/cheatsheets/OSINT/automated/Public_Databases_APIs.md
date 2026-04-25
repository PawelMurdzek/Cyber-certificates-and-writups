# Public Databases & APIs for OSINT — Programmatic Access

Cross-cutting catalogue of **public databases with documented programmatic access** (REST / GraphQL / SPARQL / OAI-PMH / bulk download / RSS). Most have free tiers or are entirely free for non-commercial / journalistic use.

> **Scope:** this file lists sources you can query *as a computer* — script-friendly. **Web-only / UI-only sources moved to** [[Public_Databases_Web]] (in `manual/`). If a source has both a UI and an API, only the API row appears here.

Companion files:
- [[Public_Databases_Web]] (in `manual/`) — UI-only sources, manual lookup workflow
- [[OSS_Tools]] — open-source tooling that consumes these APIs
- [[Tools_Kali_Tracelabs]] — CLI tooling organised by selector
- [[Commercial_Tools]] — paid / vetted-access counterparts
- Country / regional pages under `manual/regional/` for jurisdiction-specific registries

> **Free-tier note:** Some databases are unrestricted; others require academic affiliation, an API key, or a journalist credential. Free-tier limits change — verify before relying on them in a live investigation.

---

## Academic & Scholarly (the people-finding angle)

> Researchers, academics, and scientists leave an exceptionally rich open footprint: papers, affiliations, co-author networks, ORCIDs, grant numbers, conference attendance. For target profiles in academia, government R&D, defence research, or biotech, **start here before social media**.

| Source | Coverage | API | Use for |
|:-------|:---------|:----|:--------|
| **ORCID** ([orcid.org](https://orcid.org/)) | Researcher identity registry — name, affiliations, employment history, education, publications, peer-review activity | Free public API + OAuth | Person → all known publications + employer chain |
| **Semantic Scholar** ([semanticscholar.org](https://www.semanticscholar.org/)) | 200M+ papers, AI-extracted entities, citation context | Free API, generous rate limits | Programmatic paper / author search, influential-citation analysis |
| **OpenAlex** ([openalex.org](https://openalex.org/)) | Open replacement for Microsoft Academic — works, authors, institutions, concepts | Free, no key for ≤10 req/s | Bulk academic graph queries, ROR-mapped institutions |
| **CrossRef** ([crossref.org](https://www.crossref.org/)) | DOI registration agency — metadata for ~150M scholarly works | Free REST API | Resolve DOI → authors, affiliations, funders, ORCID |
| **DataCite** | DOIs for datasets, software, samples | Free API | Find research datasets and software releases tied to a person |
| **OpenAIRE** ([openaire.eu](https://www.openaire.eu/)) | EU-funded research, projects, grants, datasets | Free API | Track EU Horizon / FP7 funding to PI / institution |
| **CORE** ([core.ac.uk](https://core.ac.uk/)) | Largest open-access full-text aggregator | Free API key | Full-text search where Scholar only gives snippets |
| **BASE** ([base-search.net](https://www.base-search.net/)) | 400M+ open-access docs, Bielefeld | OAI-PMH | Repository-level search, theses |
| **arXiv** | Pre-prints in physics, math, CS, q-bio, q-fin, stat | Free OAI / REST API | Pre-publication research, often more current than peer-reviewed |
| **bioRxiv / medRxiv** | Bio + medical pre-prints | Free API | Same, life-sciences |
| **PubMed / PMC** | Biomedical literature, full-text in PMC | E-utilities API (NCBI), free | Medical research, clinicians, pharma authors |
| **PubMed Central (PMC)** | Open-access full text subset of PubMed | Same E-utilities | Full-text mining |
| **ClinicalTrials.gov** | US-registered clinical trials, PIs, sponsors, sites | Free API | Trial PIs, sponsors, sites — pharma OSINT, conflicts of interest |
| **EU CTR (Clinical Trials Register)** | EU clinical trials | Bulk XML download | EU-side equivalent (UI lookup → [[Public_Databases_Web]]) |
| **GRID / ROR** ([ror.org](https://ror.org/)) | Research Organisation Registry — institutional IDs | Free API | Disambiguate "MIT" vs "Manchester Institute of Tech" — links to all affiliated researchers |
| **ROR-affiliated lookup** | Institution → researchers via OpenAlex | OpenAlex | Map every researcher at a target institution |
| **Lens.org** | Patents + scholarly works in one graph (free for non-commercial) | Free + paid API tiers | **Best free patent/paper crossover** — researcher-to-patent link |
| **Dimensions.ai** | Scholarly + patents + grants + clinical trials | Free for academic; commercial API | Comprehensive but gated for commercial |
| **Scopus / Web of Science** | Premier paid citation indices | Paid API (institutional) | Better than Scholar for citation metrics if you have access |
| **DBLP** ([dblp.org](https://dblp.org/)) | Computer science bibliography, exhaustive | Free API | CS-specific author + co-author graph |
| **INSPIRE-HEP** | High-energy physics literature | Free API | Particle physics / HEP community |
| **NASA ADS** | Astronomy + astrophysics | Free API | Astro-specific, also covers physics overlap |
| **RePEc / IDEAS** | Economics literature, author profiles | Free + scrapable | Economist profiles, central-bank research |
| **HAL** | French national open archive | Free OAI | French researchers, theses |
| **DOAJ** | Directory of Open Access Journals | Free API | Journal credibility checks |
| **Retraction Watch Database** | Retracted papers, fraud, misconduct | Free CSV / API | Misconduct flags on a target |
| **PubPeer** | Post-publication peer review, fraud allegations | Free API | Same — open allegations, image manipulation cases |

### Patterns for academic-target OSINT
1. **Name → ORCID → all affiliations + grant numbers** (gateway selector for academia).
2. **ORCID → CrossRef / OpenAlex → co-author graph** (network).
3. **Co-authors → institutional ROR → conferences / programme committees** (events they attended).
4. **Funder name + grant number → funding-body database** (NIH RePORTER, NSF Awards, UKRI Gateway, EU CORDIS).
5. **Patents (Lens / Espacenet / Google Patents) → assignee company** (academia ↔ industry bridge).

### Funding-body databases (researcher → grant → money trail)

| Source | Coverage |
|:-------|:---------|
| **NIH RePORTER** | All NIH-funded research, PI, dollar amounts |
| **NSF Awards** | National Science Foundation grants |
| **EU CORDIS** | All EU framework programme projects (FP7, H2020, Horizon Europe) |
| **UKRI Gateway to Research** | UK research-council funding |
| **DFG GEPRIS** | German DFG-funded projects |
| **JSPS KAKEN** | Japanese research grants |
| **NSERC, CIHR, SSHRC** | Canadian tri-council |
| **ARC, NHMRC** | Australian research council, medical |
| **DARPA / IARPA** | US defence research — partly public |
| **ERC Project Database** | European Research Council |
| **Welcome Trust Grants** | Biomedical philanthropy |
| **Gates Foundation** | Searchable grants DB |

---

## Sanctions, PEP, Watchlist & Beneficial Ownership

| Source | Coverage | API | Notes |
|:-------|:---------|:----|:------|
| **OFAC SDN List** (US Treasury) | US sanctions | Free CSV / SDN.XML | Authoritative US list |
| **OFAC Consolidated** | All non-SDN US sanctions lists | Free | |
| **EU Consolidated Financial Sanctions List** | EU sanctions | Free download | XML/CSV |
| **UK OFSI Consolidated List** | UK sanctions | Free CSV | Post-Brexit divergence from EU |
| **UN Consolidated Sanctions List** | UN Security Council sanctions | Free XML | Cross-jurisdiction baseline |
| **OpenSanctions** ([opensanctions.org](https://www.opensanctions.org/)) | **Aggregates 200+ lists** — sanctions, PEP, criminals, debarred | Free + commercial API | Single best free entrypoint, deduplicated entities |
| **OpenSanctions Yente** | Self-host OpenSanctions matching API | Open source | Privacy-preserving on-prem screening |
| **WikiData PEP queries** | Politically-exposed persons via SPARQL | Free SPARQL | Useful when name is generic |
| **World Bank Debarred Firms** | Firms banned from WB-funded projects | Free | Procurement integrity |
| **FBI Wanted** | US wanted persons | Web + RSS feeds per category | Per-list scraping; UI lookup → [[Public_Databases_Web]] |
| **Offshore Leaks Database (ICIJ)** ([offshoreleaks.icij.org](https://offshoreleaks.icij.org/)) | Panama / Paradise / Pandora / Bahamas / Offshore Leaks | Free web search + bulk CSV | Beneficial-ownership leaks, 800k+ entities |
| **OCCRP Aleph** ([aleph.occrp.org](https://aleph.occrp.org/)) | Investigative-journalism dataset hub: registries, leaks, court docs | Free API (key required) | **Single best free investigative DB** |
| **OpenOwnership Register** ([register.openownership.org](https://register.openownership.org/)) | Beneficial-ownership data from UK PSC + open jurisdictions | Free API | UBO graph |
| **PEP database (Wikidata-derived)** | Open PEP via Wikidata classes | SPARQL | Free alternative to commercial PEP feeds |
| **OpenCorporates** ([opencorporates.com](https://opencorporates.com/)) | 200M companies across 140 jurisdictions | Free + paid API | Company graph; some reconciliation requires paid |
| **GLEIF (LEI)** ([gleif.org](https://www.gleif.org/)) | Legal Entity Identifier — global ID for legal entities | Free download / API | Cross-jurisdiction company canonical ID |
| **EU Transparency Register** | Lobbyists registered with EU institutions | Free CSV | Lobbyist OSINT |
| **US LDA Lobbying Disclosures** | US federal lobbying | Free download | |
| **OpenSecrets** | US campaign-finance + lobbying | Free API | |
| **FollowTheMoney (NIMP)** | US state-level campaign finance | Free | |

---

## Patents & Intellectual Property

| Source | Coverage | API | Notes |
|:-------|:---------|:----|:------|
| **Google Patents** | Global patents, full text + machine translation | Web only (BigQuery dataset for bulk) | **Best free UX**, indexes most jurisdictions |
| **USPTO PatFT / AppFT** | US issued + applications | Bulk download + PEDS API | Authoritative US |
| **USPTO PEDS** | Patent application status, file wrapper | Free API | Prosecution history |
| **EPO Espacenet** | European Patent Office, 130M+ patents | Free + OPS API | Family search across jurisdictions |
| **WIPO PATENTSCOPE** | International PCT applications | Free API | Earliest-filing layer |
| **Google Patents Public Datasets** (BigQuery) | Bulk SQL on global patents | Free tier in BigQuery | Best for graph / co-inventor / assignee analysis |
| **Lens.org** | Patents + papers + collections | Free for non-commercial | Cross-link patents ↔ scholarly articles |
| **PatentsView** | USPTO bulk + APIs for inventor / assignee disambiguation | Free | Inventor identity resolution |
| **Korea KIPRIS** | Korean patents | Free API | |
| **J-PlatPat** | Japanese patents | Free API | |
| **TMView / Designview** | EU+ trademark + design search | Free | |
| **USPTO TESS** | US trademarks | Free | Trademark → entity |

---

## Court Records & Litigation

| Source | Coverage | Notes |
|:-------|:---------|:------|
| **PACER (US Federal)** | All US federal cases | $0.10/page, free public terminals; **CourtListener / RECAP** mirror is free for documents already pulled |
| **CourtListener / RECAP** ([courtlistener.com](https://www.courtlistener.com/)) | Free PACER mirror, opinions, oral arguments | Free API |
| **Harvard Caselaw Access Project** | 6.7M US cases, complete | Free API |
| **EUR-Lex / CURIA** | EU legislation + Court of Justice | Free SPARQL + REST APIs |
| **Justice.cz, Pappers, KRS** etc. | National registries — see country pages |

> Web-only court portals (Justia, BAILII, CanLII, AustLII, WorldLII, HUDOC, ICC/ICTR/ICTY archives, US state per-county portals) → [[Public_Databases_Web]].

---

## Maritime, Aviation & Vehicle

| Source | Coverage | Notes |
|:-------|:---------|:------|
| **MarineTraffic** | Live + historical AIS | Free API tier (limited), paid for history |
| **VesselFinder** | Same as above | Free API tier |
| **OpenSky Network** | Academic ADS-B, free history | Free for research |
| **ADS-B Exchange** | Uncensored aircraft tracking (incl. blocked tail numbers) | Free + paid API |
| **FlightAware** | Flight tracking | Free API tier |
| **VIN-decoder APIs** (NHTSA vPIC) | US VIN decoding | Free |
| **MMSI lookup (ITU)** | Marine MMSI → vessel | Free |
| **Hexcode → ICAO 24-bit registry mapping** | Aircraft ID resolution | Free |
| **Nautical Almanac, Time and Date** | Sun, tides, daylight — geolocation use | Free |

---

## Datasets, Leaks & Investigative Hubs

| Source | What | API |
|:-------|:-----|:----|
| **OCCRP Aleph** | Aggregator of leaks, registries, court records | Free API key |
| **ICIJ Offshore Leaks DB** | Panama / Paradise / Pandora / Bahamas / Offshore Leaks | Free + bulk CSV |
| **Internet Archive Datasets** | archive.org datasets section, BookSearch, Wayback CDX | Free APIs |
| **Wayback CDX API** | Time-machine programmatic search | Free |
| **GDELT** | Global news event data, multilingual | Free, BigQuery |
| **MediaCloud** | Global news media analysis | Free API, account |
| **Common Crawl** | Petabytes of crawled web | Free in S3 |
| **OpenStreetMap (Overpass API)** | Map features, POIs, infrastructure | Free |
| **OSM Wiki + Taginfo** | Tag schema, POI types | Free Taginfo API |

> Web-only / closed leak archives (WikiLeaks, DDoSecrets magnet index, Pushshift mirrors, Bellingcat OIT) → [[Public_Databases_Web]].

---

## News, Archive & Press

| Source | Coverage |
|:-------|:---------|
| **Wayback Machine (CDX API)** | Web archive — programmatic snapshots via CDX API |
| **NewsAPI / GNews / Mediastack** | Aggregator APIs, free tiers |
| **GDELT 2.0 GKG** | Global Knowledge Graph of news entities |
| **MediaCloud** | Multilingual news source analysis |

> Web-only archives (Wayback Machine UI, archive.today, Internet Archive TV News, national broadcaster archives) → [[Public_Databases_Web]].

---

## Health & Medical Public Records

| Source | Coverage |
|:-------|:---------|
| **ClinicalTrials.gov** | US + many international trials (PIs, sponsors) |
| **EU Clinical Trials Register** | EU equivalent |
| **WHO ICTRP** | Cross-jurisdiction meta |
| **OpenPaymentsData (CMS)** | US doctor → pharma payment records |
| **NHS England Open Data** | NHS spending, prescribing, GP records (de-id) |
| **NPI Registry (CMS)** | All US healthcare providers |
| **State medical-licensing boards** | Per-state US |
| **GMC (UK), Bundesärztekammer, etc.** | National regulators |

---

## Crypto & Blockchain

| Source | Use |
|:-------|:----|
| **Block explorers** (Etherscan, Mempool.space, Blockchair) | Free address / tx lookup |
| **Blockchair** | Multi-chain explorer + API |
| **Chainabuse** | Community-reported scam addresses |
| **ScamSniffer / GoPlus** | Address risk-scoring |
| **OFAC SDN crypto address list** | US-sanctioned wallets |
| **Wallet Explorer / OXT (Bitcoin)** | BTC clustering heuristics |
| **WhaleAlert** | Large-tx feed |
| **DeBank / Zapper** | Wallet portfolio across chains |
| **Sanctioned-address lists** | OpenSanctions includes these |

> Commercial-grade attribution (Chainalysis, TRM, Elliptic) lives in [[Commercial_Tools]].

---

## Government Open-Data Portals

A starting set — most countries have one. Search "{country} open data portal" if missing here. Country-specific registries live on the relevant country page.

| Portal | Country |
|:-------|:--------|
| **data.gov** | USA |
| **data.gov.uk** | UK |
| **data.europa.eu** | EU consolidated |
| **data.gouv.fr** | France |
| **GovData** | Germany |
| **dane.gov.pl** | Poland |
| **data.gov.au** | Australia |
| **data.gc.ca** | Canada |
| **e-Stat** | Japan |
| **dados.gov.br** | Brazil |
| **datos.gob.mx** | Mexico |
| **NHS England Open Data** | UK NHS-specific |
| **data.world** | Community-uploaded datasets |
| **Kaggle Datasets** | Same |
| **Hugging Face Datasets** | ML-oriented but contains many OSINT-relevant releases |

---

## Identity & Identifier Resolution

| Source | Resolves |
|:-------|:---------|
| **WikiData SPARQL** | Person / org / place → cross-IDs (ORCID, ISNI, VIAF, IMDb, Twitter, …) |
| **ISNI** | International Standard Name Identifier — bulk dumps + lookup API |
| **GeoNames** | Place-name → coordinates + variants — free API |
| **CitizenDB / Wikidata People** | People linked to public IDs — SPARQL |
| **Crossref Funder Registry** | Funder name disambiguation — free API |

> Web-only authority files (VIAF, WorldCat) → [[Public_Databases_Web]].

---

## Stub: things to add (research with the prompt below, then fill in)

- Per-country FOIA / public-records request portals
- Educational accreditation databases (degree verification)
- Professional licensing (engineers, lawyers, accountants — per jurisdiction)
- Real-estate / land registries beyond country pages
- Charity / non-profit registries (IRS Form 990, UK Charity Commission, etc.)
- Trade / customs data (Panjiva, ImportGenius — partly paid)
- Procurement portals (TED EU, SAM.gov, UK Contracts Finder, Polish BZP)
- Conference programme committees / speaker rosters (research events)
- Defence / arms-export licensing data
- Spectrum / radio licensee databases (FCC ULS, Ofcom, UKE)

---

## See Also

- [[OSINT]] — Folder index
- [[Public_Databases_Web]] (in `manual/`) — UI-only / manual-lookup companion
- [[OSS_Tools]] — Tooling that consumes these APIs
- [[Tools_Kali_Tracelabs]] — Selector-organised tooling
- [[Commercial_Tools]] — Paid alternatives where free tiers don't reach
- [[Social_Media_APIs]] — Platform APIs (separate file because of scale)
- Country pages under `manual/regional/` for jurisdiction-specific registries
