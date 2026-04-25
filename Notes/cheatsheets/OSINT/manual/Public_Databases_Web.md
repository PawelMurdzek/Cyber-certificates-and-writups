# Public Databases — Web-Only / Manual Lookup

Companion to [[Public_Databases_APIs]] (in `automated/`). This page collects sources that have **no documented free API** — you query them through a browser, sometimes after registration. Useful when working a single target by hand, in a sock-puppet browser, or when the automated counterpart is gated.

> **Scope:** entries are limited to publicly accessible web interfaces. If a source has both a UI and an API, the **API row lives in [[Public_Databases_APIs]]** — this file only lists the UI-only / scraping-required cases.

---

## Academic & Scholarly (web-only)

| Source | Coverage | Access notes |
|:-------|:---------|:-------------|
| **Google Scholar** ([scholar.google.com](https://scholar.google.com/)) | Citation graph, near-complete academic index, author profiles | No official API. SerpAPI (paid) or `scholarly` Python lib (scrapes, ToS-grey) |
| **WHO ICTRP** ([trialsearch.who.int](https://trialsearch.who.int/)) | Global clinical-trial meta-registry | Web search only |
| **ResearchGate** ([researchgate.net](https://www.researchgate.net/)) | Researcher social network | No public API; scraping ToS-violating |
| **Academia.edu** ([academia.edu](https://www.academia.edu/)) | Same idea, more humanities | No public API |
| **Mathematics Genealogy Project** ([mathgenealogy.org](https://www.mathgenealogy.org/)) | PhD advisor / advisee tree | Web only — academic lineage |
| **SSRN** ([ssrn.com](https://www.ssrn.com/)) | Social-science pre-prints | Web only |
| **PhilPapers** ([philpapers.org](https://philpapers.org/)) | Philosophy papers + author directory | Web only — niche but exhaustive |
| **Beall's List (archive)** | Predatory journal lists | Web archive only |
| **Microsoft Academic** | **Discontinued 2021** — replaced by OpenAlex | (legacy reference, no live UI) |

**Manual workflow:** Google Scholar → author profile page → click each paper for citing-paper count → manually browse co-authors → cross-check with ResearchGate / Academia.edu for additional affiliations and "requested copies" links (which sometimes leak collaborator emails).

---

## Sanctions, PEP & Wanted-Person Lookups (web-only)

| Source | Coverage | Access notes |
|:-------|:---------|:-------------|
| **Interpol Red Notices** ([interpol.int/notices](https://www.interpol.int/How-we-work/Notices/Red-Notices)) | Wanted persons (excl. political/military) | Web only, no bulk download |
| **Europol Most Wanted** ([eumostwanted.eu](https://eumostwanted.eu/)) | EU equivalent | Web only |
| **FBI Wanted** ([fbi.gov/wanted](https://www.fbi.gov/wanted)) | US wanted persons | Web + RSS feeds per category |

**Manual workflow:** name → check all three sequentially. Interpol Red Notices include passport numbers and DOB; Europol pages link to national investigators; FBI Wanted includes Wanted Posters with detailed images useful for face match.

---

## Court Records (web-only)

Most national / appellate court systems publish judgments online but offer no API. Programmatic mirrors (CourtListener, Harvard CAP) live in [[Public_Databases_APIs]].

| Source | Jurisdiction |
|:-------|:-------------|
| **Justia** ([justia.com](https://www.justia.com/)) | US case law, dockets, lawyer directory |
| **BAILII** ([bailii.org](https://www.bailii.org/)) | UK + Ireland case law |
| **CanLII** ([canlii.org](https://www.canlii.org/)) | Canadian case law |
| **AustLII** ([austlii.edu.au](https://www.austlii.edu.au/)) | Australian + Pacific case law |
| **WorldLII / CommonLII / AsianLII** | Federated free case-law search across LIIs |
| **HUDOC** ([hudoc.echr.coe.int](https://hudoc.echr.coe.int/)) | European Court of Human Rights case law |
| **ICC / ICTR / ICTY archives** | International criminal tribunals |
| **State court portals (US)** | Highly fragmented; per-county portals — see country page |

**Manual workflow:** name → BAILII for Commonwealth → CanLII / AustLII for parallel jurisdictions → Justia for US (with PACER paid for federal docket detail; CourtListener API is the free mirror — see `automated/`).

---

## Maritime, Aviation & Vehicle (web-only)

| Source | Coverage | Access notes |
|:-------|:---------|:-------------|
| **ShipSpotting** ([shipspotting.com](https://www.shipspotting.com/)) | Crowdsourced ship photos | Free, useful for visual ID |
| **Equasis** ([equasis.org](https://www.equasis.org/)) | Ship safety + ownership records | Free, registration required |
| **IMO GISIS** ([gisis.imo.org](https://gisis.imo.org/)) | IMO ship database, port-state control | Free, registration required |
| **FAA Aircraft Registry** ([registry.faa.gov](https://registry.faa.gov/)) | US aircraft owner search | Free web search |
| **National civil-aviation registries (EASA-side)** | Per-country registry portals | Free, varies per jurisdiction |

**Manual workflow:** vessel name or IMO number → MarineTraffic UI (free tier) for live position → Equasis for ownership chain → ShipSpotting for visual confirmation of repaint / re-flag → IMO GISIS for sanctions / port-state-control history.

---

## Leaks, Investigative Hubs & Archives (web-only)

| Source | Coverage | Access notes |
|:-------|:---------|:-------------|
| **WikiLeaks** ([wikileaks.org](https://wikileaks.org/)) | Historic + current leaks | Web archive |
| **DDoSecrets** ([ddosecrets.com](https://ddosecrets.com/)) | Leaked datasets, journalist-grade | Magnet links + web index, no query API |
| **Bellingcat Online Investigation Toolkit** ([bellingcat.com/resources](https://www.bellingcat.com/resources/)) | Curated dataset + tool list | Free web |
| **archive.today** ([archive.ph](https://archive.ph/)) | Single-snapshot web archive | Web only, less censorable than Wayback |
| **Pushshift mirrors** | Reddit history archive — **mostly closed since 2023**, partial via Arctic Shift | Limited / web-only mirrors |
| **Internet Archive TV News Archive** ([archive.org/details/tv](https://archive.org/details/tv)) | Searchable broadcast TV transcripts | Web only |

**Manual workflow:** if a target has been leaked → DDoSecrets index by collection → cross-reference with WikiLeaks search → archive.today snapshot of any deleted target page → Wayback Machine UI for time-travel browsing (CDX API for bulk lives in `automated/`).

---

## Identity Resolution (web-only)

| Source | Coverage | Access notes |
|:-------|:---------|:-------------|
| **VIAF** ([viaf.org](https://viaf.org/)) | Authority file — author identity across libraries | Web search; bulk dumps exist |
| **WorldCat** ([worldcat.org](https://worldcat.org/)) | Library holdings — books, authored works | Web only (legacy paid SRU API discontinued) |

**Manual workflow:** author name → VIAF cluster → cross-IDs (LCNAF, GND, BNF, ISNI) → WorldCat to find which libraries hold their works → narrows institutional affiliation history.

---

## See Also

- [[Public_Databases_APIs]] (in `automated/`) — full catalogue including programmatic / API-accessible sources
- [[Commercial_Tools]] — paid alternatives where free tiers don't reach
- [[Browser_Extensions]] — capture / OPSEC extensions for manual browsing sessions
- [[Sock_Puppet_Recipes]] — persona setup before logging into registered sites (Equasis, IMO GISIS, ResearchGate)
- [[OSINT]] — folder index
