# Bytewall Academy — Full Roadmap
### Complete Topic-by-Topic Breakdown | All 18 Stages

> This document is the master index of every topic covered across the entire roadmap.
> Use it as a reference, a progress tracker, and a study checklist.

---

## STAGE 00 — Foundations

### 0.1 Hardware Fundamentals
- CPU architecture, rings, privilege levels, speculative execution (Spectre/Meltdown)
- RAM, DRAM, cold boot attacks, Rowhammer, memory forensics
- ROM, firmware storage, UEFI rootkits, firmware attack surface
- GPU and password cracking (Hashcat)
- Motherboard components, Intel ME, PCIe DMA attacks, PCILeech
- Storage: HDD forensics, SSD TRIM/wear levelling, NVMe, self-encrypting drives
- BIOS/UEFI, Secure Boot, TPM, measured boot, BitLocker key sealing
- Power supply, power analysis side-channels (DPA), voltage glitching, ChipWhisperer
- Physical security: layered controls, evil maid attack, data centre security, OT physical security

### 0.2 Operating System Fundamentals
- What an OS is, kernel architecture types (monolithic, microkernel, hybrid)
- Kernel responsibilities, kernel modules, BYOVD attacks
- User mode vs kernel mode, privilege rings, local privilege escalation
- Windows integrity levels, PPL, SMEP/SMAP
- Processes, threads, process creation, process injection techniques
- Scheduling, race conditions, TOCTOU vulnerabilities, Dirty COW
- File systems: NTFS (MFT, ADS, timestamps, ACLs), ext4 (inodes, permissions, SUID/SGID), FAT32
- Memory management: virtual memory, pages, ASLR, NX/DEP, ROP chains
- Heap memory, use-after-free, heap overflow
- System calls, strace/API Monitor, seccomp, direct syscall evasion

### 0.3 Windows Fundamentals
- Windows NT architecture: ntoskrnl, ntdll, csrss, lsass, winlogon
- Session model, WOW64, Heaven's Gate technique
- Registry structure, hives, critical security keys (Run, SAM, ShimCache, AmCache)
- Registry-based fileless malware, COM hijacking
- SIDs, built-in accounts, RID 500, access tokens, token impersonation
- Potato attacks (Juicy/Rotten/Sweet), SeImpersonatePrivilege
- Windows services, svchost.exe, unquoted service paths, weak binary permissions
- Task Manager, Event Viewer, critical Event IDs (4624, 4625, 4648, 4698, 1102...)
- Logon types and lateral movement detection
- Windows Defender, AMSI, ASR rules, exclusion abuse
- UAC, integrity levels, UAC bypass techniques (fodhelper, sdclt, eventvwr)
- Windows Firewall, WFP architecture, firewall rule manipulation
- PowerShell: execution policy bypass, download cradles, encoded commands, script block logging
- CMD: reconnaissance commands, LOLBins, service/task manipulation
- Task Scheduler as persistence: creation, detection, evasion
- Windows Update, WSUS HTTP attack, patch management

### 0.4 Linux Fundamentals
- Linux distributions, terminal usage, file system hierarchy (FHS)
- Core commands: ls, cd, cp, mv, rm, mkdir, cat, grep, find, chmod, chown
- File permissions: rwx, octal notation, SUID/SGID/Sticky bit, GTFOBins
- User management: useradd, passwd, sudo, /etc/passwd, /etc/shadow
- Package management: apt, yum, dnf
- Service management: systemctl, service
- Cron jobs and cron-based persistence
- Bash scripting fundamentals for security automation
- Linux log system: /var/log, syslog, auth.log, journalctl
- SSH: key-based auth, config hardening, tunnelling
- /proc filesystem as intelligence source
- SELinux and AppArmor basics

### 0.5 Programming Fundamentals
- Variables, data types, type conversion
- Loops, conditionals, flow control
- Functions, scope, recursion
- Error handling and exceptions
- File read/write operations
- String operations and regex
- Basic algorithms and data structures
- Security-oriented programming mindset

---

## STAGE 01 — Network Fundamentals

### 1.1 Network Concepts
- LAN, WAN, MAN, PAN — network types
- How the internet works
- Bandwidth, latency, jitter
- Packets, frames, unicast/multicast/broadcast

### 1.2 OSI Model
- All 7 layers, their roles, and protocols at each layer
- How data encapsulation works
- Security relevance of each layer

### 1.3 TCP/IP Model
- TCP vs UDP — when and why
- TCP 3-way handshake and security implications
- IP addressing (IPv4), IPv6 basics
- ICMP, ARP

### 1.4 IP Addressing and Subnetting
- IPv4 binary, classes, CIDR
- Subnet mask calculation, VLSM
- NAT/PAT, DHCP, DNS and record types (A, AAAA, MX, CNAME, TXT, PTR)

### 1.5 Core Protocols
- HTTP/HTTPS, FTP/SFTP, SMTP/POP3/IMAP
- SSH, Telnet, SNMP, NTP, LDAP, RDP, SMB

### 1.6 Network Devices
- Hub, Switch, Router — differences and security implications
- Firewall types, IDS/IPS, Proxy, Load Balancer, WAF

### 1.7 Wireless Networks
- 802.11 standards, WEP/WPA/WPA2/WPA3
- Rogue AP, Evil Twin

### 1.8 Network Analysis Tools
- Wireshark, tcpdump, netstat, Nmap, traceroute

---

## STAGE 02 — Cybersecurity Core

### 2.1 Fundamental Concepts
- CIA Triad, AAA model, Zero Trust
- Risk, Threat, Vulnerability, Attack — precise definitions
- Defence in Depth, Least Privilege, Separation of Duties

### 2.2 Cryptography
- Symmetric (AES, 3DES), Asymmetric (RSA, ECC, DH)
- Hashing (MD5, SHA family), digital signatures
- PKI, CA, SSL/TLS handshake
- Encoding vs Encryption vs Hashing
- Salt, Pepper, padding oracle, CBC bit flipping

### 2.3 Identity and Access Management
- Password policies, MFA, biometrics
- OAuth 2.0, OpenID Connect, SAML, Kerberos, NTLM, SSO, PAM

### 2.4 Security Frameworks
- NIST CSF, ISO 27001, CIS Controls
- OWASP Top 10, MITRE ATT&CK, Cyber Kill Chain
- STRIDE, DREAD, Diamond Model

### 2.5 Legal and Compliance
- KVKK, GDPR, PCI-DSS, HIPAA
- Turkish cybersecurity legislation, BTK regulations

---

## STAGE 03 — Offense and Defense

### 3.1 Social Engineering
- Phishing, spear phishing, whaling, vishing, smishing
- Pretexting, baiting, tailgating, BEC, CEO fraud
- Watering hole, awareness training

### 3.2 Malware
- Virus, worm, trojan, ransomware, spyware, rootkit, bootkit
- RAT, keylogger, fileless malware, polymorphic/metamorphic
- Botnet, dropper, banker trojan
- Static and dynamic analysis, sandbox, YARA rules

### 3.3 Network Attacks
- MITM, ARP poisoning, DNS spoofing, SSL stripping
- Session hijacking, IP spoofing, VLAN hopping, MAC flooding
- BGP hijacking, port scanning, packet sniffing

### 3.4 DoS and DDoS
- SYN Flood, UDP Flood, HTTP Flood, Slowloris
- Amplification/reflection attacks, DDoS mitigation, CDN

### 3.5 Web Application Attacks
- SQLi (blind, error-based, time-based), XSS (reflected/stored/DOM)
- CSRF, SSRF, XXE, IDOR, path traversal, LFI/RFI
- Deserialization, SSTI, business logic vulnerabilities
- HTTP response splitting, clickjacking, web cache poisoning

### 3.6 Password Attacks
- Brute force, dictionary, rainbow table, credential stuffing
- Pass-the-Hash, Pass-the-Ticket, Kerberoasting, AS-REP Roasting
- Hashcat, John the Ripper, Hydra

### 3.7 Wireless Attacks
- WEP cracking, WPA handshake capture, PMKID
- Evil Twin, deauth, Bluetooth attacks, RFID/NFC

---

## STAGE 04 — Penetration Testing

### 4.1 Methodology
- Pentest types (black/white/grey box)
- Scoping, Rules of Engagement, legal framework
- Report writing: executive summary, technical findings, remediation

### 4.2 Reconnaissance (OSINT)
- Passive vs active recon
- Google Dorks, Shodan, Censys, WHOIS, subdomain enumeration
- theHarvester, Maltego, Recon-ng, SpiderFoot, Wayback Machine
- GitHub/Pastebin OSINT, metadata analysis

### 4.3 Scanning and Enumeration
- Nmap (port scan, NSE scripts, OS/service detection), Masscan
- SMB, SNMP, LDAP, NFS, FTP, DNS zone transfer enumeration
- Web directory brute force: Gobuster, ffuf, Dirsearch, Nikto

### 4.4 Vulnerability Analysis
- CVE, CVSS, CWE, NVD, Exploit-DB
- Nessus, OpenVAS, Nexpose
- Patch management, false positive/negative

### 4.5 Exploitation
- Metasploit Framework, msfconsole, msfvenom
- Payload types, Meterpreter
- Buffer overflow: stack, heap, SEH, format string
- Return Oriented Programming (ROP), shellcode

### 4.6 Post-Exploitation
- Persistence, privilege escalation (Linux and Windows)
- Lateral movement, Pass-the-Hash, Pass-the-Ticket
- Token impersonation, Mimikatz, data exfiltration
- Pivoting, tunnelling (Chisel, Ligolo), Living off the Land
- Anti-forensics, log wiping

### 4.7 Reporting
- Finding severity ratings (Critical/High/Medium/Low)
- CVSS scoring, risk calculation, remediation recommendations

---

## STAGE 05 — Network Security

- Packet filtering, stateful inspection, NGFW
- Firewall rule writing, DMZ design, pfSense, iptables
- IDS vs IPS, Snort, Suricata, Zeek — rule writing
- VPN types: IPSec, OpenVPN, WireGuard, SSL VPN
- VLAN design, micro-segmentation, Zero Trust network architecture
- Jump server / bastion host, network ACL
- Forward/reverse/transparent proxy, SSL inspection, Squid

---

## STAGE 06 — Web Application Security

- HTTP request/response, methods, status codes, headers, cookies
- REST API, GraphQL, WebSocket, JSON/XML
- Burp Suite (Community & Pro), OWASP ZAP, sqlmap, ffuf
- Input validation, prepared statements, output encoding
- Secure session management, secure password storage
- HTTPS, HSTS, CSP, X-Frame-Options, CORS policy
- Secure/HttpOnly/SameSite cookie flags
- Rate limiting, secure API design

---

## STAGE 07 — Active Directory Security

- Domain, Forest, Tree, Domain Controller, OU, GPO
- Kerberos and NTLM authentication deep dive
- BloodHound, SharpHound — AD enumeration and attack path analysis
- Kerberoasting, AS-REP Roasting
- Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash
- Silver Ticket, Golden Ticket, DCSync
- LLMNR/NBT-NS Poisoning (Responder), SMB Relay, NTLM Relay
- PrintNightmare, ZeroLogon, AD CS attacks
- Tiered Administration, PAW, LAPS, Credential Guard
- Protected Users group, SMB signing, AppLocker

---

## STAGE 08 — Cloud Security

- IaaS/PaaS/SaaS, shared responsibility model
- AWS: IAM, S3 security, EC2 security groups, VPC, GuardDuty, CloudTrail
- Azure: Azure AD, RBAC, Defender for Cloud, Sentinel, Key Vault
- GCP: IAM, VPC, Cloud Armor, Security Command Center
- Container security: Docker hardening, image scanning, Kubernetes RBAC
- Pod Security Policy, Network Policy, Falco runtime security
- Cloud attack techniques: misconfigured S3, IAM privesc, metadata SSRF
- Pacu, ScoutSuite, Prowler

---

## STAGE 09 — Incident Response and Forensics

- IR phases: Preparation, Detection, Containment, Eradication, Recovery, Lessons Learned
- Incident Response Plan, Runbook, Playbook, tabletop exercises
- Digital forensics principles, chain of custody
- Disk imaging: dd, FTK Imager, Autopsy
- Memory forensics: Volatility — process analysis, network artifacts, malware detection
- Windows artifacts: Prefetch, ShimCache, AmCache, Registry hives, browser forensics
- Timeline analysis, file carving, deleted file recovery, metadata analysis
- Malware analysis: static (strings, PE analysis, imports), dynamic (ProcMon, Wireshark, Regshot)
- IDA Pro, Ghidra, x64dbg — code analysis
- YARA rule writing, IOC extraction
- SIEM: Splunk, ELK Stack, Microsoft Sentinel — log analysis, correlation rules
- Key Windows Event IDs for investigation

---

## STAGE 10 — SOC Operations

- SOC architecture: L1/L2/L3, MTTD/MTTR metrics, alert fatigue
- Threat hunting: hypothesis-based, IOC-based, TTP-based, MITRE ATT&CK-driven
- CTI: strategic/operational/tactical/technical intelligence
- IOC types, STIX/TAXII, MISP, dark web monitoring, APT tracking
- SOAR: playbook automation, Splunk SOAR, Palo Alto XSOAR, TheHive

---

## STAGE 11 — System Hardening

- Windows hardening: SMBv1, RDP security, AppLocker, BitLocker, CIS Benchmark, STIG
- Linux hardening: SSH hardening, SELinux/AppArmor, Fail2ban, SUID audit, CIS Benchmark
- Network device hardening: STP security, Port Security, 802.1X, SNMP v3

---

## STAGE 12 — OT / SCADA / ICS Security ⭐

### 12.1 OT/ICS Fundamentals
- OT vs IT differences, ICS/SCADA/DCS architecture
- PLC, RTU, HMI, Historian, Engineering Workstation
- Field devices: sensors, actuators, transmitters

### 12.2 OT Protocols
- Modbus RTU/TCP, DNP3, IEC 60870-5-101/104
- IEC 61850, PROFIBUS, PROFINET, EtherNet/IP, CIP
- OPC-DA/UA, BACnet, HART, Foundation Fieldbus, RS-485/232

### 12.3 OT Security Standards
- IEC 62443, NIST SP 800-82, NERC CIP (CIP-002 to CIP-014)
- Purdue Model / PERA, ISA-99, ICS-CERT advisories

### 12.4 OT Architecture and Segmentation
- Purdue Model layers (Level 0-5)
- IT/OT integration security, DMZ in OT, data diode
- Air gap security, remote access in OT, jump server design

### 12.5 OT Vulnerabilities
- Default credentials, legacy unpatched systems
- USB/removable media risk, supply chain attacks
- Engineering workstation exposure, insider threat
- Modbus/DNP3 protocol vulnerabilities

### 12.6 Real-World OT Attacks
- Stuxnet — full analysis
- Ukraine Power Grid (2015, 2016)
- Triton/TRISIS — safety system attack
- Colonial Pipeline, Oldsmar Water Treatment
- CRASHOVERRIDE/Industroyer, BlackEnergy, Havex RAT
- APT groups targeting OT: Sandworm, Dragonfly, Lazarus

### 12.7 OT Security Tools
- Claroty, Nozomi Networks, Dragos Platform
- Microsoft Defender for IoT, Tenable.OT
- Shodan ICS search, PLCScan, GrassMarlin

### 12.8 Critical Infrastructure Sectors
- Power (generation, transmission, distribution), water/wastewater
- Oil and gas, nuclear, transportation, healthcare OT
- Smart factory (Industry 4.0), smart city, building automation

### 12.9 Electrical Sector Specific
- SCADA-based EMS and DMS
- AMI/smart grid security, PMU security
- Substation automation, RTU/IED security
- NERC CIP compliance, IEC 61850 GOOSE security

### 12.10 OT Security Operations
- Asset inventory, risk assessment, vulnerability management
- OT incident response, network forensics, OT pentest methodology

---

## STAGE 13 — Red Team Operations

- Red Team vs Pentest, adversary simulation, Purple Team
- Cobalt Strike, Brute Ratel, Sliver, Havoc C2
- C2 infrastructure: redirectors, domain fronting, DNS C2, malleable profiles
- AMSI/ETW/UAC bypass, LOLBins, macro-based attacks
- HTA, LNK, ISO, VHD payloads, GoPhish phishing campaigns
- Physical red team: lock picking, tailgating, badge cloning, Rubber Ducky, drop box

---

## STAGE 14 — Advanced Blue Team

- STRIDE/DREAD/Attack Tree threat modelling
- Defense in depth architecture, Zero Trust design
- SASE, SD-WAN security, cloud security architecture
- Honeypots (Cowrie, OpenCanary), honeynet, canary tokens

---

## STAGE 15 — Development and Automation

- Python for security: socket programming, Scapy, Requests, Paramiko
- Python: port scanner, brute force scripts, log analysis, IOC extraction
- Bash scripting for automation: log analysis, hardening scripts, backup
- PowerShell: AD management, log collection, security controls
- Security tool development: C/C++, Go, Rust
- YARA, Snort/Suricata, Sigma rule writing

---

## STAGE 16 — Advanced Topics

- Reverse engineering: x86/x64 assembly, PE/ELF format, IDA Pro, Ghidra, x64dbg
- Anti-debugging, anti-VM, packer analysis, DLL injection, process hollowing
- Exploit development: stack/heap overflow, format string, UAF, ROP, ASLR/DEP bypass
- Advanced cryptography: padding oracle, CBC flipping, RSA attacks, post-quantum crypto
- Mobile security: Android/iOS architecture, APK reversing, Frida, MobSF, OWASP Mobile Top 10
- IoT security: firmware analysis, UART/JTAG/SPI, Binwalk, embedded device attacks

---

## STAGE 17 — Certifications and Career

- Entry: CompTIA Security+, Network+, eJPT, CEH, Cisco CyberOps
- Mid: OSCP, eCPPT, CompTIA CySA+, GCIH, GCIA
- Advanced: OSCE3, OSEP, OSED, OSWE, CISSP, CISM
- OT/ICS: **GICSP** (priority), CSSA, ISA/IEC 62443, GRID
- Cloud: AWS Security Specialty, AZ-500, CCSP
- Career strategy, CV/portfolio building, interview preparation

---

## STAGE 18 — Platforms and Resources

- TryHackMe, HackTheBox, PortSwigger Web Academy, VulnHub, PicoCTF
- OT/ICS practice: CISA training, GRFICSv2, SWaT Dataset, Dragos training
- CTF methodology: Web, Pwn, Crypto, Forensics, Reversing, Misc
- Essential reading list, blogs, threat intel feeds, communities

---

*Last updated: 2026 | github.com/RENCBERAKMAN/bytewall-academy*