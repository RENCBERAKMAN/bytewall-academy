# Stage 2.1 — Core Security Concepts
### From Zero to Cybersecurity Professional | Complete Roadmap Series

> **Series:** Cybersecurity × OT/ICS Security — Full Roadmap  
> **Stage:** 2 — Cybersecurity Core  
> **Module:** 2.1 — Core Concepts  
> **Level:** Beginner → Advanced  
> **Prerequisites:** Stage 1 — Network Fundamentals (all modules)  
> **Next Module:** 2.2 — Cryptography

---

## Table of Contents

1. [Why Core Concepts Are the Foundation of Every Security Decision](#1-why-core-concepts-are-the-foundation-of-every-security-decision)
2. [CIA Triad — Confidentiality, Integrity, Availability](#2-cia-triad--confidentiality-integrity-availability)
3. [Authentication — Proving Identity](#3-authentication--proving-identity)
4. [Authorization — Granting Permission](#4-authorization--granting-permission)
5. [Access Control — Enforcing Decisions](#5-access-control--enforcing-decisions)
6. [AAA Model — Authentication, Authorization, Accounting](#6-aaa-model--authentication-authorization-accounting)
7. [Risk, Threat, Vulnerability, Attack — Precise Definitions](#7-risk-threat-vulnerability-attack--precise-definitions)
8. [Threat Actor Types](#8-threat-actor-types)
9. [Attack Surface](#9-attack-surface)
10. [Defence in Depth](#10-defence-in-depth)
11. [Least Privilege Principle](#11-least-privilege-principle)
12. [Separation of Duties](#12-separation-of-duties)
13. [Zero Trust Model](#13-zero-trust-model)
14. [Module Summary](#14-module-summary)

---

## 1. Why Core Concepts Are the Foundation of Every Security Decision

Security tools change. Vendors come and go. Vulnerabilities are patched. Attack techniques evolve. But the conceptual framework underlying every security decision — why something is secure or insecure, who should have access to what, how trust is established, what constitutes acceptable risk — remains constant. Professionals who understand these concepts at a deep level make better decisions faster, in situations they have never encountered before.

**Concrete examples of how concept failures cause real breaches:**

**Target (2013) — CIA and Least Privilege failure:** The breach began through an HVAC vendor who had network access for remote monitoring. Proper network segmentation (a CIA-Availability/Integrity control) would have contained vendor access to HVAC systems only. Instead, the vendor's access reached the point-of-sale network. 40 million payment card records were compromised. The CIA triad concept, properly applied, would have mandated isolation.

**SolarWinds SUNBURST (2020) — Integrity failure:** The attackers compromised the SolarWinds build pipeline and inserted malicious code into legitimate, digitally signed software updates. 18,000 organisations installed the malicious update. This was a supply chain integrity attack — the update appeared authentic, was signed with a legitimate certificate, but contained a backdoor. Integrity controls on the build process (code signing with hardware-bound keys, build pipeline monitoring) were insufficient.

**Colonial Pipeline (2021) — Availability and Zero Trust failure:** Ransomware encrypted systems and Colonial shut down pipeline operations proactively. The initial access was via a compromised VPN account with no MFA. A Zero Trust approach would have required MFA, device health verification, and continuous validation — not just "valid credentials = full access." The Availability impact was $4.4 million in ransom and fuel shortages across the US East Coast.

**OT/ICS — Stuxnet (2010) — All three CIA pillars targeted:** Stuxnet attacked Confidentiality (covert operation hidden from operators), Integrity (false data sent to SCADA while centrifuges were physically destroyed), and Availability (centrifuges rendered inoperable). Understanding which CIA pillar an attack targets immediately tells you the appropriate defensive response.

These were not tool failures. They were conceptual failures — wrong assumptions about trust, access, identity, and risk. This module corrects those assumptions from first principles.

---

## 2. CIA Triad — Confidentiality, Integrity, Availability

### 2.1 The Framework

The CIA Triad is the foundational model of information security. Every security control, every policy, every architectural decision can be mapped to protecting one or more of its three properties.

```
        Confidentiality
             /\
            /  \
           /    \
          /      \
         /________\
  Integrity      Availability

Each property protects a different aspect of information:
  Confidentiality: Who can SEE the information
  Integrity:       Who can CHANGE the information, and whether it has been changed
  Availability:    Whether the information/system can be ACCESSED when needed
```

### 2.2 Confidentiality

**Definition:** Ensuring that information is accessible only to those authorised to access it.

**First principles:** Information has value. That value is often reduced or destroyed when it reaches parties who should not have it — competitors, attackers, regulators, the public. Confidentiality controls limit who can access information.

**Mechanisms:**
- Encryption (at rest: disk encryption, at transit: TLS)
- Access controls (authentication + authorisation)
- Physical security (who can reach the hardware)
- Data classification (categorising information by sensitivity)
- Need-to-know principle (access only to what the role requires)

**How confidentiality is attacked:**

```
Attack methods targeting confidentiality:

Eavesdropping: 
  Wireshark/tcpdump on shared medium
  ARP spoofing + MITM
  Wireless sniffing (WEP cracking, evil twin)
  
Credential theft:
  Phishing (social engineering for passwords)
  Keylogging (capture as user types)
  Mimikatz (extract from Windows memory)
  Pass-the-hash (use credential hash without knowing plaintext)
  
Data exfiltration:
  DNS tunnelling (exfiltrate via DNS queries)
  HTTPS C2 (exfiltrate over encrypted channels)
  Cloud storage abuse (upload to Dropbox/Google Drive)
  Physical media (USB drives)
  
Inference attacks:
  Machine learning on metadata (who communicates with whom)
  Traffic analysis (even encrypted traffic reveals patterns)
  Timing attacks (response time reveals information)
```

**Measuring confidentiality failure:**
- Data classification level of exposed data
- Number of records exposed
- Regulatory exposure (GDPR, HIPAA, PCI-DSS)
- Time data was exposed before detection

**OT/ICS Confidentiality:**
In OT environments, confidentiality concerns include:
- Process parameters (setpoints, recipes, formulas) — competitive intelligence
- Control system architecture (network topology, PLC models, firmware versions) — facilitates targeted attacks
- Personnel locations and schedules (safety risk)
- Proprietary industrial processes

However, OT prioritises Availability > Integrity > Confidentiality (inverse of typical IT). A confidentiality breach in OT rarely causes immediate physical harm; an availability breach can stop production or cause safety incidents.

```bash
# Testing confidentiality controls:

# Check if data is encrypted in transit:
openssl s_client -connect target:443 2>/dev/null | grep -E "Protocol|Cipher"
# If no TLS: confidentiality is unprotected in transit

# Check if sensitive files are readable by unauthorised users:
find /etc /var /opt -name "*.conf" -o -name "*.key" -o -name "*.pem" | \
    xargs ls -la 2>/dev/null | grep -v "^-r--------\|^-rw-------"
# Files readable by group/other = potential confidentiality failure

# Check disk encryption status (Linux):
lsblk -o NAME,FSTYPE,MOUNTPOINT | grep -i crypt   # LUKS volumes
cryptsetup status /dev/sda                          # LUKS status

# Check Windows BitLocker:
manage-bde -status C:
# "Protection Status: Protection On" = confidentiality protected

# Find world-readable sensitive files:
find / -name "id_rsa" -o -name "*.key" -o -name "shadow" 2>/dev/null | \
    xargs ls -la 2>/dev/null | grep -v " root root "
```

### 2.3 Integrity

**Definition:** Ensuring that information is accurate, complete, and has not been modified by unauthorised parties.

**First principles:** Information only has value if it is trustworthy. If a financial record, a software update, a medical record, or a sensor reading can be silently modified by an attacker, every decision based on that information may be wrong. Integrity ensures that data is what it claims to be.

**Two types of integrity:**

```
Data Integrity:
  The content of information has not been modified
  Example: a log entry has not been altered after the fact
  
System Integrity:
  The system behaves as designed
  Example: the operating system hasn't been modified by malware
  
Both are required — compromising either defeats the purpose of the other
```

**Mechanisms:**
- Cryptographic hashes (SHA-256, SHA-3) — detect any modification
- Digital signatures — verify origin and integrity together
- MACs (Message Authentication Codes) — integrity + authentication
- Checksums — detect accidental modification (not malicious)
- Write-once storage (immutable logs, WORM)
- Version control systems (detect unauthorised changes)
- File integrity monitoring (Tripwire, AIDE, Windows FIM)

**How integrity is attacked:**

```
SolarWinds SUNBURST (2020):
  Target: Software supply chain integrity
  Method: Modify legitimate software before distribution
  How: Compromise build server, inject malicious code into DLL
  Result: Signed, legitimate-looking update contained backdoor
  Impact: 18,000 organisations infected

NotPetya (2017):
  Target: Software supply chain integrity (MeDoc accounting software)
  Method: Hijack auto-update mechanism
  How: Compromise update server for Ukrainian tax software
  Distribution: Sent malicious update to all MeDoc users in Ukraine
  Impact: $10 billion global damage, most destructive malware ever

Log tampering:
  Attacker modifies system logs after compromise to remove evidence
  Mitigation: Forward logs to remote, append-only syslog server immediately
  Forensic indicator: gaps in log sequence numbers, missing events

Database manipulation:
  Direct SQL UPDATE/DELETE on database records
  No trace unless query logging enabled
  Example: financial fraud via database record modification
```

**OT/ICS Integrity — Most Critical Property:**

In OT, integrity is arguably the most dangerous property to violate because the consequences are physical:

```
Stuxnet Integrity Attack (2010):
  Attack: Modified centrifuge control parameters while sending false
          "normal" readings to the operator HMI
  Result: Operators saw normal operation; centrifuges were destroying themselves
  Mechanism: Rootkit intercepted Siemens WinCC API calls
             Returned pre-recorded "normal" data to SCADA
             Sent actual destructive commands to PLCs
  
  This is the definitive integrity attack on OT:
  - Sensor data integrity: FALSE (operators see lies)
  - Control command integrity: COMPROMISED (PLCs receive attacker commands)
  - System integrity: COMPROMISED (rootkit hidden in SCADA)
  
Integrity in OT sensor data:
  A pressure sensor reading 150 PSI when actual pressure is 300 PSI = 
  operator makes decisions on false data = potential explosion
  
  Mitigations:
  - Cross-reference multiple independent sensors
  - Physical safety systems independent of digital controls
  - IEC 62443 security levels for control system integrity
  - Message authentication for control commands (IEC 62351)
```

```bash
# Integrity verification tools:

# File integrity checking:
sha256sum /bin/ls                         # Calculate hash
sha256sum -c checksums.txt               # Verify against saved hashes

# AIDE (Advanced Intrusion Detection Environment):
sudo aide --init                          # Create baseline database
sudo aide --check                         # Compare current state to baseline
# Reports: added, removed, changed files

# Tripwire (enterprise FIM):
sudo tripwire --init                      # Initialise database
sudo tripwire --check                     # Check integrity
sudo tripwire --update                    # Update after approved changes

# Verify package integrity (Linux):
rpm -V package_name                       # RPM: verify installed package
dpkg -V package_name                      # Debian: verify package
# Output: 5 = checksum failure (file modified)

# Verify digital signatures:
gpg --verify file.sig file               # Verify GPG signature
openssl dgst -sha256 -verify key.pub -signature sig.bin file  # Verify OpenSSL sig

# Check Windows system file integrity:
sfc /scannow                              # System File Checker
# Detects and repairs modified system files

# Log integrity monitoring:
# Forward logs to remote syslog IMMEDIATELY (before attacker can tamper):
# /etc/rsyslog.conf:
# *.* @@syslog-server:514              # @@ = TCP (reliable, ordered)
# *.* @syslog-server:514               # @ = UDP (fire and forget)
```

### 2.4 Availability

**Definition:** Ensuring that authorised users can access information and systems when needed.

**First principles:** A system that works perfectly but is inaccessible provides zero value. Availability controls ensure that systems remain operational and accessible under adversarial conditions (DDoS, ransomware, hardware failure) and non-adversarial conditions (power outage, software bugs, natural disasters).

**Mechanisms:**
- Redundancy (no single point of failure)
- Load balancing (distribute load across multiple systems)
- Backups (restore capability after failure)
- Disaster Recovery (DR) and Business Continuity Planning (BCP)
- Rate limiting (prevent resource exhaustion)
- DDoS mitigation
- Patch management (prevent exploit-based outages)
- Monitoring and alerting

**Availability metrics:**
```
Uptime measurement:
  99%     = 87.6 hours downtime/year     ("two nines")
  99.9%   = 8.76 hours downtime/year    ("three nines")
  99.99%  = 52.6 minutes downtime/year  ("four nines")
  99.999% = 5.26 minutes downtime/year  ("five nines")
  
RTO (Recovery Time Objective): How fast must systems be restored?
RPO (Recovery Point Objective): How much data loss is acceptable?

Example: RPO = 1 hour means: backups must run at least hourly
Example: RTO = 4 hours means: systems must be restored within 4 hours
```

**How availability is attacked:**
- DDoS (Distributed Denial of Service) — overwhelm with traffic
- Ransomware — encrypt data/systems, demand payment to restore
- Physical destruction — sabotage of hardware
- Resource exhaustion — fill disk, exhaust memory, TCP state table attacks
- Logic bombs — scheduled code to crash systems
- Supply chain attacks on dependencies

**OT/ICS Availability — The Primary Concern:**

```
OT Availability Priority:

In enterprise IT: CIA (Confidentiality first)
In OT/ICS: AIC (Availability first)

Why availability dominates in OT:
  A manufacturing PLC going offline = production stop = $X/minute losses
  A water treatment SCADA going offline = inability to control water quality
  A power grid SCADA going offline = potential for blackout
  An oil refinery control system going offline = unsafe process conditions
  
"Fail safe" vs "Fail operational":
  Enterprise IT failure: systems go down, users can't work (bad but manageable)
  OT failure: physical process continues without control (potentially dangerous)
  
  Safety Instrumented Systems (SIS) are designed to "fail safe":
  If SIS loses communication, it takes the process to a safe state automatically
  
  But: making OT highly available often means avoiding patches (restart risk),
  avoiding changes (configuration risk), avoiding monitoring (performance risk)
  → This is why OT systems are often most vulnerable
```

```bash
# Availability monitoring and testing:

# Check system uptime:
uptime                              # Linux
systeminfo | grep "System Boot"     # Windows

# Monitor service availability:
while true; do
    if ! ping -c 1 -W 2 192.168.1.100 &>/dev/null; then
        echo "$(date): HOST DOWN: 192.168.1.100" | tee -a /var/log/availability.log
    fi
    sleep 30
done

# Check disk space (availability killer if full):
df -h | awk '$5 > 80 {print "WARNING: "$1" is "$5" full"}'

# Backup verification:
sha256sum backup.tar.gz             # Hash before storage
sha256sum backup_restored.tar.gz    # Hash after restoration — must match

# DDoS simulation (own infrastructure only):
# hping3 --flood -S -p 80 target   # SYN flood
# Only run on your own test infrastructure
```

> **Key Insight:** The CIA Triad tells you what you are protecting, not how. Every security control maps to at least one pillar — and the most damaging attacks often compromise multiple pillars simultaneously. Before designing any security control, always ask: which CIA property does this protect, and what is the most likely attack against it? The answer determines the correct tool.

---

## 3. Authentication — Proving Identity

### 3.1 What Authentication Is

Authentication answers the question: **"Are you who you claim to be?"**

It is the process of verifying that an entity (person, system, application) is who or what it claims to be. Authentication precedes authorisation — you must know WHO someone is before you can determine what they are ALLOWED to do.

```
Authentication vs Identification vs Authorisation:

Identification:  "I am John Smith"       (claim — anyone can make this)
Authentication: "I can prove I am John"  (verification — requires proof)
Authorisation:  "John may access X"      (permission — granted after auth)

In systems:
  Username = identification  (I claim to be 'jsmith')
  Password = authentication  (I can prove it)
  ACL check = authorisation  (jsmith is allowed to read /etc/passwd)
```

### 3.2 Authentication Factors

Authentication factors are categories of proof. Using multiple factors increases security exponentially because an attacker must compromise multiple independent mechanisms.

```
Factor 1 — Something You KNOW:
  Passwords, PINs, security questions, passphrases
  Weaknesses: forgotten, guessed, stolen via phishing, cracked offline,
              reused across sites, exposed in data breaches
  
Factor 2 — Something You HAVE:
  Hardware tokens (YubiKey, RSA SecurID), smart cards, mobile phones
  (TOTP codes via Authenticator apps), certificates on specific devices
  Weaknesses: lost or stolen device, SIM swapping (for SMS-based)
  
Factor 3 — Something You ARE:
  Biometrics: fingerprint, face recognition, iris scan, voice print, typing patterns
  Weaknesses: cannot be changed if compromised, spoofing possible,
              privacy implications, accuracy varies

Factor 4 — Somewhere You ARE:
  Geolocation, IP address, network location
  Weaknesses: VPN/proxy bypass, GPS spoofing, imprecise geofencing
  Use: usually a supplemental factor, not primary

Factor 5 — Something You DO:
  Behavioural biometrics: typing rhythm, mouse movement patterns, gait analysis
  Weaknesses: can be affected by injury, illness, stress; training period needed
```

**Multi-Factor Authentication (MFA):**

```
MFA = using two or more factors from DIFFERENT categories

Common MFA implementations:
  Password + TOTP code (Factor 1 + Factor 2)
  Smart card + PIN (Factor 2 + Factor 1)
  Password + hardware key + fingerprint (F1 + F2 + F3)
  
NOT real MFA:
  Password + security question (both Factor 1)
  Two passwords (both Factor 1)
  Password + email code (Factor 1 + quasi-Factor 2 — email is often Factor 1 protected)
  
MFA Bypass Attacks:
  SIM swapping: convince carrier to transfer phone number to attacker's SIM
  OTP phishing: real-time phishing captures OTP before it expires
  MFA fatigue: send repeated MFA push notifications until user accepts
  
MFA Fatigue Attack (Uber, 2022):
  Attacker obtained credentials from dark web
  Spammed Uber employee's phone with MFA push notifications
  Employee eventually approved to stop the spam
  Attacker gained access → full Uber internal network compromise
  
  Defence: number matching MFA (display code in app that must match screen)
           Phishing-resistant MFA: FIDO2/WebAuthn hardware keys
```

### 3.3 Authentication Protocols

```
Kerberos (Windows Active Directory):
  
  Design: Avoid transmitting passwords over network
  Method: Ticket-based authentication system
  
  Flow:
  Client → AS (Authentication Service): "I am user X" + encrypted timestamp
  AS → Client: TGT (Ticket Granting Ticket) encrypted with AS key
  Client → TGS (Ticket Granting Service): TGT + "I want service Y"
  TGS → Client: Service Ticket for Y, encrypted with service Y's key
  Client → Service Y: Service Ticket
  Service Y: Decrypts ticket, grants access
  
  Security implications:
  - Password never transmitted in cleartext
  - Tickets are time-limited (default: 10 hours)
  - Kerberoasting: request service tickets for accounts with SPNs,
    crack offline (ticket encrypted with service account's password)
  - Pass-the-ticket: steal TGT from memory, use to authenticate as victim
  - Golden Ticket: forge TGT using krbtgt hash (Domain Admin → persistent access)
  
  Tools:
    Rubeus: Kerberos attack toolkit (Kerberoasting, AS-REP Roasting, ticket extraction)
    Mimikatz: Extract Kerberos tickets from Windows memory
    Impacket GetUserSPNs: Kerberoasting from Linux

NTLM (NT LAN Manager):
  Challenge-response authentication
  Server sends 8-byte challenge
  Client responds with HMAC of NT hash
  Vulnerability: relay attacks, offline cracking
  
  Responder + ntlmrelayx: capture NTLM hashes, relay to other services
  Hashcat -m 5600: crack NTLMv2 hashes
  
OAuth 2.0 / OIDC:
  Token-based delegation
  "Login with Google" = Google authenticates, provides token to app
  Access token: what you can do
  Refresh token: get new access tokens without re-authenticating
  ID token: who you are (OIDC extension to OAuth)
  
SAML (Security Assertion Markup Language):
  Enterprise SSO (Single Sign-On)
  XML-based assertions from Identity Provider to Service Provider
  Attack: SAML response manipulation if not properly signed and verified
```

```bash
# Authentication testing and monitoring:

# Check password hash algorithm in /etc/shadow:
sudo cat /etc/shadow | head -3
# $6$ = SHA-512 (good)
# $5$ = SHA-256 (acceptable)
# $1$ = MD5 (insecure — must change)
# $y$ = yescrypt (modern, excellent)
# DES (no prefix) = extremely insecure

# Enumerate Kerberoastable accounts:
# (requires domain credentials)
impacket-GetUserSPNs -dc-ip 192.168.1.10 DOMAIN/user:password -request
# Outputs: TGS tickets for service accounts → crack with hashcat -m 13100

# AS-REP Roasting (accounts with "don't require preauth"):
impacket-GetNPUsers DOMAIN/ -usersfile users.txt -dc-ip 192.168.1.10 -no-pass
# Outputs: AS-REP hashes → crack with hashcat -m 18200

# Check for weak authentication on web services:
# Test default credentials:
curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target/login \
    -d '{"user":"admin","pass":"admin"}'
# 200 with success indicator = default creds work

# Check for MFA enforcement:
# If login succeeds with just username/password (no second factor prompt): no MFA

# Monitor authentication failures (Linux):
sudo grep "Failed password\|Invalid user" /var/log/auth.log | \
    awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -10
# High count from single IP = brute force attempt

# Windows authentication log:
# Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4625} | Select-Object -First 10
# Event 4625 = failed logon
# Event 4624 = successful logon
# Event 4648 = logon with explicit credentials (often malicious)
```

**Authentication in OT/ICS:**

```
OT Authentication Challenges:

1. Many field devices (PLCs, RTUs) have NO authentication:
   Modbus: no authentication — any device on the network can read/write
   DNP3 baseline: no authentication (SAv5 adds it but rarely deployed)
   PROFIBUS: no authentication
   → Anyone with network access = full control
   
2. Default credentials pervasive in OT:
   PLC web interfaces: admin/admin
   SCADA systems: factory default passwords rarely changed
   Industrial switches: default Telnet credentials
   
3. Legacy OT systems cannot support modern authentication:
   Old PLCs cannot run TLS or modern crypto
   Resources too constrained for authentication overhead
   
4. Shared credentials common:
   "The HMI password" known to all operators
   No individual accountability
   Cannot audit who made which change
   
5. Authentication vs real-time requirements:
   Latency introduced by authentication may be unacceptable for
   time-critical control operations
   
Defence:
  Network segmentation (compensate for device auth failure)
  Jump servers with strong auth for accessing OT
  OPC-UA with authentication for modern inter-device communication
  IEC 62351 for protocol-level authentication
  NERC CIP requires access management for BES Cyber Systems
```

> **Key Insight:** Authentication is the gateway to all other security controls — if authentication is bypassed or compromised, every authorisation control becomes meaningless. Phishing-resistant hardware MFA (FIDO2/WebAuthn) is the only authentication method provably resistant to the most common attacks (phishing, credential stuffing, real-time OTP replay). SMS and TOTP codes remain valuable but are not phishing-resistant.

---

## 4. Authorization — Granting Permission

### 4.1 What Authorization Is

Authorisation answers: **"What are you allowed to do?"**

After identity is verified (authentication), the system determines what resources and actions the authenticated entity is permitted to access or perform. Authorisation and authentication are distinct — one system knowing who you are does not mean it knows what you're allowed to do.

```
Authentication → Authorization → Access

Authentication verifies identity
Authorisation enforces policy
They can fail independently:

Broken Auth + Correct Authz:  Attacker impersonates user, gets user's permissions only
Correct Auth + Broken Authz:  Real user authenticated, but can access resources beyond permissions
Both broken:                  Complete compromise
```

### 4.2 Authorisation Models

**DAC — Discretionary Access Control:**
```
Owner of resource decides who can access it
Example: Linux file permissions (chmod)
  -rw-r--r-- file.txt
  Owner: read, write
  Group: read
  Others: read
  
Weakness: Owner can grant access to anyone
          "Discretionary" = no central oversight
          User error leads to data exposure (chmod 777)
          
Attack relevance: Find world-readable sensitive files
find / -perm -o+r -name "*.key" -o -name "*.conf" 2>/dev/null
```

**MAC — Mandatory Access Control:**
```
Central authority assigns labels (classifications) to subjects and objects
Access granted only when subject label permits object label
Subject cannot override — even if they "own" the file

Examples:
  SELinux (Security Enhanced Linux)
  AppArmor
  Military classifications: Unclassified, Secret, Top Secret
  
Multi-Level Security (MLS) model (Bell-LaPadula):
  No read up: Top Secret user can read Secret (but not TS from Secret)
  No write down: Top Secret user cannot write to Unclassified (prevent leakage)
  
Check SELinux status:
  getenforce               # Enforcing / Permissive / Disabled
  sestatus                 # Detailed SELinux status
  ls -Z /etc/shadow        # See file's SELinux label
  ps -eZ | grep httpd      # See process's SELinux context
```

**RBAC — Role-Based Access Control:**
```
Permissions assigned to roles, users assigned to roles
User inherits permissions of their role(s)

Example:
  Role: "Network Admin" = permission to view/change network config
  Role: "Read-Only Auditor" = permission to view logs, no changes
  User: jsmith = assigned role "Network Admin"
  
Benefits:
  Scalable (manage roles, not individual user permissions)
  Consistent (all users with same role have same access)
  Auditable (clear what each role can do)
  
Weakness:
  Role explosion: too many roles becomes unmanageable
  Role creep: users accumulate roles over time beyond what's needed
  
RBAC in Active Directory:
  Security groups = roles
  DACL (Discretionary ACL) on objects = permissions per group
```

**ABAC — Attribute-Based Access Control:**
```
Access decisions based on attributes of: user, resource, environment, action

Example policy:
  "Allow access to Document X IF:
    user.department == 'Finance'
    AND user.clearance >= document.classification
    AND time.current_hour BETWEEN 8 AND 18
    AND user.location == 'corporate_network'"
    
More flexible than RBAC — can express complex, context-aware policies
Used in: AWS IAM, Azure RBAC, modern zero trust systems
```

**PBAC — Policy-Based Access Control (modern):**
```
Centralised policy engine evaluates access requests in real-time
Example: Open Policy Agent (OPA)

Decouples policy from code:
  Application asks OPA: "Can user X do action Y on resource Z?"
  OPA evaluates policies, returns: allow/deny + reason
  
Used in: Kubernetes admission control, API gateways, microservices
```

### 4.3 Broken Authorization — OWASP Top 10

```
Broken Access Control is the #1 OWASP vulnerability (2021, 2023)

Common Broken Authorisation Patterns:

IDOR (Insecure Direct Object Reference):
  URL: /api/user/12345/profile
  Attacker changes to: /api/user/12346/profile
  → Access to another user's data
  Defence: Check that authenticated user owns resource 12346
  
Privilege Escalation — Vertical:
  Regular user accesses admin function
  URL: /admin/delete_user?id=5
  No check that user is admin → any user can delete users
  
Privilege Escalation — Horizontal:
  User A accesses User B's data
  Same privilege level, different account
  
Missing Function-Level Access Control:
  Frontend hides admin menu from non-admins
  But /admin/users endpoint is not protected server-side
  Attacker discovers URL → full access
  
Forced Browsing:
  /reports/financial/2024/q4.pdf is protected
  /reports/financial/2023/q4.pdf is not
  Attacker traverses to find unprotected resources
```

```bash
# Testing authorisation controls:

# Check for IDOR manually:
# Identify user-owned resource ID in URL/response
# Authenticate as different user, attempt to access first user's resource
curl -H "Cookie: session=user2_session" \
    https://target.com/api/users/USER1_ID/data
# If returns user1's data: IDOR vulnerability

# Test for privilege escalation via HTTP method:
# Many apps check GET but not POST/PUT/DELETE
curl -X DELETE https://target.com/api/admin/users/5 \
    -H "Cookie: regular_user_session"
# If succeeds: missing authorisation check on DELETE method

# Test for parameter manipulation:
curl "https://target.com/api/invoice?user_id=YOUR_ID&invoice_id=INVOICE_ID"
# Change user_id to another user's ID
# If returns their invoice: IDOR

# Check for directory traversal (forced browsing):
for path in /admin /administrator /manager /api/admin /api/internal; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
    echo "$code: https://target.com$path"
done
# 200 on admin paths without admin login = authorisation failure

# Linux authorisation check:
sudo -l                             # What can current user sudo?
id                                  # Current user, groups, capabilities
find / -perm -4000 2>/dev/null     # SUID files (run as owner, not as self)
find / -perm -2000 2>/dev/null     # SGID files
# SUID on non-standard binaries = privilege escalation opportunity
```

> **Key Insight:** Authentication proves identity; authorisation enforces what that identity can do. Broken access control (authorisation failure) is consistently the most common vulnerability class in web applications. The root cause is almost always the same: trusting client-supplied data (user IDs, role indicators) without server-side verification. Every access control check must happen on the server, every time, for every request.

---

## 5. Access Control — Enforcing Decisions

### 5.1 Access Control as the Enforcement Layer

Access control is the mechanism that takes authentication + authorisation decisions and enforces them. It is the "gate" between subjects (users, processes, systems) and objects (files, databases, APIs, network services).

```
Access Control Components:

Subject: Entity requesting access (user, process, service)
Object:  Resource being accessed (file, database, API, network)
Reference Monitor: Policy enforcement mechanism
Policy: Rules defining what subjects may do to objects

Reference Monitor Requirements:
  1. Always invoked (cannot be bypassed)
  2. Tamperproof (cannot be modified)
  3. Small enough to be verified correct (formally verifiable)
```

### 5.2 Access Control Lists (ACLs)

```
ACL: a list attached to an object defining which subjects have which permissions

File system ACL example (Linux extended ACL):
getfacl /var/data/sensitive.txt
# file: /var/data/sensitive.txt
# owner: root
# group: finance
user::rw-           # file owner: read, write
user:alice:rw-      # alice: read, write
user:bob:r--        # bob: read only
group::r--          # finance group: read
group:security:rwx  # security group: read, write, execute
mask::rwx           # maximum effective permissions
other::---          # everyone else: no access

# Set ACL:
setfacl -m u:alice:rw /var/data/sensitive.txt
setfacl -m g:security:rwx /var/data/sensitive.txt
setfacl -x u:bob /var/data/sensitive.txt         # Remove bob's entry

# Windows ACL (DACL):
# Get-Acl C:\Sensitive\file.txt | Format-List
# icacls C:\Sensitive\file.txt
# icacls C:\Sensitive\file.txt /grant alice:R
```

### 5.3 Network Access Control

```
NAC (Network Access Control): determines whether a device may connect to the network

Components:
  802.1X: port-based authentication
  RADIUS: AAA server that makes access decisions
  Supplicant: device software seeking access (Windows, macOS, Linux)
  Authenticator: network device enforcing decision (switch, AP)
  
802.1X Flow:
  Device plugs in → Switch port in unauthorised state
  Supplicant sends EAP identity
  Authenticator forwards to RADIUS
  RADIUS validates: credentials, device certificate, device health
  RADIUS returns: Access-Accept or Access-Reject
  Access-Accept: switch port moves to authorised state, VLAN assigned
  Access-Reject: device has no network access
  
Device health checks (NAC posture assessment):
  Is antivirus installed and up to date?
  Is OS patched to required level?
  Is disk encryption enabled?
  Is the device compliant with security policy?
  
If not compliant: quarantine VLAN (access to patching resources only)
```

```bash
# Access control audit commands:

# Linux filesystem permissions audit:
# Find files/dirs with dangerous permissions:
find / -type f -perm -o+w 2>/dev/null | head -20    # World-writable files
find / -type d -perm -o+w 2>/dev/null | head -20    # World-writable directories
find / -perm -4000 2>/dev/null                        # SUID files
find / -perm -2000 2>/dev/null                        # SGID files

# Check sudo configuration:
cat /etc/sudoers
sudo -l                              # Current user's sudo permissions
# Look for: NOPASSWD: ALL (allows full sudo without password)
# Look for: wildcard use in allowed commands

# Windows: check who has local admin rights:
net localgroup administrators
# Should be minimal: only IT admin accounts

# Check for excessive AD privileges:
# (requires BloodHound or similar)
# Find users with DCSync rights:
# Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteOwner|WriteDacl"}
```

---

## 6. AAA Model — Authentication, Authorization, Accounting

### 6.1 The Three As

AAA (Authentication, Authorization, Accounting) is the security framework for controlling access to network resources and tracking that access.

```
Authentication: WHO are you? (verify identity)
Authorization:  WHAT can you do? (enforce policy)
Accounting:     WHAT DID you do? (record activity)

The three are inseparable for complete access control:
  Without Accounting: authorised access leaves no audit trail
  Without Authorization: all authenticated users have equal access
  Without Authentication: accounting cannot attribute actions to individuals
```

### 6.2 RADIUS — The AAA Protocol

RADIUS (Remote Authentication Dial-In User Service, RFC 2865) is the most widely deployed AAA protocol.

```
RADIUS Architecture:

Client (NAS):    Network Access Server — the device enforcing access
                 (VPN gateway, wireless AP, switch port, firewall)
RADIUS Server:   Policy engine — makes access decisions
User Directory:  Backend store (AD/LDAP, local database)

Protocol:
  Client → RADIUS Server: Access-Request (UDP 1812)
    Contains: username, hashed password (MD5 challenge-response), NAS info
  
  RADIUS Server → Client: Access-Accept, Access-Reject, or Access-Challenge
  
  Access-Accept may include attributes:
    Session-Timeout: how long the session may last
    Idle-Timeout: timeout if no activity
    Class: VLAN assignment
    Filter-Id: ACL to apply to the session

RADIUS Weakness:
  Password encrypted with MD5(PAP) — weak
  Accounting over UDP — can be spoofed
  
RADIUS/TLS (RadSec): RADIUS over TLS — addresses cleartext vulnerability
```

### 6.3 Accounting — The Audit Trail

```
Accounting records what was accessed, when, by whom, for how long

Typical accounting record:
  Timestamp:     2024-05-29 10:15:32 UTC
  User:          jsmith@company.com
  Client IP:     192.168.1.5
  NAS-IP:        10.0.0.1 (the VPN gateway or switch)
  Action:        Authenticated successfully
  Session-Time:  3600 seconds
  Bytes-In:      15,234,567
  Bytes-Out:     892,345
  Termination:   User-Request

SIEM Integration:
  RADIUS accounting → SIEM
  Correlate: login at unusual time, login from unusual location,
             excessive data transfer, concurrent sessions from different IPs
  
Alert rules:
  User authenticated from 2 different countries within 2 hours (impossible travel)
  Data transfer > 1GB in single session (possible exfiltration)
  Failed authentication followed by success from different IP (credential spray → success)
  Authentication outside business hours for non-privileged user
```

```bash
# AAA implementation examples:

# FreeRADIUS server (Linux):
sudo apt install freeradius
# Config: /etc/freeradius/3.0/users
# Test user: echo "testuser Cleartext-Password := 'testpassword'" >> /etc/freeradius/3.0/users
sudo systemctl start freeradius
radtest testuser testpassword localhost 0 testing123  # Test auth

# Verify RADIUS authentication from network device:
radtest username password radius_server_ip 0 shared_secret
# Expected: Received Access-Accept (success)

# Analyse RADIUS accounting logs:
cat /var/log/freeradius/radacct/*/detail | \
    grep -A10 "Acct-Status-Type = Start" | \
    grep "User-Name\|Framed-IP\|Acct-Session-Time" | head -30

# Check sudo accounting (Linux):
# Enable sudo logging:
# /etc/sudoers: Defaults logfile="/var/log/sudo.log"
cat /var/log/sudo.log | grep "COMMAND"
# Shows: who ran what command with sudo, when, from where

# Windows accounting via Security event log:
# Event 4624: Successful logon
# Event 4625: Failed logon
# Event 4647: User-initiated logoff
# Event 4648: Logon with explicit credentials
# Event 4662: Object access
# Event 4688: Process creation (with command line if enabled)
```

**AAA in OT/ICS:**

```
NERC CIP Requirements (North American power grid):
  CIP-004: Personnel training and access management
  CIP-007: Systems security management (authentication controls)
  
  Specifically requires:
  - Individual user accounts (no shared accounts for privileged access)
  - Password policies
  - Access logging and review
  
IEC 62443 (industrial cybersecurity standard):
  Security Level 2 (default target): Requires authentication for all access
  Security Level 3 (high): Requires MFA for privileged access
  Accounting: All access to BES (Bulk Electric System) must be logged
  
Common OT failure:
  Shared "operator" account → no individual accountability
  If something goes wrong (deliberate or accidental), cannot attribute
  Insider threat: no way to know who made changes
  
Solution: even if field devices cannot authenticate individually,
  require authentication at the boundary (jump server, HMI login)
  and log all sessions with session recording
```

> **Key Insight:** Accounting is the pillar most often neglected — authentication and authorisation receive attention, logging is treated as optional. This is backwards: without accounting, you cannot detect breaches, cannot investigate incidents, cannot prove compliance, and cannot learn from security events. Comprehensive, tamper-resistant logging is not optional — it is the difference between a recoverable incident and an unexplained mystery.

---

## 7. Risk, Threat, Vulnerability, Attack — Precise Definitions

### 7.1 Why Precise Terminology Matters

These four terms are routinely confused and misused — in vendor marketing, in management meetings, and sometimes in security documentation. Using them incorrectly leads to misallocated resources, wrong priorities, and misunderstood risk posture.

```
Definitions:

VULNERABILITY: A weakness in a system, process, or control
  Examples:
  - Unpatched software (CVE-2017-0144 / EternalBlue)
  - Default password on router
  - Missing input validation in web application
  - Unlocked server room door
  - Employee who will click phishing links

THREAT: A potential cause of harm — an actor, event, or circumstance
  Examples:
  - Ransomware group targeting healthcare
  - Disgruntled employee with access
  - Nation-state APT with persistent presence
  - Hurricane disrupting data centre
  - Power outage

RISK: The probability that a threat will exploit a vulnerability, causing impact
  Risk = f(Threat, Vulnerability, Impact)
  
  More precisely:
  Risk = Threat Likelihood × Vulnerability Exploitability × Impact Severity
  
  If any factor is zero, risk is zero:
  No threat: vulnerability exists but nobody cares → low risk
  No vulnerability: threat exists but system has no weaknesses → low risk
  No impact: system compromised but contains nothing of value → low risk

ATTACK: A threat actor actually exploiting a vulnerability
  An attack is a threat becoming real
  Not all vulnerabilities are attacked
  Not all threats execute attacks
```

### 7.2 The Risk Formula

```
Qualitative Risk Assessment:

Likelihood      × Impact       = Risk Level
High (3)        × High (3)     = Critical (9)
High (3)        × Medium (2)   = High (6)
Medium (2)      × High (3)     = High (6)
Medium (2)      × Medium (2)   = Medium (4)
Low (1)         × High (3)     = Medium (3)
Low (1)         × Low (1)      = Low (1)

Quantitative Risk Assessment (FAIR methodology):
  Asset Value (AV): monetary value of what's at risk
  Threat Event Frequency (TEF): how often the threat occurs
  Vulnerability (V): probability of exploitation if threat occurs
  Loss Magnitude (LM): impact if successful
  
  Annualised Loss Expectancy (ALE) = TEF × V × LM
  
Example:
  Database breach risk:
  TEF = 2 per year (two significant attacks expected)
  V = 0.3 (30% chance of success if attacked)
  LM = $500,000 (cost of breach: notification, legal, remediation)
  ALE = 2 × 0.3 × $500,000 = $300,000/year
  
  Spend up to $300,000/year on controls that prevent the breach
  Spending $1,000,000/year to prevent a $300,000 risk = poor risk management
```

### 7.3 Vulnerability Scoring — CVSS

```
CVSS (Common Vulnerability Scoring System) quantifies vulnerability severity

CVSS v3.1 Base Metrics:

Attack Vector (AV):
  Network (N):    Exploitable remotely (worst)
  Adjacent (A):   Must be on same network
  Local (L):      Must have local access
  Physical (P):   Requires physical access (least severe for remote attack)

Attack Complexity (AC):
  Low (L):        No special conditions needed
  High (H):       Specific conditions required (race condition, non-default config)

Privileges Required (PR):
  None (N):       No authentication needed (most severe)
  Low (L):        Regular user
  High (H):       Admin/root

User Interaction (UI):
  None (N):       No user action needed
  Required (R):   Victim must take action

Scope (S):
  Unchanged (U):  Impact contained to vulnerable component
  Changed (C):    Impact extends beyond vulnerable component

Confidentiality / Integrity / Availability Impact:
  None (N) / Low (L) / High (H)

CVSS Score Ranges:
  0.0:     None
  0.1-3.9: Low
  4.0-6.9: Medium
  7.0-8.9: High
  9.0-10.0: Critical

Examples:
  EternalBlue (MS17-010): CVSS 9.8 (Critical) — Network, Low complexity, No auth
  Log4Shell (CVE-2021-44228): CVSS 10.0 (Critical) — Network, Low, None auth, Changed scope
  Local privilege escalation typical: CVSS 7.8 (High) — Local access required
```

```bash
# Vulnerability management workflow:

# Check for CVEs in installed packages (Linux):
# Debian/Ubuntu:
sudo apt list --installed 2>/dev/null | grep -oE "^[^/]+" | \
    xargs dpkg -s 2>/dev/null | grep "Version\|Package" | \
    paste - - | awk '{print $2, $4}'
# Then cross-reference against CVE databases

# Trivy (container/system vulnerability scanner):
trivy image nginx:latest             # Scan container image
trivy fs /                           # Scan filesystem
trivy --severity HIGH,CRITICAL fs /  # Only high/critical

# OpenVAS / GVM (vulnerability scanner):
gvm-cli socket --xml "<get_tasks/>"  # List scheduled scans

# Check specific CVE status:
# CVE database API:
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228" | \
    python3 -m json.tool | grep -A5 "cvssMetricV3"

# Risk prioritisation script:
python3 << 'EOF'
vulnerabilities = [
    {"cve": "CVE-2021-44228", "cvss": 10.0, "exploited": True, "systems": 50},
    {"cve": "CVE-2022-30190", "cvss": 7.8,  "exploited": True, "systems": 200},
    {"cve": "CVE-2020-1472",  "cvss": 10.0, "exploited": True, "systems": 1},
    {"cve": "CVE-2023-12345", "cvss": 5.0,  "exploited": False, "systems": 100},
]

# Risk score = CVSS × (2 if actively exploited) × log(systems affected)
import math
for v in vulnerabilities:
    score = v["cvss"] * (2 if v["exploited"] else 1) * math.log(v["systems"] + 1)
    print(f"{v['cve']}: CVSS={v['cvss']}, Risk Score={score:.1f}")

# Sort by risk score to prioritise patching
vulnerabilities.sort(key=lambda x: x["cvss"] * (2 if x["exploited"] else 1) * math.log(x["systems"] + 1), reverse=True)
print("\nPatching Priority:")
for i, v in enumerate(vulnerabilities, 1):
    print(f"  {i}. {v['cve']} (CVSS {v['cvss']}, {'ACTIVELY EXPLOITED' if v['exploited'] else 'not exploited'})")
EOF
```

> **Key Insight:** Risk is the product of threat × vulnerability × impact — reducing any factor reduces risk. The key insight for resource allocation: patching the highest-CVSS vulnerability affecting only one system may be lower priority than patching a medium-CVSS vulnerability affecting 500 critical systems that is being actively exploited. Risk prioritisation, not CVSS score alone, should drive remediation order.

---

## 8. Threat Actor Types

### 8.1 Why Threat Actor Classification Matters

Different threat actors have different capabilities, motivations, resources, and targets. Knowing who is most likely to target you changes how you defend — against a ransomware group, patch management and backups are critical; against a nation-state APT, focus shifts to detection and containment since prevention alone is insufficient.

```
Threat Actor Taxonomy:

┌──────────────────┬──────────────┬───────────────┬──────────────────────────┐
│ Actor Type       │ Motivation   │ Capability    │ Primary Targets          │
├──────────────────┼──────────────┼───────────────┼──────────────────────────┤
│ Nation-State APT │ Espionage,   │ Highest       │ Government, Defence,     │
│                  │ Sabotage,    │               │ Critical Infrastructure,  │
│                  │ Disruption   │               │ Technology companies     │
├──────────────────┼──────────────┼───────────────┼──────────────────────────┤
│ Cybercriminals   │ Financial    │ High          │ Any profitable target:   │
│ (organised)      │ gain         │               │ Finance, Healthcare,     │
│                  │              │               │ Retail, all sectors      │
├──────────────────┼──────────────┼───────────────┼──────────────────────────┤
│ Ransomware       │ Extortion    │ High          │ Any organisation that    │
│ Groups           │              │               │ cannot afford downtime   │
│                  │              │               │ (hospitals, utilities)   │
├──────────────────┼──────────────┼───────────────┼──────────────────────────┤
│ Insider Threats  │ Varies:      │ Variable      │ Own employer             │
│                  │ Financial,   │ (privileged   │                          │
│                  │ Revenge,     │ access)       │                          │
│                  │ Ideology     │               │                          │
├──────────────────┼──────────────┼───────────────┼──────────────────────────┤
│ Hacktivists      │ Political,   │ Medium        │ Organisations they       │
│                  │ Social       │               │ disagree with ideologically│
├──────────────────┼──────────────┼───────────────┼──────────────────────────┤
│ Script Kiddies   │ Curiosity,   │ Low           │ Opportunistic, easy      │
│                  │ Reputation   │               │ targets, not targeted    │
├──────────────────┼──────────────┼───────────────┼──────────────────────────┤
│ Competitors      │ Corporate    │ Variable      │ Industry competitors     │
│                  │ espionage    │               │                          │
└──────────────────┴──────────────┴───────────────┴──────────────────────────┘
```

### 8.2 Nation-State APT Groups

```
APT (Advanced Persistent Threat): sophisticated, long-term intrusion campaign

Key characteristics:
  Advanced: Custom tools, zero-days, sophisticated evasion
  Persistent: Maintain access for months or years
  Threat: Driven by specific geopolitical objectives

Documented APT Groups and Their Targeting:

APT29 (Cozy Bear) — Russia (SVR):
  Victims: SolarWinds (2020), DNC (2016), COVID-19 vaccine research
  TTPs: Supply chain compromise, password spraying, phishing, living-off-the-land
  Attribution: US/UK government official attributions
  
APT28 (Fancy Bear) — Russia (GRU):
  Victims: DNC (2016), World Anti-Doping Agency, Ukrainian infrastructure
  TTPs: Spear phishing, credential harvesting, destructive malware (NotPetya supply chain)
  
Sandworm — Russia (GRU Unit 74455):
  Victims: Ukrainian power grid (2015, 2016), NotPetya (2017), Viasat satellite (2022)
  TTPs: Destructive malware (BlackEnergy, Industroyer, Cyclops Blink)
  OT Focus: Most advanced OT attack capability of any known threat actor
  
APT41 — China (dual espionage + financial crime):
  Victims: Healthcare, telecom, technology companies globally
  TTPs: Supply chain attacks, exploitation of public-facing apps, Cobalt Strike
  
Volt Typhoon — China (critical infrastructure pre-positioning):
  Victims: US water utilities, energy, transportation, communications
  TTPs: Living-off-the-land (LOLBins), no malware, use existing tools
  Goal: Pre-position for potential conflict, not active espionage
  2024: FBI and CISA disclosed Volt Typhoon compromised multiple critical infrastructure
  
Lazarus Group — North Korea (DPRK):
  Victims: Banks (SWIFT fraud), cryptocurrency exchanges, Sony Pictures
  TTPs: Spear phishing, supply chain attacks, custom malware
  Motivation: Financial (generates revenue for DPRK regime sanctions evasion)
```

### 8.3 Ransomware Groups

```
Evolution of Ransomware 2013-Present:

2013: CryptoLocker — first major ransomware, Bitcoin payments
2017: WannaCry (EternalBlue) — 200,000 victims, wormable
2017: NotPetya — disguised as ransomware, actually pure destructor
2019-present: Double extortion — encrypt AND steal data, threaten to publish
2020-present: Triple extortion — add DDoS as third pressure
2020-present: RaaS (Ransomware-as-a-Service) — operators rent to affiliates

Major active groups (as of 2024):
  LockBit 3.0: Most active RaaS, $91M+ collected from US victims alone
  BlackCat/ALPHV: Sophisticated, Rust-based ransomware, healthcare targets
  Cl0p: MOVEit (2023) — exploited zero-day to breach 2,000+ organisations
  Play: Used in attacks on Oakland CA (2023), publishing all data exfiltrated
  
Anatomy of a ransomware attack:
  Day 0:    Initial access (phishing, exposed RDP, VPN vulnerability)
  Day 1-7:  Lateral movement, privilege escalation
  Day 8-30: Data exfiltration (double extortion leverage)
  D-Day:    Ransomware deployment across all systems simultaneously
  
Why OT is increasingly targeted:
  Production downtime = immediate financial pressure
  Safety concerns add urgency to payment
  OT systems harder to restore from backup (specialist configuration)
  Example: Oldsmar Water Treatment (2021) — operator observed cursor moving
           Changed NaOH level from 111 ppm to 11,100 ppm (not ransomware
           but demonstrated OT attack surface)
```

### 8.4 Insider Threats

```
Insider threat categories:

Malicious Insider:
  Motivated: Financial gain (selling data/access), revenge, ideology
  Example: Capital One data breach (2019) — Paige Thompson, former AWS employee,
           exploited misconfigured WAF to steal 100M customer records
  Example: Edward Snowden — NSA contractor, exfiltrated classified documents
  
Negligent Insider (most common):
  No malicious intent but causes breaches through error or poor security practice
  Example: Clicking phishing links, using weak passwords, misconfiguring cloud storage
  Example: 2019 First American Financial — developer left 885 million records
           publicly accessible via URL manipulation
  
Compromised Insider:
  Legitimate employee whose credentials or account have been stolen
  The insider is a victim; their access enables the external attacker
  Example: Most APT campaigns involve compromised employee credentials at some point
  
Detection:
  User Entity and Behaviour Analytics (UEBA)
  DLP (Data Loss Prevention) monitoring
  Privileged Access Management (PAM) with session recording
  Anomaly detection: access at unusual hours, unusual data volumes, unusual destinations
```

```bash
# Threat intelligence and monitoring:

# Check if your IPs appear in threat intelligence feeds:
curl "https://www.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90" \
    -H "Key: YOUR_API_KEY" -H "Accept: application/json"

# Query VirusTotal for indicator:
curl "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8" \
    -H "x-apikey: YOUR_API_KEY" | python3 -m json.tool | grep "malicious"

# Check if domain is in threat intel:
curl "https://www.virustotal.com/api/v3/domains/suspicious.com" \
    -H "x-apikey: YOUR_API_KEY"

# MITRE ATT&CK correlation:
# Navigate to attack.mitre.org
# Each threat actor (APT group) has documented TTPs
# Map your controls against their known techniques

# Monitor for credential exposure (your organisation's credentials in breaches):
# HaveIBeenPwned API:
curl "https://haveibeenpwned.com/api/v3/breachedaccount/user@company.com" \
    -H "hibp-api-key: YOUR_KEY"
```

> **Key Insight:** Threat intelligence changes your security strategy from reactive ("respond to what happened") to proactive ("prepare for what this specific threat actor will likely do next"). Nation-state APTs use living-off-the-land techniques — native OS tools — specifically to evade signature-based detection. Against them, behaviour-based detection and comprehensive logging are more effective than AV/EDR signatures alone.

---

## 9. Attack Surface

### 9.1 Definition and Components

**Attack surface** is the sum of all points where an attacker could attempt to enter, extract data from, or cause harm to a system or organisation.

```
Attack Surface Components:

Digital Attack Surface:
  Network: All exposed IP addresses, ports, protocols
  Application: Every input field, API endpoint, web page
  Credentials: All accounts that can authenticate to systems
  Code: Software vulnerabilities in every line of code
  Cloud: Misconfigured buckets, exposed APIs, IAM misconfigurations
  Email: Phishing entry point
  
Physical Attack Surface:
  USB ports on devices
  Physical server access
  Printed documents
  Hardware supply chain
  
Human Attack Surface (Social Engineering):
  Employees who can be phished, vished, or manipulated
  Help desk procedures that can be socially engineered
  Third-party vendors with access to your systems
  
Supply Chain Attack Surface:
  Software dependencies (npm packages, PyPI, NuGet)
  Build pipeline (SolarWinds model)
  Hardware manufacturers
  Managed service providers (MSPs) with administrative access
```

### 9.2 Attack Surface Reduction

```
Principles of Attack Surface Reduction:

1. Eliminate what's not needed:
   Disable unused services and ports
   Remove unused accounts
   Remove unused software
   
2. Minimise exposure:
   Don't expose internal services externally
   Use VPN/private endpoints instead of public exposure
   
3. Harden what remains:
   Patch all remaining components
   Configure securely (disable defaults, apply hardening)
   
4. Monitor what you cannot eliminate:
   If you must expose something: monitor it intensively
   Log all access, alert on anomalies
```

```bash
# Attack surface discovery and reduction:

# Map your external attack surface:
# What IPs/domains do you own?
# What services are exposed to internet?

# External port scan of your own infrastructure:
sudo nmap -sS -sV -p- --open YOUR_PUBLIC_IP -oA external_scan

# Find exposed admin interfaces:
for port in 22 23 80 443 3389 5900 8080 8443 8888 9090; do
    nc -zw 2 YOUR_PUBLIC_IP $port 2>/dev/null && \
        echo "Port $port: EXPOSED to internet"
done

# Identify open cloud storage (if using AWS):
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
    xargs -I{} aws s3api get-bucket-acl --bucket {}
# Look for "AllUsers" or "AuthenticatedUsers" = public bucket

# Find shadow IT / unknown external assets:
# Certificate transparency logs reveal all subdomains:
curl "https://crt.sh/?q=%25.yourdomain.com&output=json" | \
    python3 -c "import json,sys; [print(c['name_value']) for c in json.load(sys.stdin)]" | \
    sort -u

# Subdomain enumeration:
subfinder -d yourdomain.com -silent | sort -u | tee /tmp/subdomains.txt
# Each subdomain = potential attack surface asset

# Check for exposed sensitive paths:
for path in /.git /wp-admin /.env /phpinfo.php /server-status /actuator/health; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://yourdomain.com$path")
    [ "$code" != "404" ] && echo "$code: https://yourdomain.com$path"
done

# Reduce local attack surface:
sudo systemctl list-unit-files --type=service | grep enabled  # Running services
sudo systemctl disable service_not_needed                      # Disable unnecessary
sudo ufw status                                                # Firewall status
sudo ufw enable                                                # Enable firewall
sudo ufw default deny incoming                                 # Default deny
sudo ufw allow 22/tcp                                          # Allow only needed
```

**OT Attack Surface:**

```
OT attack surface has unique characteristics:

External exposure (should be minimal but often isn't):
  SCADA systems inadvertently connected to internet (Shodan shows thousands)
  Remote access VPN portals (vulnerable to VPN CVEs)
  Historian servers with dual-homed connections (IT + OT)
  
Internal attack surface:
  Engineering workstations (Windows, often unpatched, running SCADA software)
  HMI systems (Windows XP/7 — often cannot be upgraded, vendor lock-in)
  All Modbus/DNP3 devices accessible from control network (no auth)
  USB ports on PLCs and workstations (malware entry via USB)
  
Third-party attack surface:
  Vendor remote access (often direct into control network)
  VPN accounts for maintenance that persist after contract ends
  PLC programming software downloaded from vendor sites (supply chain)
  
Search exposed OT on Shodan:
  shodan search "port:502" (Modbus)
  shodan search "port:102" (S7comm — Siemens PLCs)
  shodan search "port:20000" (DNP3)
  shodan search "BACnet" port:47808
  
Attack surface reduction for OT:
  Network segmentation (Purdue Model zones)
  Eliminate all internet-facing OT components
  Remove all vendor remote access when not actively needed
  Disable USB ports on OT systems (Group Policy, physical blockers)
  Patch windows systems even if SCADA vendor hasn't validated
  (with proper change management and testing)
```

> **Key Insight:** You cannot secure what you don't know exists. The first step of attack surface management is discovering your complete surface — including shadow IT, forgotten assets, abandoned cloud resources, and third-party connections. Attackers discover your assets with the same tools (Shodan, certificate transparency, subdomain enumeration) — you should know your attack surface better than they do.

---

## 10. Defence in Depth

### 10.1 The Concept

Defence in Depth (DiD) is the principle of using multiple, overlapping security controls across different layers, so that failure of any single control does not result in complete compromise.

```
Defence in Depth Model:

         Physical Security
              │
        Network Security
              │
         Host Security
              │
       Application Security
              │
         Data Security
              │
         User Security

Each layer:
  Provides controls that the layers above and below cannot
  Slows attacker progress (forces lateral movement, privilege escalation)
  Creates detection opportunities (attacker behaviour visible at each layer)
  Limits blast radius if one layer fails
```

### 10.2 Layers in Practice

```
Physical:
  Guards, access cards, cameras, biometrics
  Locked server rooms, equipment cages
  Cable locks, device tracking
  Attack stopped: prevents physical access to hardware

Network:
  Firewalls, IDS/IPS, network segmentation, DMZ
  VPN for remote access, NAC for device admission
  VLAN isolation, WAF for web applications
  Attack stopped: prevents lateral movement, limits blast radius

Host:
  OS hardening (CIS benchmarks, STIG)
  Antivirus/EDR, host-based firewall
  Patch management, FIM (file integrity monitoring)
  Disable unnecessary services
  Attack stopped: prevents malware execution, detects compromise

Application:
  Secure coding practices, SAST/DAST scanning
  Input validation, output encoding
  Authentication (MFA), session management
  WAF, API gateway
  Attack stopped: prevents SQL injection, XSS, authentication bypass

Data:
  Encryption at rest (AES-256), encryption in transit (TLS 1.3)
  DLP, data classification
  Backup and recovery
  Database activity monitoring
  Attack stopped: limits impact of breach, enables recovery

User:
  Security awareness training
  Phishing simulation
  Clear policies and procedures
  Background checks for privileged roles
  Attack stopped: reduces social engineering success rate
```

### 10.3 Castle Analogy and Its Limits

```
Traditional security: Castle model
  Strong perimeter (moat, walls) = firewall
  "If they're inside, they're trusted"
  
  Problem: Once perimeter is breached, attacker has full castle
  
DiD improvement:
  Multiple walls (network segmentation)
  Guards inside (EDR, monitoring)
  Locked rooms (file permissions, encryption)
  Audit trails (comprehensive logging)
  
But even DiD has limits:
  All layers can be defeated in theory
  Complexity of DiD creates management overhead
  Layered controls must be monitored, not just deployed
  
Modern improvement: Zero Trust (see Section 13)
  Don't trust based on location
  Verify every access, every time
  Assume breach — hunt for threats already inside
```

```bash
# Verify defence-in-depth controls are in place:

# Network layer check:
sudo iptables -L -n -v | grep -c "ACCEPT\|DROP\|REJECT"  # Active firewall rules
sudo netstat -tulnp | grep "0.0.0.0:" | grep -v "127.0.0.1"  # Internet-exposed services

# Host layer check:
which auditd && sudo systemctl status auditd               # Audit daemon
which aide && aide --check 2>/dev/null | head -5           # File integrity
sudo systemctl status fail2ban                              # Brute force protection
sudo ufw status | head -5                                   # Host firewall

# Application layer check:
curl -sI https://target.com | grep -iE "x-frame|content-security|hsts|x-content-type"
# Missing headers = missing application-layer controls

# Data layer check:
sudo cryptsetup status /dev/sda 2>/dev/null | grep "type"   # Disk encryption
ls -la /etc/ssl/                                             # Certificate management

# Monitoring check (is there visibility at each layer?):
sudo systemctl status rsyslog                               # Logging running?
cat /etc/rsyslog.d/*.conf | grep "@@"                      # Remote syslog configured?
```

---

## 11. Least Privilege Principle

### 11.1 Definition

**Least Privilege:** Every user, process, and system should have only the minimum permissions required to perform their specific function — nothing more.

```
Principle in practice:

Not least privilege:
  Database administrator account used for everything:
    Running DB server → SYSTEM / root
    Backing up databases → full admin
    Reading application data → full admin
    
Least privilege applied:
  DB server process: runs as 'mysql' user (no shell, no login, only DB access)
  Backup account: read-only on backup directories only
  Application service account: SELECT on specific tables only
  DBA account: full admin, but only used from management workstation, 
               with MFA, and all actions logged
```

### 11.2 Why Least Privilege Matters — Real Impact

```
WannaCry (2017) — Least Privilege Failure:
  Many infected machines ran as local Administrator
  Ransomware inherited full admin rights
  Encrypted ALL accessible files including network shares
  If processes ran as limited users: ransomware encrypts only that user's files
  Least privilege = contained blast radius

Pass-the-Hash / Mimikatz — Least Privilege Failure:
  If every machine has the same local administrator password:
  Compromise one machine → extract hash → use on all machines (PTH)
  
  Fix (Microsoft LAPS): 
  Unique, randomised local admin password per machine
  Stored in AD, accessible only to authorised admins
  
  Even better: disable local admin account entirely (CIS benchmark)
  
SolarWinds-type attacks:
  Build pipeline had excessive permissions
  Compromise of build system = ability to modify any software, sign it
  Least privilege: build system should not have production signing keys
  Production signing: isolated, hardware-backed, requires human approval
```

### 11.3 Just-in-Time (JIT) Privilege

```
JIT Privilege: escalate permissions only when needed, revoke immediately after

Traditional (persistent privilege):
  Admin has always-on domain admin rights
  Risk: if account compromised at any moment, attacker has domain admin
  
JIT (temporary privilege):
  Admin has limited standard user account normally
  To perform admin task: request elevated access via PAM (CyberArk, BeyondTrust)
  PAM grants temporary access (1 hour, specific system)
  PAM records the entire session
  Access revoked automatically after session
  
Benefits:
  Attacker who steals credentials gets no privilege (not currently elevated)
  All privileged actions are recorded (accountability)
  Unusual access requests are visible and auditable
  
Azure PIM (Privileged Identity Management):
  Users are "eligible" for roles but not permanently assigned
  To activate: request role, provide MFA, provide justification
  Role activates for configured duration (e.g., 8 hours max)
  All activations logged to Azure AD audit log
```

```bash
# Implement and audit least privilege:

# Audit Linux sudo privileges:
sudo cat /etc/sudoers | grep -v "^#\|^$"
sudo cat /etc/sudoers.d/*
# Look for: ALL=(ALL) ALL or NOPASSWD: ALL — these are overprivileged

# Check running services and their privilege level:
ps -eo user,pid,comm | sort | uniq -c | sort -rn | head -20
# Processes running as root that shouldn't be

# Check for setuid/setgid binaries (potential privilege escalation):
find / -perm -4000 -o -perm -2000 2>/dev/null | \
    grep -v "^/proc\|^/sys"
# Non-standard SUID files = investigate

# Check Windows local admins:
net localgroup administrators
# Only IT service accounts and break-glass accounts should be here

# Check Windows service account privileges:
sc qc service_name                    # Check what account a service runs as
# Services running as LocalSystem = highest risk if exploited

# Implement principle via Linux capabilities (instead of full root):
sudo setcap cap_net_raw+eip /usr/bin/ping    # ping only needs raw socket
getcap -r / 2>/dev/null               # List all capability-enabled binaries
```

> **Key Insight:** Least privilege is the single most effective control for limiting the blast radius of any compromise. WannaCry encrypted entire networks because processes ran as administrators. Ransomware running as a limited user can only encrypt that user's files. JIT privilege means even if admin credentials are stolen, they provide no privilege until explicitly elevated — eliminating the persistent privileged account as an attack target.

---

## 12. Separation of Duties

### 12.1 Definition

**Separation of Duties (SoD):** Ensuring that no single person has control over all aspects of a critical operation. Requires multiple people to complete critical actions.

```
Why it matters:

Without SoD:
  Single accountant: creates vendor, approves invoice, initiates payment
  One person controls entire financial transaction
  If malicious: can create fictitious vendor and pay themselves
  If compromised: attacker has full financial control
  
With SoD:
  Person A: creates vendor in system
  Person B (supervisor): approves new vendor
  Person C: creates invoice
  Person D: approves invoice payment
  Person E: initiates bank transfer (requires Person D's approval code)
  
  For fraud to succeed: attacker must compromise multiple people/systems
  
Principle in IT:
  Developer should not deploy their own code to production
    (could introduce malicious code without review)
  Security team should not manage the logs they are measured against
    (could manipulate metrics)
  Network admin should not also be the security monitor
    (could cover tracks after policy violation)
  Backup admin should not control the systems being backed up
    (could delete both production and backup)
```

### 12.2 SoD in Technology Controls

```
Code Review as SoD:
  No code reaches production without peer review
  Developer → Pull Request → Peer Review → Merge → CI/CD → Staging → Approval → Production
  
  Critical: review must be meaningful — rubber-stamp approval defeats purpose
  
Four-Eyes Principle:
  Any critical action requires two people to approve
  Common in:
    Banking: large transfers require two authorisers
    Change management: changes require change advisory board
    Cryptography: split knowledge key ceremonies (HSM administration)
    Nuclear weapons: two-person integrity rule (two keys simultaneously)
    
SoD in Access Control:
  Privileged Access Management: admin cannot grant themselves more access
  AD: user who can modify AD groups should not be able to modify audit logs
  Database: DBA who can read all data should not control application authentication
```

```bash
# Implement and verify separation of duties:

# Git branch protection (enforce code review via GitHub API):
curl -X PATCH "https://api.github.com/repos/ORG/REPO/branches/main/protection" \
    -H "Authorization: token YOUR_TOKEN" \
    -H "Accept: application/vnd.github.v3+json" \
    -d '{
        "required_pull_request_reviews": {
            "required_approving_review_count": 2,
            "dismiss_stale_reviews": true
        },
        "required_status_checks": {"strict": true, "contexts": ["CI/Tests"]},
        "enforce_admins": true
    }'

# Linux: make audit logs immutable:
sudo chattr +i /etc/audit/auditd.conf  # Cannot modify without removing attribute first

# Require two-factor for privilege escalation (PAM):
# /etc/pam.d/sudo: auth required pam_google_authenticator.so

# Check for SoD violations — user who can both reset passwords AND manage audit:
# (requires AD access)
# Get-ADUser -Filter * -Properties MemberOf | Where-Object {
#     $_.MemberOf -match "Account Operators" -and $_.MemberOf -match "Event Log Readers"
# }
```

> **Key Insight:** Separation of Duties is the only control that protects against malicious insiders with legitimate access. No technical control prevents a DBA with full database access from stealing data — but requiring two people to authorise exports, using DLP to detect anomalous queries, and session recording creates both deterrence and detection. The four-eyes principle applied to critical operations converts single points of failure into conspiracy requirements.

---

## 13. Zero Trust Model

### 13.1 The Paradigm Shift

Traditional security assumed that everything inside the network perimeter was trusted. Zero Trust rejects this assumption entirely.

```
Traditional Model ("Castle and Moat"):
  Inside network = trusted
  Outside network = untrusted
  If you're on the VPN → you're trusted → access everything
  
  Fatal flaw: attackers who breach the perimeter have free movement inside
  
Zero Trust Model:
  "Never trust, always verify"
  Location in network conveys NO trust
  Every access request verified:
    Who is the user? (identity)
    What device are they using? (device health)
    What are they trying to access? (resource)
    Is this request normal for them? (behaviour)
    What is the minimum access needed? (least privilege)
  
  Even valid internal traffic is verified continuously
  Even privileged users are verified per-request
```

### 13.2 Zero Trust Architecture Components

```
NIST SP 800-207 Zero Trust Architecture:

Policy Engine (PE): Makes access decisions
  Input: identity, device posture, resource, context, policy
  Output: ALLOW / DENY / ALLOW with conditions
  
Policy Administrator (PA): Enforces decisions from PE
  Establishes/terminates sessions
  Issues credentials for specific sessions
  
Policy Enforcement Point (PEP): Gatekeeper
  Sits between user and resource
  All traffic passes through PEP
  PEP checks with PA before allowing connection
  
Identity Provider (IdP): Source of identity truth
  Azure AD, Okta, Ping Identity
  Provides: authentication, MFA, attributes
  
Device Trust: Certificate-based device authentication
  MDM (Intune, Jamf) attestation
  Device health: OS version, patch status, AV status, encryption
  
Network: Software-Defined Perimeter
  Resources not discoverable without authorisation
  Micro-segmentation: every workload in its own segment
  
Monitoring: Full visibility into all access
  Every request logged
  Continuous risk scoring
  Anomaly detection
```

### 13.3 Zero Trust Implementation

```
Zero Trust Maturity Model (CISA, 2023):

Identity:
  Traditional: Username/password
  Initial: MFA added
  Advanced: Phishing-resistant MFA (FIDO2), identity risk scoring
  Optimal: Continuous identity verification, behaviour analytics
  
Devices:
  Traditional: No device check
  Initial: MDM enrolled devices required
  Advanced: Device compliance gating access (health check)
  Optimal: Continuous device monitoring, automated remediation
  
Networks:
  Traditional: Flat trusted internal network
  Initial: VLANs, basic segmentation
  Advanced: Micro-segmentation, software-defined perimeter
  Optimal: ZTNA (Zero-trust network access), no implicit trust anywhere
  
Applications:
  Traditional: All internal apps accessible on network
  Initial: Application proxy, published selectively
  Advanced: Per-app MFA, session recording for sensitive apps
  Optimal: Fine-grained authorisation per request, behaviour analytics
  
Data:
  Traditional: Perimeter protects data, no internal DLP
  Initial: Data classification, basic DLP
  Advanced: DRM (rights management), zero-trust data access
  Optimal: Automated data protection based on sensitivity
```

```bash
# Zero Trust implementation verification:

# Check: are internal resources reachable without authentication?
curl -s -o /dev/null -w "%{http_code}" http://internal-app.company.local/
# 401/403: correct (requires auth)
# 200: no authentication required = zero trust violation

# Check: is VPN the only way to access internal resources?
nmap -p 80,443,8080,3389,22 internal_hostname_from_internet
# Ports accessible directly from internet = perimeter failure

# Verify MFA is enforced (attempt login with password only — should fail):
# If login succeeds without second factor: MFA not enforced

# Check Cloudflare Access / ZTNA policy enforcement:
curl -I https://protected-app.company.com/
# Should redirect to identity provider, not serve content directly

# Implement basic ZT — verify every session via nginx + oauth2-proxy:
# All requests require OAuth2 authentication before reaching the app
# No direct access without a valid, MFA-verified session token

# Verify micro-segmentation (from inside a workstation):
# Try to reach another workstation directly:
ping ANOTHER_WORKSTATION_IP
nc -zv ANOTHER_WORKSTATION_IP 445
# If succeeds: no micro-segmentation (flat network)
# If fails: micro-segmentation working correctly
```

**Zero Trust in OT/ICS:**

```
Zero Trust concepts applied to OT/ICS:

Challenge: many OT devices cannot authenticate themselves
  PLCs don't have certificates
  Field sensors have no identity mechanism
  
OT Zero Trust approach:

1. Zone/Conduit model (IEC 62443):
   Replace flat OT network with security zones
   All inter-zone traffic through verified conduits (firewalls)
   Devices inherit trust from zone membership
   
2. Identity at the boundary:
   Even if PLC has no identity, the engineering workstation accessing it does
   MFA on engineering workstation
   Session recording for all PLC access
   
3. Never trust the IT-OT connection:
   IT network is assumed compromised
   OT access from IT: through DMZ, jump server, protocol break
   One-way data flows where possible (data diode)
   
4. Micro-segmentation of OT zones:
   Instead of one OT VLAN: separate VLANs per process area
   Firewall between each area
   Attack contained to one process area if successful
   
5. Continuous monitoring:
   Baseline normal OT traffic (passive)
   Alert on any deviation
   Assume breach — always be looking for threat actors already inside
```

> **Key Insight:** Zero Trust is not a product — it is a security philosophy requiring architectural changes across identity, device, network, application, and data. The starting point for most organisations is always identity: enforce phishing-resistant MFA (FIDO2/WebAuthn) for all users, all applications, all the time. This single control eliminates the vast majority of credential-based attacks that represent the initial access vector in most documented breaches.

---

## 14. Module Summary

| Concept | Core Principle | Attack Scenario | Key Defence | OT/ICS Application |
|---------|---------------|-----------------|-------------|-------------------|
| **CIA — Confidentiality** | Only authorised parties see data | Eavesdropping, data exfiltration, credential theft | Encryption (TLS, disk), access controls, DLP | Process parameters, network topology protection |
| **CIA — Integrity** | Data has not been unauthorised modified | Supply chain tampering (SolarWinds), log modification, sensor spoofing (Stuxnet) | Cryptographic hashes, digital signatures, FIM, immutable logs | ICS protocol auth (IEC 62351), cross-validate sensors, SIS independence |
| **CIA — Availability** | Systems accessible when needed | DDoS, ransomware, SYN flood, disk exhaustion | Redundancy, DDoS mitigation, backups, patching | Highest priority in OT; redundant control paths; maintenance window patches |
| **Authentication** | Verify claimed identity | Phishing, brute force, credential stuffing, MFA fatigue, Kerberoasting | Phishing-resistant MFA (FIDO2), password managers, Kerberos hardening | Compensate for no-auth OT protocols with boundary auth and session recording |
| **Authorization** | Determine what identity may do | IDOR, privilege escalation, broken access control (OWASP #1) | Server-side checks every request, RBAC, ABAC, deny by default | Jump server ACLs, OT zone firewall rules, per-function access control |
| **Access Control** | Enforce auth/authz decisions | VLAN hopping, DAC bypass, SUID exploitation | 802.1X NAC, SELinux MAC, ACL auditing, remove SUID | Network segmentation, managed switch port security |
| **AAA** | Auth + Authz + Audit trail | Unattributed access, compliance gaps, incident reconstruction failure | RADIUS/TACACS+, centralised logging, SIEM | NERC CIP compliance, individual accounts, session logging for OT access |
| **Risk** | Threat × Vulnerability × Impact | Misallocated resources (patching low-risk, ignoring high-risk) | FAIR/CVSS-based prioritisation, risk register, ALE calculation | OT risk: availability/safety impact far exceeds data breach cost |
| **Threat Actors** | Who is targeting you and why | APT persistent access (SolarWinds), ransomware (Colonial), insider (Capital One) | Threat intelligence, TTP-based detection, sector-specific ISAC | Sandworm targets OT; Volt Typhoon pre-positioning in critical infrastructure |
| **Attack Surface** | Every entry point an attacker could use | Exposed SCADA on internet (Shodan), shadow IT, forgotten assets | Asset discovery, exposure reduction, continuous attack surface monitoring | Thousands of OT devices exposed on Shodan; vendor remote access scope |
| **Defence in Depth** | Overlapping controls at multiple layers | Single control failure → complete compromise | Layered controls: physical → network → host → app → data → human | Purdue model zones + firewalls + monitoring = OT DiD implementation |
| **Least Privilege** | Minimum necessary permissions only | WannaCry blast radius (admin accounts), lateral movement | LAPS, JIT privilege, service accounts with minimal rights | No shared "operator" accounts; application-specific accounts for HMI |
| **Separation of Duties** | No single person controls critical action | Insider fraud, malicious code deployment without review | Code review, 4-eyes principle, PAM for privileged access | Two-person rule for safety system changes; change advisory board |
| **Zero Trust** | Never trust, always verify — location conveys no trust | Lateral movement after perimeter breach (Colonial Pipeline), VPN-only perimeter bypass | Phishing-resistant MFA first; then ZTNA, micro-segmentation, continuous monitoring | Zone/conduit model; identity at boundary; assume breach posture |

---

> **Next Module:** [Stage 2.2 — Cryptography](./stage-2.2-cryptography.md)  
> **Previous Module:** [Stage 1.8 — Network Analysis Tools](../STAGE-01_Network-Fundamentals/stage-1.8-network-analysis-tools.md)  
> **Stage Index:** [Stage 2 README](./README.md)  
> **Series Index:** [Full Roadmap](../../README.md)

---

*This document is part of the Cybersecurity × OT/ICS Security Full Roadmap series. All techniques are presented for educational purposes, authorised security research, and defensive security practice. Always obtain proper authorisation before testing any system.*