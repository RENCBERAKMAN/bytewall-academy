# Stage 1.1 — Network Concepts
### From Zero to Cybersecurity Professional | Complete Roadmap Series

> **Series:** Cybersecurity × OT/ICS Security — Full Roadmap  
> **Stage:** 1 — Network Fundamentals  
> **Module:** 1.1 — Network Concepts  
> **Level:** Beginner → Advanced  
> **Prerequisites:** Stage 0 — Foundations (Complete)  
> **Next Module:** 1.2 — OSI Model

---

## Table of Contents

1. [Why Networks Are the Battlefield](#1-why-networks-are-the-battlefield)
2. [What Is a Network — First Principles](#2-what-is-a-network--first-principles)
3. [Network Types — LAN, WAN, MAN, PAN](#3-network-types--lan-wan-man-pan)
4. [How the Internet Actually Works](#4-how-the-internet-actually-works)
5. [Bandwidth, Latency, Jitter — The Performance Trinity](#5-bandwidth-latency-jitter--the-performance-trinity)
6. [Packets and Frames — How Data Travels](#6-packets-and-frames--how-data-travels)
7. [Unicast, Multicast, Broadcast — Addressing Modes](#7-unicast-multicast-broadcast--addressing-modes)
8. [Network Topologies and Their Security Implications](#8-network-topologies-and-their-security-implications)
9. [The Security Mindset on Networks](#9-the-security-mindset-on-networks)
10. [Hands-On Exercises](#10-hands-on-exercises)
11. [Further Reading and Resources](#11-further-reading-and-resources)

---

## 1. Why Networks Are the Battlefield

Every single cyberattack — without exception — involves a network at some point. An attacker scanning for open ports, a piece of ransomware calling home to its command-and-control server, credentials being exfiltrated, a phishing link being clicked, lateral movement from one compromised machine to another — all of it flows through network infrastructure.

When security professionals talk about "the attack surface," networks represent the largest and most exposed portion of it. An organisation might lock down every workstation perfectly, deploy every patch on time, and train every employee — and still be compromised because a misconfigured network segment allowed an attacker to reach a system they should never have been able to touch.

**For you specifically:** Understanding networks is not a prerequisite you get through to reach the "interesting" material. It IS the interesting material. The difference between a junior analyst who struggles and a senior professional who consistently finds things others miss comes down, very often, to how deeply they understand what is happening at the network level.

A packet captured in Wireshark is meaningless noise to someone who does not understand networks. To someone who does, it tells a complete story — where the connection came from, where it was going, what protocol was used, whether the traffic is normal or anomalous, whether an attack is in progress, and what the attacker was trying to do.

**For OT/ICS specifically:** Industrial networks are fundamentally different from enterprise IT networks in their topology, their protocols, and their failure modes. Power substations, manufacturing floors, and water treatment facilities run communication networks that were designed for reliability and real-time control — not security. Understanding networking from first principles is what allows you to reason about these environments clearly when you encounter them.

The security mindset for this stage: **The network is not a dumb pipe that moves bytes from A to B. It is a complex, stateful, layered system with its own logic, its own vulnerabilities, and its own forensic trail. Every byte that crosses a network leaves a story. Your job is to read it.**

---

## 2. What Is a Network — First Principles

### 2.1 The Core Definition

A network is any system that allows two or more devices to exchange information. That definition is deceptively simple. The complexity — and the security implications — emerge from how that exchange is implemented.

At the most fundamental level, a network requires three things:

**1. A medium** — something through which the signal travels. This can be:
- Copper wire (Ethernet, telephone lines)
- Optical fibre (glass or plastic that carries light signals)
- Radio waves (Wi-Fi, cellular, Bluetooth, Zigbee)
- Even lasers through air (free-space optical communication, used in some industrial settings)

**2. A protocol** — an agreed-upon language for communication. Without protocols, a device sending data and a device receiving data would have no way to understand each other. Protocols define everything: how to start a conversation, how to end it, how to handle errors, how to ensure data arrives in order, how to authenticate, how to encrypt.

**3. Addressing** — a way to identify who is talking and who should receive the data. Without addressing, data broadcast by one device would reach all devices but none would know if it was meant for them.

These three requirements — medium, protocol, addressing — map directly onto the OSI model you will study in Module 1.2. Understanding this mapping now will make OSI click immediately when you reach it.

### 2.2 Why Networks Exist — The Business and Operational Driver

This matters for security because understanding *why* a network exists tells you what it is supposed to protect and what its failure modes mean.

Networks exist to enable:

**Resource sharing** — printers, storage, software licenses. Before networks, every computer needed its own copy of everything.

**Communication** — email, messaging, video calls. The entire modern communication infrastructure is a network.

**Centralised management** — instead of configuring every machine individually, network-connected devices can be managed from a central point. Active Directory is the enterprise manifestation of this.

**Distributed computing** — breaking large problems across many machines. Cloud computing is this at massive scale.

**Real-time control** — in OT/ICS environments, networks carry control signals between sensors, controllers, and actuators. A factory's production line communicates over a network. A power substation's protection relays communicate over a network. Here, the network is not a convenience — it is the operational backbone. Disrupting it does not cause inconvenience; it causes physical consequences.

### 2.3 The Fundamental Problem Networks Solve — and Create

Networks solve the problem of physical distance. Information that would take hours to transport physically can be transmitted in milliseconds.

But networks also create new problems:

**Confidentiality:** Data crossing a network can be intercepted. Every packet that travels through shared infrastructure — routers, switches, ISPs — passes through hardware you do not control. Anyone with access to that hardware can potentially read your data. This is why encryption exists.

**Integrity:** Data can be modified in transit. An attacker positioned between sender and receiver (Man-in-the-Middle) can alter packets. This is why cryptographic authentication exists.

**Availability:** Networks can be overwhelmed, disrupted, or severed. A DDoS attack exploits this. A cut cable exploits this. For OT networks where availability means operational continuity, this is the most critical concern.

**Authentication:** How does a receiving device know that data is actually from who it claims to be from? IP addresses can be spoofed. MAC addresses can be faked. This is why authentication protocols exist — and why their weaknesses are so heavily exploited.

These four properties — confidentiality, integrity, availability, authentication — map directly onto the CIA triad and its extensions that you studied in Stage 0. Everything you learn about networks connects back to these fundamentals.

---

## 3. Network Types — LAN, WAN, MAN, PAN

### 3.1 Why Classification Matters for Security

Network type classification is not academic taxonomy. It tells you:
- What protocols are likely in use
- What the physical attack surface looks like
- What the regulatory environment is (some network types are regulated)
- What assumptions about trust are built into the design
- How an attacker would approach targeting it

### 3.2 PAN — Personal Area Network

**Scale:** Centimetres to ~10 metres  
**Purpose:** Connect personal devices in immediate proximity  
**Technologies:** Bluetooth (IEEE 802.15.1), Zigbee (IEEE 802.15.4), NFC, USB, IrDA  

```
Your body area:
Smartphone ←→ Smartwatch (Bluetooth)
Laptop ←→ Wireless mouse/keyboard (Bluetooth)
Phone ←→ Payment terminal (NFC, <10cm)
Medical device ←→ Monitoring station (Zigbee)
```

**Security Characteristics:**
- Short range limits the attack surface physically — attacker must be nearby
- But "nearby" in a crowded office, airport, or conference is not much of a limitation
- Bluetooth has had catastrophic vulnerabilities: BlueBorne (2017) allowed unauthenticated RCE on any Bluetooth device without pairing — just being in range was enough
- NFC proximity requirement (≤4cm) is often cited as a security feature, but relay attacks can extend this range significantly
- **OT/ICS relevance:** Zigbee is extensively used in smart meters, building automation, and some industrial sensor networks. Zigbee security depends heavily on proper key management, which is frequently misconfigured in deployments

**Real Attack Scenarios:**
- Bluetooth keyboard injection: send keystrokes to a paired device to execute commands
- NFC relay attack: intercept and relay contactless payment at a distance using two devices
- Zigbee network compromise: capture the network key from a commissioning device, decrypt all traffic

### 3.3 LAN — Local Area Network

**Scale:** Single building or campus, typically up to ~1km  
**Purpose:** Connect devices within an organisation or home  
**Technologies:** Ethernet (IEEE 802.3), Wi-Fi (IEEE 802.11), Token Ring (legacy)  
**Speed:** 100 Mbps to 400 Gbps (modern enterprise)

```
Typical Corporate LAN:
[Workstations] ←→ [Access Switch] ←→ [Distribution Switch] ←→ [Core Switch]
[Servers]      ←→ [Access Switch] ←→ [Distribution Switch] ←→ [Core Switch]
[IP Phones]    ←→ [Access Switch] ←→ (VLAN separation)
[IoT Devices]  ←→ [Access Switch] ←→ (Isolated VLAN)
```

**Security Characteristics:**

The LAN is where most enterprise security incidents happen. Because LAN traffic stays within the organisation's infrastructure, there is a common (and dangerous) assumption that LAN traffic is trustworthy. The Zero Trust model exists specifically to challenge this assumption.

**Why LAN is the primary attack surface:**
- Once an attacker gains initial access (phishing, exploitation), they are inside the LAN
- Traditional security models focused defences at the perimeter (where LAN meets WAN)
- Inside the LAN, lateral movement was often unimpeded — flat networks where every device could reach every other device
- ARP poisoning, VLAN hopping, SMB relay attacks, LLMNR/NBT-NS poisoning — all LAN-specific attacks
- Active Directory, which dominates enterprise identity, is a LAN technology

**Network Segmentation — The Most Important LAN Security Concept:**

A flat LAN is a security disaster. Proper segmentation divides the LAN into zones where communication between zones is explicitly controlled:

```
Segmented Corporate LAN:
[Internet] → [Firewall] → [DMZ: Web servers, Mail relays]
                       → [Corporate LAN]
                            ├── [User VLAN: Workstations]
                            ├── [Server VLAN: Internal servers]
                            ├── [Management VLAN: Network devices, IPMI]
                            ├── [VoIP VLAN: IP phones]
                            ├── [Guest VLAN: Visitors — no LAN access]
                            └── [OT VLAN: Industrial devices — strictly isolated]
```

Each zone communicates with others only through explicitly allowed firewall rules. A compromised workstation in the User VLAN cannot directly reach the Server VLAN without going through inspection.

**OT/ICS LAN specifics:** Industrial LANs are supposed to be isolated from corporate IT LANs. In practice, the IT/OT boundary is one of the most frequently misconfigured security controls in the industry. The Ukraine 2015 power grid attack used IT network access to reach OT networks that were inadequately segregated.

### 3.4 MAN — Metropolitan Area Network

**Scale:** City or metropolitan area, typically 5-50km  
**Purpose:** Connect multiple buildings or LANs within a geographic region  
**Technologies:** Fibre optic rings (SONET/SDH), Carrier Ethernet, MPLS  
**Who uses it:** Telecommunications providers, city governments, large universities, utility companies

```
City Infrastructure MAN:
[Hospital Campus] ←→ [City Fibre Ring] ←→ [City Hall]
[University]      ←→ [City Fibre Ring] ←→ [Library Network]
[Power Utility]   ←→ [City Fibre Ring] ←→ [Water Authority]
```

**Security Characteristics:**
- The physical medium crosses public spaces — fibre cables can be cut, tapped, or accessed at junction points
- Traffic often passes through multiple intermediate carriers where you have no visibility
- City-scale infrastructure MANs are critical infrastructure targets — disrupting a MAN can affect hospitals, utilities, and government services simultaneously
- BGP (Border Gateway Protocol) route hijacking can redirect MAN traffic through attacker-controlled infrastructure
- **Utility company MANs** connect substations, control centres, and distribution equipment — these are high-value OT targets precisely because they are networked

### 3.5 WAN — Wide Area Network

**Scale:** Across cities, countries, or globally  
**Purpose:** Connect geographically distributed networks  
**Technologies:** MPLS, SD-WAN, leased lines, satellite, undersea cables  
**The internet itself is the world's largest WAN**

```
Corporate WAN Example:
[HQ — Istanbul] ←→ [MPLS Provider] ←→ [Branch — Ankara]
[HQ — Istanbul] ←→ [MPLS Provider] ←→ [Branch — Izmir]
[HQ — Istanbul] ←→ [Internet VPN]  ←→ [Remote Workers]
[HQ — Istanbul] ←→ [Internet]      ←→ [Cloud Services]
```

**Security Characteristics:**

The WAN is fundamentally hostile territory. Traffic crosses infrastructure owned by third parties — ISPs, backbone providers, content delivery networks. This is the environment for which TLS/SSL was invented.

**BGP — The Internet's Routing Protocol and Its Security Problem:**
BGP (Border Gateway Protocol) is how routers on the internet decide where to send traffic. It is based on trust — networks announce which IP ranges they own, and other networks believe them. This design worked when the internet was small and all participants were known entities.

Today, BGP hijacking is a real and recurring threat:
- In 2018, a Pakistani ISP accidentally announced that it owned YouTube's IP ranges. YouTube was unreachable globally for ~2 hours.
- In 2010, China Telecom advertised routes for ~15% of internet traffic, routing it through China for ~18 minutes.
- In 2022, researchers documented dozens of suspicious BGP events suggesting intentional route manipulation.

BGP hijacking can be used to:
- Intercept traffic before it reaches its destination
- Perform SSL stripping attacks at scale
- Take over domains by intercepting DNS traffic
- Disrupt specific organisations' connectivity

RPKI (Resource Public Key Infrastructure) is the cryptographic solution — it allows networks to cryptographically sign their BGP route announcements. Adoption is growing but not universal.

**SD-WAN — The Modern Enterprise WAN:**
SD-WAN (Software-Defined WAN) overlays software-defined networking principles onto WAN infrastructure. It dynamically routes traffic across multiple links (MPLS + broadband internet + 4G) based on policy. SD-WAN has its own attack surface — the centralised controller is a high-value target, and misconfigured SD-WAN deployments have exposed management interfaces to the internet.

---

## 4. How the Internet Actually Works

### 4.1 The Physical Foundation

The internet is not a cloud. It is a very concrete physical infrastructure. Understanding its physical reality changes how you think about attacks, censorship, intelligence collection, and reliability.

**Undersea Cables:**
Approximately 95% of international internet traffic travels through undersea fibre optic cables. There are roughly 400 active submarine cable systems connecting every continent except Antarctica. Each cable is roughly the diameter of a garden hose and carries petabits of traffic per second.

These cables are:
- Vulnerable to physical damage (anchors, earthquakes, fishing trawlers)
- Landing stations where cables come ashore are intelligence collection points — the Snowden documents revealed that GCHQ and NSA tapped undersea cables at landing stations
- When a major cable is cut, traffic reroutes through other cables, but capacity constraints cause slowdowns affecting entire regions

**Internet Exchange Points (IXPs):**
IXPs are physical locations where different networks (ISPs, content providers, CDNs) connect and exchange traffic directly — "peering." Major IXPs include DE-CIX (Frankfurt), AMS-IX (Amsterdam), Equinix (multiple cities).

IXPs handle enormous traffic volumes and are significant surveillance and intelligence collection points. They are also single points of failure for regional connectivity.

### 4.2 IP Routing — The Logic Layer

When you send data across the internet, it does not travel a fixed, pre-determined path. It is routed dynamically, hop by hop, from router to router.

```
Your packet's journey from Istanbul to New York:
Your PC (192.168.1.5)
    ↓
Home Router (ISP gateway)
    ↓
ISP Router — Istanbul
    ↓
ISP Core Router — Istanbul
    ↓
Undersea Cable Landing Station — Portugal
    [Undersea fibre cable — Atlantic Ocean]
    ↓
Landing Station — New York
    ↓
Tier-1 ISP — New York
    ↓
Destination ISP — New York
    ↓
Target Server (203.0.113.1)
```

Each "hop" is a router that examines the destination IP address, looks up its routing table, and forwards the packet to the next hop. The routing table says: "For packets destined to 203.0.113.0/24, forward to next-hop 198.51.100.1."

**Traceroute reveals this path:**
```bash
traceroute google.com
# Each line is one hop
# 1  192.168.1.1      1ms    ← Your router
# 2  10.0.0.1         5ms    ← ISP router
# 3  195.175.39.1    12ms    ← ISP core
# 4  195.175.39.254  15ms    ← ISP backbone
# ...
# 18 142.250.185.78   98ms   ← Google's network
```

**Security Implication of Routing:**
You have no control over which routers handle your packets. Traffic between two Turkish endpoints might transit through routers in other countries depending on peering agreements. Each router along the path is a potential point of interception, modification, or blocking.

This is why end-to-end encryption (TLS) is designed to protect data even when the network infrastructure is untrusted. The encryption happens between your browser and the server — all the intermediate routers see is encrypted ciphertext.

### 4.3 DNS — The Internet's Phone Book

DNS (Domain Name System) translates human-readable names (google.com) into IP addresses (142.250.185.78) that routers use to route packets.

Understanding DNS is critical because:
- DNS is involved in almost every internet communication
- DNS attacks (poisoning, hijacking, tunnelling) are common and powerful
- DNS queries are often unencrypted — they reveal every site you visit
- C2 (Command and Control) communication for malware frequently uses DNS

**The DNS Resolution Process:**
```
You type: www.example.com

1. Check local DNS cache → not found
2. Query local resolver (your ISP or 8.8.8.8)
3. Resolver checks its cache → not found
4. Resolver queries root nameserver (.)
   "I need to find .com"
   Root server: "Ask the .com nameserver at 192.5.6.30"
5. Resolver queries .com nameserver
   "I need example.com"
   .com nameserver: "Ask example.com's nameserver at 205.251.196.1"
6. Resolver queries example.com's nameserver
   "I need www.example.com"
   Returns: "www.example.com → 93.184.216.34"
7. Resolver caches this result (TTL: 3600 seconds)
8. Returns 93.184.216.34 to your computer
9. Your computer connects to 93.184.216.34

Total time: typically 50-300ms (first query, uncached)
```

**DNS Security Issues:**
- DNS cache poisoning: inject false DNS records into a resolver's cache, causing victims to connect to attacker-controlled IP
- DNS hijacking: modify DNS settings on a device or router to redirect all queries to a malicious server
- DNS tunnelling: encode data in DNS queries to exfiltrate data or maintain C2 communication through firewalls that allow DNS traffic
- DNS over HTTP (DoH) and DNS over TLS (DoT) encrypt DNS queries, but also bypass traditional DNS monitoring — both a security improvement (privacy) and a detection challenge (visibility)

### 4.4 CDN — How Content Actually Reaches You

When you visit a major website, you are rarely connecting to the company's own server. You are connecting to a Content Delivery Network (CDN) — a globally distributed network of servers that cache and serve content from the closest location.

Major CDNs: Cloudflare, Akamai, Fastly, Amazon CloudFront, Google Cloud CDN.

```
Without CDN:
Turkish user → Request → Server in California → Response (200ms round trip)

With CDN:
Turkish user → Request → CDN node in Frankfurt → Response (20ms round trip)
                         (cached content served locally)
```

**CDN Security Relevance:**
- CDNs absorb DDoS attacks — they have enough bandwidth and distributed infrastructure to absorb volumetric attacks that would overwhelm a single server
- Cloudflare's "magic transit" and similar services can protect infrastructure from DDoS even at the network layer
- CDN misconfigurations can expose origin server IPs (bypassing DDoS protection) or leak internal content
- WAF (Web Application Firewall) functionality is commonly embedded in CDN services
- CDNs see plaintext traffic even for HTTPS sites (TLS terminates at the CDN edge) — this is both a capability and a trust consideration

---

## 5. Bandwidth, Latency, Jitter — The Performance Trinity

### 5.1 Why These Matter for Security Professionals

Network performance metrics are not just for network engineers. They directly affect:
- Whether attacks are detectable (anomalous bandwidth usage is an IOC)
- How C2 channels are designed (attackers must stay within normal baseline traffic patterns to avoid detection)
- DDoS attack characterisation (bandwidth exhaustion vs latency degradation vs jitter-based attacks)
- OT network viability (real-time control requires strict latency and jitter bounds — exceeding them causes physical consequences)
- Forensic timeline reconstruction (network timing data helps reconstruct attack sequences)

### 5.2 Bandwidth — The Pipe Size

**Definition:** The maximum rate at which data can be transferred across a network link. Measured in bits per second (bps) and its multiples: Kbps, Mbps, Gbps, Tbps.

```
Common bandwidth references:
Home broadband (Turkey, 2026): 100 Mbps - 1 Gbps download
Enterprise WAN link:           1 Mbps - 10 Gbps
Undersea cable (single):       ~160 Tbps
Ethernet LAN:                  1 Gbps - 400 Gbps
Wi-Fi 6 (802.11ax):           up to ~9.6 Gbps theoretical
5G cellular:                   up to ~20 Gbps theoretical, typically 100-900 Mbps real

Bits vs Bytes — confusion source:
Network speeds: bits/second (lowercase b) → 100 Mbps
File sizes: bytes (uppercase B) → 10 MB/s
100 Mbps ÷ 8 = 12.5 MB/s actual file transfer speed
```

**Bandwidth vs Throughput vs Goodput:**
- **Bandwidth** — theoretical maximum capacity of the link
- **Throughput** — actual data transfer rate achieved (always ≤ bandwidth)
- **Goodput** — useful data transferred, excluding protocol overhead, retransmissions, headers

Real-world throughput is always less than bandwidth due to:
- Protocol overhead (headers in every packet)
- Network congestion
- Half-duplex limitations
- TCP flow control and congestion control
- Physical medium quality

**Security Relevance of Bandwidth:**

**DDoS characterisation:** A volumetric DDoS attack aims to exhaust bandwidth. If a target's link is 10 Gbps and the attacker sends 50 Gbps, the link is saturated — legitimate traffic is crowded out. Modern DDoS attacks have reached 3.47 Tbps (Microsoft Azure, November 2021).

**Exfiltration detection:** A workstation that normally transfers 100 MB/day suddenly transferring 50 GB overnight is an anomaly. Baseline bandwidth monitoring makes this detectable. Tools like NetFlow and IPFIX collect per-flow bandwidth statistics that enable exactly this type of detection.

**C2 traffic blending:** Sophisticated attackers design C2 (command and control) communication to blend with baseline traffic. They beacon at irregular intervals, keep bandwidth low, and mimic the size patterns of legitimate traffic (mimicking HTTPS web browsing, for example). Understanding baseline bandwidth is what makes abnormal traffic visible.

**OT/ICS critical point:** Industrial control networks are engineered for specific, low bandwidth and extremely low latency. A Modbus poll from an HMI to a PLC might transfer only 12 bytes. If that link suddenly shows kilobytes or megabytes of traffic, something is wrong — either an attack is in progress, a misconfigured device is broadcasting, or malware is active. Bandwidth anomalies in OT networks are extremely significant.

### 5.3 Latency — The Speed of Information

**Definition:** The time it takes for data to travel from source to destination. Also called round-trip time (RTT) when measuring the time for a packet to travel to a destination and back.

```
Latency components — where the delay comes from:

Propagation delay:   Physical travel time through the medium
                     Light in fibre: 200,000 km/s (~2/3 speed of light)
                     1000 km distance → ~5ms one-way propagation

Transmission delay:  Time to push all bits of a packet onto the link
                     1500-byte packet on 1 Gbps link = 12,000 bits / 1,000,000,000 bps = 0.012ms

Processing delay:    Time for routers/switches to process the packet header
                     Modern routers: microseconds

Queuing delay:       Time spent waiting in router buffers during congestion
                     Highly variable — the main source of variable latency

Total RTT = 2 × (propagation + transmission + processing) + queuing
```

**Real-world latency examples:**
```
Ping within the same LAN:          < 1ms
Ping to server in same city:       5-15ms
Ping Istanbul to Frankfurt:        ~30ms
Ping Istanbul to New York:         ~100ms
Ping Istanbul to Singapore:        ~180ms
Ping Istanbul to Sydney:           ~280ms
Ping to LEO satellite (Starlink):  20-40ms
Ping to GEO satellite:             ~600ms
```

**Why latency matters to security:**

**Timing attacks:** Cryptographic side-channel attacks often exploit timing variations in cryptographic operations. If an operation takes slightly longer when a certain key bit is 1 vs 0, measuring response times across thousands of requests can reveal the key. TLS implementations are carefully designed to be constant-time for this reason.

**Network reconnaissance:** Latency measurements reveal network topology. A host with 1ms ping is on the local network. A host with 30ms ping is regional. This tells an attacker whether a target is local infrastructure or remote. Traceroute maps the path, and latency at each hop reveals geographic boundaries.

**C2 beaconing detection:** Malware that beacons to a C2 server at regular intervals creates a detectable pattern in network timing. Statistical analysis of connection timing can identify beaconing even when the traffic volume and content are normal-looking. This is how network detection tools like Zeek identify malware that evades signature-based detection.

**OT/ICS critical point:** Real-time industrial control has strict latency requirements. IEC 61850 GOOSE messages (used for protection relay signalling in electrical substations) must be delivered within 4ms. If an attacker can introduce latency on an OT network — through a DoS attack, traffic injection, or network device compromise — the control system's real-time performance degrades. This is a form of cyber-physical attack where a network-level action causes physical consequences.

### 5.4 Jitter — The Chaos in the Pipe

**Definition:** The variation in latency over time. Formally, jitter is the standard deviation of packet delay. If some packets take 10ms and others take 50ms, the jitter is high even if the average is acceptable.

```
Low jitter (stable):
Packet 1: 20ms
Packet 2: 21ms
Packet 3: 19ms
Packet 4: 20ms
Jitter: ~1ms ← Consistent, predictable

High jitter (unstable):
Packet 1: 10ms
Packet 2: 85ms
Packet 3: 12ms
Packet 4: 140ms
Jitter: ~55ms ← Unpredictable, problematic
```

**What causes jitter:**
- Network congestion (packets queue in router buffers for varying amounts of time)
- Different routing paths (packets sometimes take different routes and arrive out of order)
- Physical layer interference (Wi-Fi especially, radio frequency interference causes variable retransmissions)
- CPU load on network devices

**Why jitter matters for security:**

**VoIP and video — the obvious case:** High jitter makes voice and video communication unintelligible. Voice data arrives out of order or with gaps. A jitter buffer compensates by reordering and smoothing, but it adds latency. VoIP over Wi-Fi is particularly susceptible.

**Jitter-based DDoS:** Some DoS attacks deliberately introduce jitter rather than dropping traffic. The connection stays up but becomes unusable. This is harder to detect than packet loss because the link appears operational.

**Network forensics:** Unusual jitter patterns can indicate active attacks. A man-in-the-middle attack introduces processing delay at the intercept point. An attacker modifying packets in transit adds a small but measurable delay. High-resolution packet capture timing analysis can detect these anomalies — this is one of the techniques used in intrusion detection at the network level.

**OT critical:** PROFINET, EtherNet/IP, and other industrial Ethernet protocols have jitter requirements measured in microseconds. High jitter on an OT network causes missed control cycles, which manifests as physical process instability. A targeted jitter-inducing attack on an industrial network can cause a controlled process to become erratic or fail without any obviously "malicious" network traffic.

### 5.5 Measuring Performance — The Tools

```bash
# Measure latency — ICMP ping
ping -c 10 8.8.8.8          # 10 packets to Google DNS
# Output shows: min/avg/max/stddev — that stddev IS jitter

# Measure path latency — traceroute
traceroute -n 8.8.8.8       # -n = no DNS resolution (faster)
# Each hop shows latency — latency that jumps suddenly indicates congestion point

# Measure bandwidth — iperf3 (requires server at destination)
# On server:
iperf3 -s
# On client:
iperf3 -c server_ip -t 30   # 30-second bandwidth test
iperf3 -c server_ip -u -b 100M  # UDP test at 100 Mbps (tests jitter too)

# Monitor real-time bandwidth per interface
iftop                        # Interactive bandwidth monitor per connection
nethogs                      # Bandwidth per process
bmon                         # Interface bandwidth statistics

# Measure DNS latency
dig @8.8.8.8 google.com      # Query specific DNS server
# Look for "Query time:" in output
```

---

## 6. Packets and Frames — How Data Travels

### 6.1 The Encapsulation Model

Data does not travel across networks as a single, continuous stream. It is broken into discrete units and wrapped in layers of headers — this is called **encapsulation**. Each layer adds its own header (and sometimes trailer) containing information relevant to that layer's function.

Understanding encapsulation is not academic — every time you analyse a packet capture in Wireshark, you are looking at these layers. Every time you write a network detection rule, you specify which layer and which field you are inspecting. Every network attack targets specific fields in specific headers.

```
Application layer produces: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

Transport layer adds TCP header:
[Source Port: 54321 | Dest Port: 80 | Seq: 100 | Ack: 0 | Flags: SYN | ...]
[Application Data: GET / HTTP/1.1...]
→ This unit is called a SEGMENT

Network layer adds IP header:
[Version: 4 | IHL | TOS | Total Length | ID | Flags | TTL: 64 | Proto: 6 | Checksum | Src: 192.168.1.5 | Dst: 93.184.216.34]
[TCP Segment]
→ This unit is called a PACKET

Data Link layer adds Ethernet header + trailer:
[Dst MAC: AA:BB:CC:DD:EE:FF | Src MAC: 11:22:33:44:55:66 | EtherType: 0x0800]
[IP Packet]
[FCS Trailer: checksum]
→ This unit is called a FRAME
```

The terminology matters:
- **Frame** — Layer 2 unit, contains MAC addresses, travels between adjacent network nodes
- **Packet** — Layer 3 unit, contains IP addresses, routed across networks
- **Segment** (TCP) / **Datagram** (UDP) — Layer 4 unit, contains port numbers, addresses applications

### 6.2 Frames — The Layer 2 Unit

A frame is the unit of data at the Data Link layer. It contains everything needed to move data between two directly connected devices on the same network segment.

**Ethernet Frame Structure:**
```
┌───────────────────────────────────────────────────────────────────────┐
│ Preamble │ Dest MAC │ Src MAC │ EtherType │ Payload (46-1500 bytes) │ FCS │
│  7 bytes │ 6 bytes  │ 6 bytes │  2 bytes  │                         │ 4B  │
└───────────────────────────────────────────────────────────────────────┘

Preamble: 7 bytes of alternating 1s and 0s to synchronise receiver clock
Dest MAC: 6-byte MAC address of destination (or FF:FF:FF:FF:FF:FF for broadcast)
Src MAC:  6-byte MAC address of sender
EtherType: What protocol is in the payload (0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6)
Payload:  The IP packet (or ARP message, etc.)
FCS:      Frame Check Sequence — CRC32 checksum to detect transmission errors
```

**Maximum Transmission Unit (MTU):**
The MTU is the maximum payload size a frame can carry. Standard Ethernet MTU is **1500 bytes**. This is why packets larger than 1500 bytes must be fragmented — split into multiple packets that are individually framed.

**Jumbo frames** (up to 9000 bytes payload) are used in data centre environments for performance — fewer frames = less header overhead = more efficient bandwidth use.

**Security implication of MTU:**
IP fragmentation is a classic attack vector. Fragmentation offsets in IP headers can be crafted to:
- Evade intrusion detection systems that only inspect the first fragment
- Cause denial of service through fragment buffer exhaustion (Teardrop attack)
- Bypass firewall rules that do not reassemble fragments before inspection

Modern firewalls perform fragment reassembly before inspection, but legacy systems and some embedded OT devices still don't.

**MAC Addresses — 48 bits of identity:**
```
MAC address: AA:BB:CC:DD:EE:FF
             ─────────────── ──────────
             OUI (24 bits)   Device ID (24 bits)
             Manufacturer    Specific device

OUI examples:
00:50:56 → VMware
00:0C:29 → VMware (alternative)
3C:22:FB → Apple
DC:A6:32 → Raspberry Pi
00:1A:11 → Google
```

**MAC addresses in security:**
- MAC addresses are only meaningful within the same Layer 2 network segment — they are replaced at each router hop
- MAC address spoofing is trivial: `ip link set eth0 address AA:BB:CC:DD:EE:FF`
- MAC filtering on Wi-Fi networks provides essentially no security — attackers sniff the network, identify an allowed MAC, and spoof it
- MAC addresses are used for device tracking in Wi-Fi networks — modern operating systems randomise MAC addresses for probe requests specifically to prevent this
- In forensics, MAC addresses in captured traffic reveal manufacturer and sometimes device model, which is useful for asset identification

### 6.3 Packets — The Layer 3 Unit

A packet is the unit of data at the Network layer. It contains the addressing information needed to route data across multiple networks.

**IPv4 Packet Header:**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─────────┬─────────┬──────────────────┬──────────────────────────┤
│ Version │   IHL   │ Type of Service  │       Total Length       │
│  4 bits │  4 bits │     8 bits       │         16 bits          │
├────────────────────┬───┬───┬─────────┴──────────────────────────┤
│   Identification   │ R │DF │MF│      Fragment Offset            │
│      16 bits       │   │   │  │          13 bits                │
├────────────────────┴───┴───┴─┬──────────────┬───────────────────┤
│   Time to Live (TTL)         │   Protocol   │  Header Checksum  │
│         8 bits               │    8 bits    │     16 bits       │
├──────────────────────────────┴──────────────┴───────────────────┤
│                    Source IP Address (32 bits)                   │
├─────────────────────────────────────────────────────────────────┤
│                  Destination IP Address (32 bits)               │
├─────────────────────────────────────────────────────────────────┤
│                    Options (variable) + Padding                  │
├─────────────────────────────────────────────────────────────────┤
│                    Data (payload)                                │
└─────────────────────────────────────────────────────────────────┘
```

**Critical fields for security:**

**TTL (Time to Live):**
Each router that forwards a packet decrements TTL by 1. When TTL reaches 0, the packet is dropped and an ICMP "Time Exceeded" message is sent back to the sender. This prevents packets from circulating forever on misconfigured networks.

TTL fingerprinting: Different operating systems start with different default TTLs:
```
Linux:   64
Windows: 128
Cisco:   255
macOS:   64

If you receive a packet with TTL=115, and Windows starts at 128:
128 - 115 = 13 hops away, likely a Windows machine
This is used in OS fingerprinting — nmap uses TTL as one signal
```

**Protocol field:**
Identifies the Layer 4 protocol: 6 = TCP, 17 = UDP, 1 = ICMP, 89 = OSPF, 50 = ESP (IPSec), 51 = AH (IPSec).

**IP Spoofing:**
The source IP field in a packet is set by the sender. There is no built-in verification. An attacker can craft packets with any source IP — this is IP spoofing. Limitations:
- Replies go to the spoofed address, not the attacker — so TCP (which requires a handshake) is generally not useful with spoofed IPs
- UDP-based attacks can use spoofed IPs effectively — amplification DDoS attacks (DNS amplification, NTP amplification) work exactly this way
- BCP38 (network ingress filtering) is an ISP-level best practice that drops packets with source IPs that are not routable from the customer's network — but not all ISPs implement it

### 6.4 Why Encapsulation Creates Security Complexity

Each encapsulation layer has its own header that can be:
- **Inspected** — for analysis, detection, and filtering
- **Manipulated** — for spoofing, evasion, and attack
- **Tunnelled** — one protocol can carry another (GRE tunnels IP, IP-in-IP, DNS tunnelling carries any data in DNS queries)

Tunnel within tunnel attacks bypass security controls by hiding inner protocol traffic:
```
Legitimate: [Ethernet][IP][TCP][HTTP][Payload]
Tunnelled:  [Ethernet][IP][UDP][DNS][Encoded C2 commands]

DNS is allowed through most firewalls.
An attacker who encodes C2 traffic as DNS queries bypasses firewall rules
that block direct TCP connections to attacker infrastructure.
```

This is why deep packet inspection (DPI) — which inspects all layers, including decrypting and inspecting TLS traffic — is a feature of modern security appliances. Perimeter security that only looks at IP addresses and ports is fundamentally blind to a significant portion of modern attack techniques.

---

## 7. Unicast, Multicast, Broadcast — Addressing Modes

### 7.1 The Fundamental Question: Who Receives This?

When a device sends data on a network, the addressing mode determines who receives it. This has direct security implications — some attacks work by abusing these addressing modes.

### 7.2 Unicast — One to One

```
[Device A] ──────────────────────────────→ [Device B]
           (Only Device B receives this)

Example: Your browser loading a web page
         192.168.1.5 → 93.184.216.34 (example.com)
```

Unicast is the dominant mode for all normal application traffic — web, email, file transfer, SSH, video calls. The destination is a single specific device identified by its MAC address (Layer 2) or IP address (Layer 3).

**Security characteristics:**
- Unicast traffic is "private" in the sense that only the intended recipient's NIC is supposed to process it
- **But:** On shared media (Wi-Fi, old hub-based networks), all devices receive all frames — NICs normally discard frames not addressed to them
- **Promiscuous mode:** A NIC can be configured to capture ALL frames, not just those addressed to it. This is how packet sniffers (Wireshark, tcpdump) work. On a Wi-Fi network, anyone nearby with a card in monitor mode can capture your unicast traffic. On a switched Ethernet network, this requires ARP poisoning to redirect traffic through the attacker.

### 7.3 Broadcast — One to All

```
[Device A] ──────────────────────────────→ [Device B]
                                         → [Device C]
                                         → [Device D]
                                         → [ALL devices in the broadcast domain]
```

**Layer 2 Broadcast:** Destination MAC = `FF:FF:FF:FF:FF:FF`. Every device on the same Layer 2 segment receives and processes this frame.

**Layer 3 Broadcast:** Destination IP = `255.255.255.255` (limited broadcast, stays on local subnet) or `192.168.1.255` (directed broadcast for 192.168.1.0/24 subnet).

**Protocols that use broadcast:**
- **ARP (Address Resolution Protocol):** "Who has IP 192.168.1.1? Tell 192.168.1.5" — broadcast because the destination MAC is not yet known
- **DHCP Discovery:** "I need an IP address" — broadcast because the client doesn't know the DHCP server's address
- **NetBIOS Name Service:** Legacy Windows name resolution — this is what LLMNR/NBT-NS poisoning attacks target
- **OSPF Hello packets:** Routing protocol neighbour discovery

**Broadcast domains:**
Every Layer 2 network segment is a broadcast domain — all devices in it receive all broadcasts. Routers do NOT forward broadcasts — they create boundaries between broadcast domains. This is why segmenting a large flat network with VLANs reduces broadcast traffic and limits the scope of broadcast-based attacks.

**Security attacks leveraging broadcast:**

**LLMNR/NBT-NS Poisoning (Responder):**
This is one of the most common and effective attacks in Active Directory environments, and it exploits broadcast-based name resolution.

```
Attack sequence:
1. User types: \\fileserver (but mistyped — server doesn't exist)
2. Windows tries: DNS → fails
3. Windows tries: LLMNR broadcast → "Who is 'fileserver'?"
4. All machines on the subnet receive this broadcast
5. Attacker's machine (running Responder) answers: "I am fileserver!"
6. Windows sends NTLM authentication to attacker
7. Attacker captures NTLMv2 hash
8. Hash cracked offline or used in relay attack

This requires NO prior access — just being on the same network segment.
This is why guest Wi-Fi must be isolated from corporate networks.
LLMNR and NBT-NS should be disabled in secure environments.
```

**Smurf Attack (historical but important):**
Send ICMP echo requests with spoofed source IP (victim's IP) to network broadcast address. All devices on the network reply to the victim. Amplification ratio = number of hosts on network.

**ARP Spoofing/Poisoning (uses broadcast):**
```
1. Attacker broadcasts ARP reply: "192.168.1.1 (gateway) is at MY_MAC"
2. All devices update their ARP cache with the false mapping
3. Traffic destined for the gateway now goes to attacker
4. Attacker forwards traffic to real gateway (transparent MITM)
5. Attacker can read, modify, or drop all traffic

Tools: arpspoof (dsniff), ettercap, Bettercap
Detection: Static ARP entries, ARP inspection on switches, anomaly detection
```

### 7.4 Multicast — One to Many (Specific Group)

```
[Device A] ──────────────────────────────→ [Device B]  ← subscribed
                                         → [Device D]  ← subscribed
                                           [Device C]  ← NOT subscribed (ignores)
                                           [Device E]  ← NOT subscribed (ignores)
```

Multicast sends to a specific group of interested recipients — not all devices, not just one. Devices must subscribe to multicast groups to receive them.

**Multicast addresses:**
- Layer 3: IPv4 Class D range: `224.0.0.0` to `239.255.255.255`
- Layer 2: MAC addresses starting with `01:00:5E` (IPv4 multicast) or `33:33` (IPv6 multicast)

**Protocols using multicast:**
- **OSPF:** `224.0.0.5` (all OSPF routers) and `224.0.0.6` (OSPF designated routers)
- **EIGRP:** `224.0.0.10`
- **PIM (Protocol Independent Multicast):** Routing protocol for multicast traffic
- **mDNS (Multicast DNS):** `224.0.0.251` — used by Apple Bonjour, Chromecast, network printer discovery
- **SSDP (Simple Service Discovery Protocol):** `239.255.255.250` — used by UPnP
- **Video streaming:** Live video distributed to multiple subscribers simultaneously
- **IEC 61850 GOOSE messages:** In electrical substations, GOOSE (Generic Object Oriented Substation Event) uses Ethernet multicast to distribute protection relay status to multiple subscribing devices

**Security relevance of multicast:**

**mDNS and SSDP — Information Leakage:**
mDNS and SSDP broadcasts reveal significant information about the network — device names, services, software versions. Attackers use tools like `avahi-browse` and `miranda` (UPnP exploitation) to enumerate these.

```bash
# Discover mDNS services on network (passive — just listen)
avahi-browse -a -t

# Discover SSDP services (UPnP)
python3 -c "
import socket, time
msg = 'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:ssdp:all\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\n\r\n'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(msg.encode(), ('239.255.255.250', 1900))
s.settimeout(3)
while True:
    try: print(s.recvfrom(1024)[0].decode())
    except: break
"
```

**IEC 61850 GOOSE — OT Attack Surface:**
GOOSE messages carry protection relay signals in electrical substations. They use multicast with no authentication in the basic standard. An attacker on the substation LAN can:
- Inject spoofed GOOSE messages to trigger protection relay operations
- Suppress legitimate GOOSE messages (blocking relay operation during a fault)
- Replay captured GOOSE messages

This is a real, demonstrated attack capability against electrical infrastructure. Stuxnet-era research showed that substation LAN access combined with GOOSE injection could cause breaker misoperation.

### 7.5 Anycast — One to Nearest (Bonus Topic)

Anycast is a routing technique where the same IP address is announced from multiple physical locations. Traffic is routed to the topologically nearest instance.

```
Same IP: 1.1.1.1 (Cloudflare DNS)
Announcement from: London, Frankfurt, New York, Singapore, São Paulo...
Your packet always routes to the nearest one automatically

Benefits:
- Automatic geographic load balancing
- DDoS resilience (attack traffic is distributed across all anycast nodes)
- Reduced latency (nearest node serves you)
```

Anycast is how major DNS providers (Cloudflare 1.1.1.1, Google 8.8.8.8), CDNs, and DDoS mitigation services work at global scale. Understanding anycast explains why a DDoS against 1.1.1.1 is much harder than DDoS against a single-server DNS — you would have to simultaneously overwhelm hundreds of geographically distributed nodes.

---

## 8. Network Topologies and Their Security Implications

This section is not in the original module outline but is essential for security professionals — network topology directly determines attack paths, blast radius of a compromise, and the effectiveness of security controls.

### 8.1 Physical vs Logical Topology

**Physical topology:** How devices are physically connected — cables, switches, their physical locations.

**Logical topology:** How data flows — the paths packets actually take, which may differ from physical connections (VLANs create logical separation on the same physical infrastructure).

Security operates primarily at the logical topology level — VLANs, routing policies, and firewall rules shape logical topology. But physical topology matters too — an attacker with physical access to a network cable or switch port can bypass all logical security controls.

### 8.2 Common Topologies and Their Security Profiles

**Star Topology (Dominant in modern LANs):**
```
        [Switch]
       /   |   \
  [PC1] [PC2] [PC3]
```
All devices connect to a central switch. The switch is a critical point of failure and control. Compromise the switch → control all traffic. Most enterprise LANs use hierarchical star (access → distribution → core).

**Bus Topology (Historical, still relevant in OT):**
```
[PC1]---[PC2]---[PC3]---[PC4]
         (shared medium)
```
All devices share a single communication medium. Any device can hear all traffic. Collision domains. This topology is still used in some industrial fieldbus systems (Modbus RTU on RS-485, CAN bus in automotive/industrial). A single compromised device can disrupt all communication.

**Ring Topology (Industrial networks):**
```
[PLC1] → [PLC2] → [Switch] → [HMI]
  ↑                              ↓
[IED] ← [Relay] ← [RTU] ← [Historian]
```
PROFIBUS, some IEC 61850 implementations, and industrial Ethernet with ring redundancy (RSTP/MRP) use ring topologies. Ring networks have high availability (two paths), but ring protocols (like RSTP) have been attacked — STP attacks can force topology recalculation and cause temporary outages.

**Mesh Topology (WAN, Wi-Fi mesh):**
```
[A] ←→ [B]
 ↕  ✕   ↕
[C] ←→ [D]
```
Every node connects to multiple others. Extremely redundant. The internet uses a form of mesh topology at the WAN level. Wi-Fi mesh networks use this for coverage. Hard to completely sever connectivity but provides multiple attack paths.

---

## 9. The Security Mindset on Networks

### 9.1 Every Network Is Hostile Until Proven Otherwise

The security principle underlying modern network design: **assume compromise**. A device on the network might be:
- An attacker's laptop they physically plugged in
- A legitimate device that has been compromised by malware
- A legitimate device being used maliciously by an insider
- A legitimate device with misconfigured settings

Network security controls must function correctly even when some network participants are actively adversarial. This is the foundation of the Zero Trust model.

### 9.2 The Network Knows Everything

Every packet that crosses a network is a piece of evidence. Network forensics — capturing and analysing network traffic — can reconstruct:
- What sites a user visited (from DNS queries and HTTP traffic)
- What files were transferred (from FTP, SMB, HTTP traffic)
- What commands were executed (from SSH session data, RDP session data)
- What credentials were used (from Kerberos tickets, NTLM challenges, plaintext protocols)
- What malware was present (from C2 beaconing patterns, known malware signatures)
- The timeline of an attack (from connection timestamps)

**This works for defenders reading attacker traffic. It also works for attackers reading network traffic on a network they have access to.**

### 9.3 The Core Attacker's Perspective on Networks

When an attacker gains a foothold on a network (initial access), their first questions are:
- What network am I on? What is the subnet? (IP address, subnet mask)
- What else is on this network? (ARP table, ping sweep, port scan)
- Where does this network connect to? (Default gateway, routing table)
- What services are running? (Port scan of discovered hosts)
- Can I reach other network segments? (Route table, probing other subnets)
- Is traffic being monitored? (IDS/IPS detection, response time to connection attempts)
- What protocols are in use? (Passive traffic analysis)

Each of these questions maps directly to network concepts. Understanding networks from first principles means you can think through both sides of this — what the attacker sees and how to detect it.

---

## 10. Hands-On Exercises

### Exercise 1: Map Your Network (30 minutes)

```bash
# On your Kali VM:

# 1. Determine your current network configuration
ip addr                              # Your IP and subnet
ip route                             # Default gateway and routing table
cat /etc/resolv.conf                 # DNS servers

# 2. Identify your broadcast domain
# If you are 192.168.1.50/24, your network is 192.168.1.0/24
# Broadcast is 192.168.1.255

# 3. Discover live hosts (ARP-based, Layer 2, no firewall evasion needed for local)
sudo arp-scan --localnet
# Or:
sudo nmap -sn 192.168.1.0/24        # Ping scan of entire subnet
# Record: how many hosts? What IPs?

# 4. Check ARP cache — who has communicated recently?
arp -a
ip neigh show

# 5. Measure latency to various destinations
ping -c 5 192.168.1.1               # Your gateway
ping -c 5 8.8.8.8                   # Google DNS (measure internet latency)
ping -c 5 1.1.1.1                   # Cloudflare DNS

# 6. Trace the path to a destination
traceroute -n 8.8.8.8               # Map the route
# Count hops, note where latency jumps — that jump indicates a geographic boundary

# 7. Capture raw traffic with tcpdump
sudo tcpdump -i eth0 -c 50 -n       # Capture 50 packets, no DNS resolution
sudo tcpdump -i eth0 broadcast      # Only broadcast traffic
# Observe: what protocols are using broadcast?
```

### Exercise 2: Broadcast Traffic Analysis (45 minutes)

```bash
# Capture and analyse broadcast traffic to understand what your network reveals

# 1. Capture all broadcast traffic for 60 seconds
sudo tcpdump -i eth0 -w /tmp/broadcast.pcap \
    'ether dst ff:ff:ff:ff:ff:ff or ip dst 255.255.255.255' &
sleep 60
kill %1

# 2. Analyse in Wireshark
wireshark /tmp/broadcast.pcap

# Questions to answer:
# - What protocols are using broadcast?
# - What device information is revealed by the broadcasts?
# - Can you identify device types from MAC OUIs?
# - What LLMNR/mDNS queries are visible (if any)?
# - What ARP traffic do you see?

# 3. Run Responder in analyse mode (no poisoning — observe only)
sudo responder -I eth0 -A           # -A = analyse mode only, no responses
# What name resolution broadcasts appear?
# This shows you what Responder would capture in an active attack
```

### Exercise 3: Packet Structure Deep Dive (1 hour)

```bash
# Capture and manually dissect packets to understand encapsulation

# 1. Capture HTTP traffic
sudo tcpdump -i eth0 -w /tmp/http.pcap port 80

# In another terminal, generate HTTP traffic:
curl http://neverssl.com

# 2. Open in Wireshark and examine:
wireshark /tmp/http.pcap

# For each packet, expand every layer:
# - Ethernet II header: source/dest MAC, EtherType
# - IPv4 header: source/dest IP, TTL, Protocol, fragmentation fields
# - TCP header: source/dest port, sequence/ack numbers, flags, window size
# - HTTP: method, URI, headers, body

# 3. Find the TCP handshake (SYN, SYN-ACK, ACK)
# Right-click → Follow → TCP Stream to see the entire conversation

# 4. Check the TTL to fingerprint the remote OS
# Filter: ip.dst == your_ip
# Look at TTL of incoming packets — 64=Linux/Mac, 128=Windows, 255=Cisco

# 5. Capture ICMP (ping) and observe packet structure
ping -c 3 8.8.8.8 &
sudo tcpdump -i eth0 -w /tmp/icmp.pcap icmp
wireshark /tmp/icmp.pcap
# Observe ICMP echo request vs echo reply, sequence numbers, TTL
```

### Exercise 4: Bandwidth and Latency Measurement (30 minutes)

```bash
# Measure actual network performance metrics

# 1. Latency + jitter measurement
ping -c 100 8.8.8.8
# From the summary line, note: min/avg/max/stddev
# stddev IS jitter — how variable is the latency?

# Compare:
ping -c 100 $(ip route | grep default | awk '{print $3}')  # Gateway (LAN)
ping -c 100 8.8.8.8                                          # Internet

# 2. Path latency analysis with traceroute
mtr 8.8.8.8                         # Interactive traceroute with statistics
# Run for 30 seconds, observe:
# - Where does latency jump? (Geographic or ISP boundary)
# - Where is packet loss? (Overloaded router)
# - How consistent is each hop? (Jitter per hop)

# 3. Bandwidth test (if iperf3 server available)
# Run your own: on any Linux machine you can SSH into:
iperf3 -s                            # Start server
# On client:
iperf3 -c server_ip                  # Test TCP throughput
iperf3 -c server_ip -u -b 0         # Test UDP (unlimited — shows max)
iperf3 -c server_ip --bidir         # Bidirectional test

# 4. Python jitter measurement script
python3 << 'PYTHON'
import subprocess, re, statistics

def measure_ping(host, count=20):
    result = subprocess.run(
        ['ping', '-c', str(count), host],
        capture_output=True, text=True
    )
    times = re.findall(r'time=(\d+\.?\d*)', result.stdout)
    times = [float(t) for t in times]
    if times:
        print(f"\nTarget: {host}")
        print(f"Packets: {len(times)}")
        print(f"Min: {min(times):.2f}ms")
        print(f"Max: {max(times):.2f}ms")
        print(f"Avg: {statistics.mean(times):.2f}ms")
        print(f"Jitter (stddev): {statistics.stdev(times):.2f}ms")

measure_ping("192.168.1.1")   # Gateway
measure_ping("8.8.8.8")       # Internet
PYTHON
```

### Exercise 5: Unicast vs Broadcast Capture (30 minutes)

```bash
# See the difference between unicast and broadcast at the packet level

# 1. Capture broadcast traffic
sudo tcpdump -i eth0 -n -e 'ether dst ff:ff:ff:ff:ff:ff'
# -e = show link-level (Ethernet) headers including MAC addresses
# Observe: what protocols send to ff:ff:ff:ff:ff:ff?

# 2. Trigger an ARP broadcast manually
# In another terminal:
sudo arping -I eth0 -c 3 192.168.1.1
# Back in tcpdump: observe the ARP who-has broadcast

# 3. Observe multicast traffic
sudo tcpdump -i eth0 -n -e 'ether dst 01:00:5e:00:00:00/ff:ff:ff:00:00:00'
# This filter captures all IPv4 multicast (starts with 01:00:5e)
# What do you see? mDNS? OSPF? SSDP?

# 4. Set NIC to promiscuous mode and observe all traffic
sudo ip link set eth0 promisc on
sudo tcpdump -i eth0 -n -e -c 100  # Capture 100 frames in promisc mode
sudo ip link set eth0 promisc off  # Turn off after exercise
# Observe: are you seeing traffic not addressed to your MAC?
# (On a switched network, probably not — switches only send relevant traffic)
# On Wi-Fi in monitor mode, you would see all traffic
```

---

## 11. Further Reading and Resources

### Foundational Papers and RFCs

These are primary sources — the actual specifications that define how these technologies work. Security professionals read RFCs because the attack surface often exists in edge cases of the specification.

- **RFC 791** — Internet Protocol (IPv4). The original IP specification. Sections on fragmentation are particularly relevant.
- **RFC 826** — ARP. Remarkably short — read it completely. Understanding the simplicity of ARP makes ARP poisoning obvious.
- **RFC 1918** — Address Allocation for Private Internets. Defines 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
- **RFC 4271** — BGP-4. Understanding BGP is essential for understanding internet-scale routing vulnerabilities.
- **RFC 4443** — ICMPv6. Understanding ICMP is essential for understanding ping flood, redirect, and other ICMP-based attacks.

### Books

- **"Computer Networks" — Andrew Tanenbaum.** The gold standard textbook. Dense but complete. Every network professional should read chapters 1-4.
- **"Network Security Assessment" — Chris McNab (O'Reilly).** Directly applicable to security assessments. Third edition covers modern techniques.
- **"The Practice of Network Security Monitoring" — Richard Bejtlich.** How to build a network security monitoring programme using open-source tools. Practical and excellent.
- **"Silence on the Wire" — Michal Zalewski.** A unique perspective on network security — passive eavesdropping, timing attacks, and the information leaked by network traffic. Essential reading.

### Tools to Install and Master

```bash
# These are the core network analysis tools for this stage
sudo apt install -y \
    wireshark \          # GUI packet analyser — the primary tool
    tshark \             # Command-line Wireshark
    tcpdump \            # CLI packet capture — lighter than Wireshark
    nmap \               # Network mapper — port scanning, OS detection
    netcat \             # Network Swiss Army knife (nc)
    iperf3 \             # Bandwidth measurement
    mtr \                # Enhanced traceroute with statistics
    arp-scan \           # ARP-based host discovery
    netdiscover \        # Passive network discovery
    responder \          # LLMNR/NBT-NS poisoner (Kali includes this)
    wireshark-doc        # Wireshark documentation

# Python libraries for network work
pip3 install scapy       # Packet crafting and analysis — the key Python network library
pip3 install dpkt        # Fast packet parsing
```

### Online Resources

- **Wireshark sample captures** — wiki.wireshark.org/SampleCaptures — practice packet analysis with real-world captures of every protocol
- **PacketLife.net cheat sheets** — protocol header reference cards, excellent for quick lookup
- **IANA Protocol Registry** — iana.org — authoritative source for protocol numbers, port assignments
- **Shodan.io** — search engine for internet-connected devices — gives you a real sense of what is exposed on the internet
- **BGP Hurricane Electric** — bgp.he.net — visualise BGP routing, autonomous system information
- **The Cloudflare Blog** — blog.cloudflare.com — high-quality technical articles on network attacks, DDoS, BGP, DNS

### Practice Platforms

- **TryHackMe — "Pre-Security" path** — covers networking fundamentals interactively
- **Wireshark Challenges** — on CyberDefenders.org and other blue team platforms
- **PacketCafe** — cloud-based packet analysis practice
- **CTFtime.org — "network" category** — real CTF challenges involving packet analysis

---

## Module Summary

| Concept | Security Application |
|---------|---------------------|
| **Network fundamentals** | Why networks are the attack surface and the evidence trail |
| **PAN (Bluetooth/NFC/Zigbee)** | BlueBorne, NFC relay, Zigbee key capture — proximity attacks |
| **LAN** | Primary attack environment — ARP poisoning, MITM, lateral movement, AD attacks |
| **MAN** | City-scale infrastructure attacks, utility network targeting |
| **WAN/Internet** | BGP hijacking, routing attacks, internet-scale DDoS |
| **Bandwidth** | DDoS characterisation, exfiltration detection, C2 traffic analysis |
| **Latency** | Timing attacks, network topology mapping, C2 detection via timing |
| **Jitter** | OT attack impact, network forensics anomaly detection, DoS characterisation |
| **Frames** | ARP poisoning (Layer 2), MAC spoofing, fragmentation attacks, GOOSE injection |
| **Packets** | IP spoofing, TTL fingerprinting, fragmentation evasion |
| **Broadcast** | LLMNR/NBT-NS poisoning (Responder), Smurf attack, ARP spoofing |
| **Multicast** | mDNS/SSDP enumeration, IEC 61850 GOOSE injection, UPnP attacks |
| **Unicast** | Promiscuous mode sniffing, switched network eavesdropping |
| **Topology** | Attack path analysis, blast radius assessment, segmentation design |

---

> **Next Module:** [Stage 1.2 — OSI Model](./stage-1.2-osi-model.md)  
> **Previous Stage:** [Stage 00 — Foundations](../STAGE-00_Foundations/README.md)  
> **Series Index:** [Full Roadmap](../../README.md)

---

*This document is part of the Cybersecurity × OT/ICS Security Full Roadmap series. All techniques are presented for educational purposes, authorised security research, and defensive security practice. Always obtain proper authorisation before testing any system.*