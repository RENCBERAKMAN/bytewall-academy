# Stage 1.2 — The OSI Model
### From Zero to Cybersecurity Professional | Complete Roadmap Series

> **Series:** Cybersecurity × OT/ICS Security — Full Roadmap  
> **Stage:** 1 — Network Fundamentals  
> **Module:** 1.2 — The OSI Model  
> **Level:** Beginner → Advanced  
> **Prerequisites:** Stage 1.1 — Network Concepts  
> **Next Module:** 1.3 — TCP/IP Model

---

## Table of Contents

1. [Why the OSI Model Is the Security Professional's Mental Framework](#1-why-the-osi-model-is-the-security-professionals-mental-framework)
2. [OSI Model Overview — The Seven Layers](#2-osi-model-overview--the-seven-layers)
3. [Layer 1 — Physical](#3-layer-1--physical)
4. [Layer 2 — Data Link](#4-layer-2--data-link)
5. [Layer 3 — Network](#5-layer-3--network)
6. [Layer 4 — Transport](#6-layer-4--transport)
7. [Layer 5 — Session](#7-layer-5--session)
8. [Layer 6 — Presentation](#8-layer-6--presentation)
9. [Layer 7 — Application](#9-layer-7--application)
10. [Encapsulation and Decapsulation — The Full Picture](#10-encapsulation-and-decapsulation--the-full-picture)
11. [OSI vs TCP/IP — Where Theory Meets Reality](#11-osi-vs-tcpip--where-theory-meets-reality)
12. [Attacking Across the Stack — Layer-by-Layer Threat Map](#12-attacking-across-the-stack--layer-by-layer-threat-map)
13. [OSI in OT/ICS Environments](#13-osi-in-oticsscada-environments)
14. [Hands-On Exercises](#14-hands-on-exercises)
15. [Module Summary](#15-module-summary)

---

## 1. Why the OSI Model Is the Security Professional's Mental Framework

Every security tool you will ever use operates at one or more specific layers of the OSI model. Every attack targets one or more specific layers. Every defence protects one or more specific layers. The moment you internalise OSI, you gain the ability to think about any network interaction — attack, defence, or forensics — with structural precision.

Without OSI, security concepts become a disconnected list of techniques to memorise. With OSI, every technique has a logical home. You stop memorising and start reasoning.

**Concrete examples of why this matters in practice:**

When an alert fires in your SIEM saying "suspicious DNS traffic," you immediately know: DNS is Application Layer (L7). The alert is about behaviour at L7. The traffic still had to cross L1-L6 to get there. You know to check: is this DNS tunnelling (L7 data being abused to exfiltrate data)? Is the DNS server reachable only because a firewall rule was misconfigured at L3? Did an ARP poisoning attack at L2 redirect the DNS query to a rogue resolver?

When a penetration tester reports "VLAN hopping vulnerability," you immediately know: VLANs are L2. The attack abuses how switches handle 802.1Q tagging at L2 to reach network segments that should be logically separated.

When a blue teamer says "we need to implement TLS inspection," you immediately know: TLS is L6 (Presentation). Inspection requires terminating the TLS session at the inspection appliance (L6 operation) and re-encrypting to the destination. This has specific forensic and privacy implications.

**For OT/ICS environments:** Industrial protocols map to the OSI model just like IT protocols, but the mapping is often unusual and the security controls present at each layer are drastically fewer. A Modbus TCP transaction starts at L7 (the Modbus application protocol) but has no authentication at any layer. Understanding exactly which OSI layer provides (or fails to provide) security in an industrial network is the foundation of OT security assessment.

The OSI model was published by ISO in 1984. It was designed as a theoretical framework for interoperability — not specifically for security. But its structure accidentally created the perfect mental model for security analysis, because it separates concerns with exactly the granularity that security work requires.

---

## 2. OSI Model Overview — The Seven Layers

### 2.1 The Stack

```
┌──────────────────────────────────────────────────────────────┐
│  Layer 7 — Application    │ HTTP, HTTPS, DNS, SMTP, FTP,    │
│                           │ SMB, Modbus, DNP3, IEC 61850    │
├──────────────────────────────────────────────────────────────┤
│  Layer 6 — Presentation   │ TLS/SSL, JPEG, MPEG, ASCII,     │
│                           │ Base64, Encryption/Compression   │
├──────────────────────────────────────────────────────────────┤
│  Layer 5 — Session        │ NetBIOS, RPC, SQL sessions,     │
│                           │ TLS handshake (session setup)    │
├──────────────────────────────────────────────────────────────┤
│  Layer 4 — Transport      │ TCP, UDP, SCTP, QUIC            │
├──────────────────────────────────────────────────────────────┤
│  Layer 3 — Network        │ IPv4, IPv6, ICMP, IPSec,        │
│                           │ OSPF, BGP, ARP*                  │
├──────────────────────────────────────────────────────────────┤
│  Layer 2 — Data Link      │ Ethernet, Wi-Fi (802.11),       │
│                           │ ARP, VLAN (802.1Q), STP         │
├──────────────────────────────────────────────────────────────┤
│  Layer 1 — Physical       │ Copper, Fibre, Radio waves,     │
│                           │ Electrical signals, RS-485       │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 The Memory Device

Two mnemonics used by every network professional. Learn both — they appear in different directions depending on context:

**Top to Bottom (L7 → L1): "All People Seem To Need Data Processing"**
- **A**ll → Application (7)
- **P**eople → Presentation (6)
- **S**eem → Session (5)
- **T**o → Transport (4)
- **N**eed → Network (3)
- **D**ata → Data Link (2)
- **P**rocessing → Physical (1)

**Bottom to Top (L1 → L7): "Please Do Not Throw Sausage Pizza Away"**
- **P**lease → Physical (1)
- **D**o → Data Link (2)
- **N**ot → Network (3)
- **T**hrow → Transport (4)
- **S**ausage → Session (5)
- **P**izza → Presentation (6)
- **A**way → Application (7)

### 2.3 The Core Principle — Layer Independence

Each layer:
- Provides services to the layer above it
- Uses services from the layer below it
- Communicates logically with the same layer on the remote device
- Does not care about the implementation details of other layers

This independence is both the power of the model and its security weakness. A layer cannot inherently verify that the layer below it is functioning correctly or hasn't been compromised. L7 application code assumes L4 is delivering data reliably. It does not verify that L2 hasn't been poisoned. This trust between layers is exploited constantly.

### 2.4 PDU — Protocol Data Unit

Each layer has a name for its unit of data:

| Layer | PDU Name | Contains |
|-------|----------|---------|
| 7 — Application | Data / Message | Application payload |
| 6 — Presentation | Data | Formatted/encrypted data |
| 5 — Session | Data | Session-managed data |
| 4 — Transport | Segment (TCP) / Datagram (UDP) | Port numbers + data |
| 3 — Network | Packet | IP addresses + segment |
| 2 — Data Link | Frame | MAC addresses + packet |
| 1 — Physical | Bits | Raw binary signal |

When you look at a Wireshark capture, every packet is one of these PDUs. Knowing the terminology eliminates confusion when reading security documentation, CVE descriptions, and tool outputs.

---

## 3. Layer 1 — Physical

### 3.1 What Layer 1 Does

Layer 1 is the medium. It defines how bits — ones and zeros — are physically transmitted between devices. It deals with:

- **Signalling:** How a bit 1 is distinguished from a bit 0 on the medium. In copper Ethernet, voltage levels. In fibre, light pulses. In Wi-Fi, radio wave modulation.
- **Bit rate:** How many bits per second the medium can carry
- **Physical connectors:** RJ-45 (Ethernet), LC/SC (fibre), SMA (coaxial/RF)
- **Cabling standards:** Cat5e, Cat6, Cat6a, single-mode fibre, multi-mode fibre
- **Signal encoding:** Manchester encoding, 4B/5B, PAM4 — how bits map to physical signals

Layer 1 has no concept of addressing, error correction, or protocol. It simply converts bits into physical signals and physical signals back into bits.

### 3.2 Layer 1 Technologies

**Copper Ethernet (IEEE 802.3):**
```
Cat5e:  1 Gbps  up to 100m
Cat6:   1 Gbps  up to 100m, 10 Gbps up to 55m
Cat6a:  10 Gbps up to 100m
Cat8:   40 Gbps up to 30m (data centre)

Connector: RJ-45 (8P8C)
Signalling: Differential voltage on twisted pairs
          1000BASE-T uses all 4 pairs simultaneously
```

**Fibre Optic:**
```
Multi-mode fibre (MMF):  
  OM3/OM4: 10 Gbps up to 300m (data centre, short runs)
  Orange/aqua jacket
  LED light source
  
Single-mode fibre (SMF):
  OS2: 10 Gbps up to 80km, 100 Gbps up to 40km
  Yellow jacket
  Laser light source
  Used for WAN, campus backbone, undersea cables
```

**Wireless (IEEE 802.11):**
```
2.4 GHz band: longer range, more interference, slower
5 GHz band:   shorter range, less interference, faster
6 GHz band:   Wi-Fi 6E only, very short range, very fast

802.11n (Wi-Fi 4):  600 Mbps theoretical
802.11ac (Wi-Fi 5): 3.5 Gbps theoretical
802.11ax (Wi-Fi 6): 9.6 Gbps theoretical
```

**Industrial Physical Layer (OT/ICS):**
```
RS-232:  Serial, point-to-point, ±12V signalling, up to 20 kbps
         Used for: legacy HMI/PLC connections, console ports on network devices

RS-485:  Serial, multi-drop bus, ±5V differential signalling, up to 10 Mbps
         Used for: Modbus RTU (the dominant industrial protocol)
         Up to 32 devices on one bus, up to 1200m
         
CAN bus: Controller Area Network, differential, up to 1 Mbps
         Used for: automotive, some industrial sensors
         
Profibus PA: 31.25 kbps, intrinsically safe for hazardous areas
             Used for: process automation field devices
             
4-20mA loop: Analogue, not digital — carries a current signal
             representing a physical measurement
             Still extremely common in field instrumentation
```

### 3.3 Layer 1 Security Threats

**Physical Wiretapping:**
Copper cables can be tapped by physically accessing the cable and connecting monitoring equipment. This does not require breaking the cable — a vampire tap or inductive coupler can intercept traffic without creating a visible break. Fibre is harder to tap without detection because bending fibre causes measurable light loss, but specialist equipment exists for covert fibre taps.

**Nation-state level physical tapping** is documented: the NSA's Room 641A at AT&T facilities, revealed in 2006, was a room that split fibre traffic for surveillance. The Snowden documents described submarine cable tap programmes.

**Signal Jamming:**
Radio-frequency jamming disrupts wireless communications by overwhelming the signal with noise. Relevant for:
- Wi-Fi networks (denial of service at Layer 1)
- Industrial wireless sensor networks (Zigbee, WirelessHART, ISA100.11a)
- GPS jamming affecting time synchronisation (critical for power grid protection systems that rely on GPS-derived timestamps for phasor measurement)

**Hardware Implants:**
Nation-state actors have demonstrated hardware implants inserted into network cables and equipment that passively capture traffic. The ANT catalogue (Snowden documents) described implants including COTTONMOUTH (implanted in USB cables) and HALLUXWATER (firmware backdoor in Huawei routers).

At an industrial level, the supply chain for PLC hardware, field instruments, and communication cards represents a physical layer attack surface that is rarely audited.

**Rogue Access Points:**
Plugging an unauthorised device into a physical network port is a Layer 1 attack — it requires physical access but bypasses all logical security controls. Once connected, the rogue device has Layer 1 access equivalent to any legitimate device.

**Power Analysis Side-Channel (covered in Stage 0.1):**
Physical measurement of power consumption during cryptographic operations. Relevant to smart meters, smart cards, HSMs, and industrial devices.

### 3.4 Layer 1 in Practice

```bash
# Check physical interface status on Linux
ip link show                        # All interfaces and their states
ip link show eth0                   # Specific interface
ethtool eth0                        # Physical layer details: speed, duplex, link status

# Example ethtool output:
# Speed: 1000Mb/s
# Duplex: Full
# Link detected: yes
# Port: Twisted Pair
# Auto-negotiation: on

# Check for physical errors (CRC errors, collisions indicate cabling issues)
ethtool -S eth0 | grep -E "error|drop|miss|crc"

# On Windows:
# Get-NetAdapter | Select-Object Name, Status, LinkSpeed, MediaType
# netsh interface show interface

# Wireless physical layer details
iwconfig wlan0                      # Legacy wireless info
iw dev wlan0 info                   # Modern wireless info
iw dev wlan0 link                   # Current link quality, signal strength, noise

# Signal strength is measured in dBm (decibel-milliwatts)
# -30 dBm: excellent
# -67 dBm: good (recommended minimum for voice/video)
# -80 dBm: poor
# -90 dBm: unusable
```

> **Key Insight:** Physical security IS Layer 1 security. All logical security controls can be bypassed by an attacker with sufficient physical access. The reason secure facilities have strict physical access controls, cable management policies, and hardware inventory audits is that once physical access is granted, every layer above it is potentially compromised. In OT environments where control system cabinets may be in unmanned remote locations, this is existential.

---

## 4. Layer 2 — Data Link

### 4.1 What Layer 2 Does

Layer 2 is responsible for reliable transmission of data between two **directly connected** devices. It does two things that Layer 1 cannot:

1. **Framing:** Packages raw bits into structured frames with a beginning, end, source, and destination
2. **Error detection:** Detects (but usually not corrects) transmission errors using checksums

Layer 2 introduces the concept of **hardware addressing** — MAC addresses — which identify devices on the same network segment. Every NIC has a MAC address burned in at manufacturing time (though it can be overridden in software).

Layer 2 is bounded by network devices that operate at L2: **switches** and **bridges**. A packet crossing a switch stays within the same Layer 2 domain. A packet crossing a router leaves one Layer 2 domain and enters another.

### 4.2 Ethernet Frame Deep Dive

```
Ethernet II Frame:
 ┌──────────┬──────────┬───────────┬──────────────────────┬──────────┐
 │ Dst MAC  │ Src MAC  │ EtherType │       Payload        │   FCS    │
 │ 6 bytes  │ 6 bytes  │  2 bytes  │   46 - 1500 bytes    │ 4 bytes  │
 └──────────┴──────────┴───────────┴──────────────────────┴──────────┘

EtherType values (critical for security — identifies L3 protocol):
  0x0800 → IPv4
  0x0806 → ARP
  0x86DD → IPv6
  0x8100 → 802.1Q VLAN tagged frame
  0x8847 → MPLS
  0x88CC → LLDP (Link Layer Discovery Protocol)
  0x88E1 → HomePlug AV (powerline networking)
  0x88F7 → PTP (Precision Time Protocol — used in OT time synchronisation)
  0x88BA → IEC 61850 GOOSE
  0x88CD → IEC 61850 SAMPLED VALUES

FCS: Frame Check Sequence
  CRC-32 checksum over the entire frame
  Calculated by sender, verified by receiver
  A frame with a bad FCS is discarded silently
  High FCS error rates indicate physical layer problems (bad cable, interference)
```

**802.1Q VLAN Tagging:**
```
Standard Ethernet II:
 [Dst MAC][Src MAC][EtherType][Payload][FCS]

802.1Q Tagged Frame:
 [Dst MAC][Src MAC][0x8100][TCI][EtherType][Payload][FCS]
                    ──────  ───
                    Tag     Tag Control Information
                    Protocol  ├── PCP: Priority Code Point (QoS, 3 bits)
                    Identifier├── DEI: Drop Eligible Indicator (1 bit)
                              └── VID: VLAN ID (12 bits, 0-4095)

VLAN 0:    Reserved
VLAN 1:    Default VLAN (most switches, traffic not explicitly tagged)
VLAN 4094: Often used for management
VLAN 4095: Reserved
```

### 4.3 Switches — The Core L2 Device

A switch builds and maintains a **MAC address table** (also called CAM table — Content Addressable Memory). When a frame arrives:

1. Switch reads source MAC → adds to MAC table with the incoming port
2. Switch reads destination MAC → looks up in MAC table
3. If found → forward frame only to that port (unicast)
4. If not found → flood frame to all ports except source port (unknown unicast)
5. If destination is broadcast (FF:FF:FF:FF:FF:FF) → flood to all ports

```bash
# View switch MAC address table (Cisco IOS)
show mac address-table
show mac address-table dynamic         # Only learned entries
show mac address-table address <MAC>   # Find which port a MAC is on

# On Linux acting as a bridge
bridge fdb show                        # Show forwarding database
```

### 4.4 ARP — Address Resolution Protocol

ARP resolves IPv4 addresses to MAC addresses. When a device wants to send an IP packet to another device on the same subnet, it needs the MAC address to construct the Ethernet frame.

```
ARP Request (broadcast):
  Who has 192.168.1.1? Tell 192.168.1.5

  [Src MAC: AA:BB:CC:DD:EE:FF]
  [Dst MAC: FF:FF:FF:FF:FF:FF]  ← Broadcast
  [EtherType: 0x0806]
  [Operation: Request (1)]
  [Sender MAC: AA:BB:CC:DD:EE:FF]
  [Sender IP:  192.168.1.5]
  [Target MAC: 00:00:00:00:00:00]  ← Unknown
  [Target IP:  192.168.1.1]

ARP Reply (unicast):
  192.168.1.1 is at 11:22:33:44:55:66

  [Src MAC: 11:22:33:44:55:66]
  [Dst MAC: AA:BB:CC:DD:EE:FF]  ← Direct to requester
  [EtherType: 0x0806]
  [Operation: Reply (2)]
  [Sender MAC: 11:22:33:44:55:66]
  [Sender IP:  192.168.1.1]
  [Target MAC: AA:BB:CC:DD:EE:FF]
  [Target IP:  192.168.1.5]
```

**The critical security flaw in ARP:**
ARP has **no authentication**. Any device can send an ARP reply claiming any IP-to-MAC mapping. Devices accept and cache unsolicited ARP replies without verification. This is the foundation of ARP spoofing.

```bash
# View ARP cache
arp -a                              # Linux/Windows
ip neigh show                       # Linux (modern)

# ARP spoofing with arpspoof (dsniff package)
# This tells all hosts on the network that 192.168.1.1 (gateway)
# is at the attacker's MAC address:
sudo arpspoof -i eth0 -t 192.168.1.0/24 192.168.1.1
# AND tell the gateway that all hosts are at attacker's MAC:
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.0/24

# Enable IP forwarding so the attacker machine actually forwards the traffic:
echo 1 > /proc/sys/net/ipv4/ip_forward

# Now all traffic between hosts and gateway passes through attacker → MITM

# More modern tool: Bettercap
sudo bettercap -iface eth0
# bettercap> net.probe on
# bettercap> arp.spoof.targets 192.168.1.0/24
# bettercap> arp.spoof on
# bettercap> net.sniff on

# Detection: monitor ARP traffic for duplicate IP-to-MAC mappings
sudo arpwatch -i eth0               # Alerts on ARP anomalies
# Or in Wireshark: filter "arp" and look for:
# - Same IP claimed by two different MACs
# - High frequency of gratuitous ARP replies
```

### 4.5 Layer 2 Attack Surface

**MAC Flooding (CAM Table Overflow):**
A switch's MAC table has finite capacity (typically 8,000-128,000 entries). If an attacker floods the switch with frames containing random source MAC addresses, the table fills up. When the table is full, the switch cannot learn new MAC addresses and falls back to flooding ALL frames to ALL ports — behaving like a hub.

Result: The attacker's NIC in promiscuous mode receives all traffic on the switch, including traffic between other devices.

```bash
# MAC flooding with macof (dsniff)
sudo macof -i eth0                  # Floods with random MAC frames
# Generates ~155,000 packets/second
# Most modern switches have MAC flooding protection (port security)
# but legacy switches and some industrial switches do not
```

**VLAN Hopping:**
Two methods to reach VLANs an attacker should not have access to:

**Method 1: Switch Spoofing**
If a switch port is configured as "dynamic" (DTP — Dynamic Trunking Protocol enabled), an attacker can negotiate a trunk link with the switch, receiving traffic from ALL VLANs.

```
Normal access port: carries traffic for one VLAN only
Trunk port: carries traffic for multiple VLANs (tagged with 802.1Q)

Attack: Send DTP packets to negotiate trunk mode on an access port
Result: Attacker receives all VLANs

Prevention: Explicitly disable DTP — configure ports as access or trunk, never dynamic
Cisco: switchport nonegotiate
      switchport mode access  (for access ports)
```

**Method 2: Double Tagging**
Works only if the attacker is on the native VLAN of a trunk port. The attacker sends a frame with TWO 802.1Q tags:
- Outer tag: native VLAN (removed by first switch)
- Inner tag: target VLAN (forwarded by second switch)

```
Attacker frame: [Outer Tag: VLAN 1][Inner Tag: VLAN 100][Payload]

Switch 1: Removes outer tag (VLAN 1 is native, strip tag), forwards
Switch 2: Sees inner tag VLAN 100, forwards to VLAN 100

The reply cannot return via this method (unidirectional)
But for sending traffic (injecting attacks, DoS), this works

Prevention: Never use VLAN 1 as native VLAN
            Change native VLAN to an unused VLAN (e.g., VLAN 999)
```

**STP Attacks — Spanning Tree Protocol:**
STP (IEEE 802.1D) prevents Layer 2 loops in networks with redundant paths. It elects a **root bridge** and blocks redundant links. If the root bridge changes, STP reconverges — temporarily disrupting the network.

```
STP attack: Send BPDUs (Bridge Protocol Data Units) with a lower
            bridge priority than the current root bridge
Result:     Attacker's machine becomes the root bridge
            Traffic reroutes through attacker's machine → MITM
            STP reconvergence causes network disruption (seconds to minutes)

Tools: Yersinia (Layer 2 attack tool — STP, CDP, VTP, DTP attacks)
sudo yersinia -G                    # GUI mode
sudo yersinia stp -attack 0        # Send superior BPDUs to become root bridge

Prevention:
  BPDU Guard: Disable port if BPDU received on access port (PortFast ports)
  Root Guard: Prevent specific ports from becoming root bridge ports
  BPDU Filter: Don't send/receive BPDUs on specific ports
```

**LLDP/CDP Information Disclosure:**
LLDP (Link Layer Discovery Protocol, IEEE 802.1AB) and CDP (Cisco Discovery Protocol) are L2 protocols that advertise device information to neighbours.

```bash
# Capture LLDP packets to enumerate network devices
sudo tcpdump -i eth0 ether proto 0x88cc -v    # LLDP EtherType
# Reveals: device name, port description, VLAN info, IP address, hardware model

# Wireshark filter: lldp or cdp
# In a corporate network, CDP/LLDP can reveal the entire network topology

# Prevention: Disable CDP/LLDP on untrusted ports (user-facing ports)
# Cisco: no cdp enable  (per interface)
# Linux: sudo lldpad -d; lldptool -L -i eth0 adminStatus=disabled
```

### 4.6 Layer 2 in OT/ICS

Industrial Ethernet increasingly uses standard Layer 2 (Ethernet II with 802.1Q). However:

**GOOSE and Sampled Values (IEC 61850):**
These are Layer 2 protocols — they do NOT use IP. They are sent directly as Ethernet frames with EtherType 0x88BA (GOOSE) and 0x88CD (Sampled Values). This means:
- They cannot be filtered by IP firewalls
- They cannot be encrypted with TLS (which requires IP)
- They traverse the Layer 2 domain freely
- An attacker with Layer 2 access can inject, replay, or suppress GOOSE messages

GOOSE messages carry protection relay status. A relay detecting a fault sends a GOOSE message instructing other relays and breakers to trip. Injecting a false GOOSE message can cause protective relays to trip unnecessarily — causing outages. Suppressing GOOSE messages prevents relays from tripping during an actual fault — causing equipment damage.

**This is why IEC 62351 exists** — it defines security for IEC 61850, including GOOSE message authentication using HMAC-SHA256. Adoption is growing but far from universal.

```
IEC 62351-6 GOOSE Security:
  - Authentication tag appended to GOOSE message
  - HMAC-SHA256 using pre-shared key or certificate-based key
  - Prevents injection and modification
  - Does NOT prevent replay (separate mechanism needed)
  - Performance impact: minimal on modern hardware, significant on legacy IEDs

Checking for GOOSE in a capture:
sudo tcpdump -i eth0 ether proto 0x88ba   # GOOSE frames
```

> **Key Insight:** Layer 2 is the most dangerous layer for lateral movement on a LAN. ARP has no authentication. STP has no authentication. VLANs can be hopped. MAC tables can be flooded. All of this happens before any IP firewall or IDS can see the traffic. In OT environments, IEC 61850 GOOSE running at Layer 2 with no authentication represents a direct path to physical consequence. Detecting Layer 2 attacks requires monitoring at Layer 2 — which most organisations fail to implement.

---

## 5. Layer 3 — Network

### 5.1 What Layer 3 Does

Layer 3 enables communication between devices on **different** networks. While Layer 2 handles same-segment communication, Layer 3 handles routing — forwarding packets across multiple networks to reach a destination anywhere in the world.

Layer 3 introduces **logical addressing** — IP addresses — which are independent of hardware and can be assigned, changed, and structured hierarchically. This hierarchy (networks, subnets) enables the internet's routing system to scale to billions of devices.

**Layer 3 devices:** Routers. A router has multiple Layer 3 interfaces, each on a different network. It examines the destination IP of every incoming packet and forwards it toward the destination based on its routing table.

### 5.2 IP — Internet Protocol

IP is the fundamental Layer 3 protocol. It provides:
- **Addressing:** Source and destination IP addresses
- **Routing:** TTL, fragmentation, options for routing decisions
- **Connectionless delivery:** No guarantee of delivery, ordering, or error-free transmission (that is TCP's job at L4)

IPv4 header fields critical for security (full header covered in 1.1):

**TTL (Time to Live):**
Decremented by each router. Prevents infinite routing loops. OS fingerprinting uses initial TTL values (Linux=64, Windows=128, Cisco=255). When TTL reaches 0, router sends ICMP Time Exceeded and drops the packet.

```bash
# TTL manipulation in attacks:
# Tools like hping3 allow setting arbitrary TTL values
hping3 --ttl 1 target_ip            # Packet dies at first hop (ICMP Time Exceeded response reveals first router)
hping3 --ttl 255 target_ip          # Maximum TTL, reaches anywhere

# TTL-based evasion: some IDSs only inspect packets with TTL > threshold
# Sending packets with very low TTL that will die before reaching IDS but
# be processed by the target if the target is "behind" the IDS
# This is the basis of "TTL manipulation" IDS evasion
```

**Fragmentation:**
IP packets can be fragmented when they exceed the MTU of a link. The receiving end reassembles fragments.

```
Original packet: 4000 bytes (exceeds MTU 1500)

Fragment 1: [IP Header: offset=0, MF=1][1480 bytes of data]
Fragment 2: [IP Header: offset=185, MF=1][1480 bytes of data]
Fragment 3: [IP Header: offset=370, MF=0][1040 bytes of data]

MF = More Fragments flag
offset = where this fragment fits in the original packet (in 8-byte units)
```

**Fragmentation attacks:**
- **Teardrop (CVE-1999):** Overlapping fragment offsets cause kernel crash during reassembly. Patched in modern OSes but relevant for legacy embedded OT devices.
- **Fragmentation evasion:** Send a signature-triggering payload split across fragments. Some IDS systems don't reassemble fragments before signature matching.
- **Tiny fragment attack:** Force TCP header into second fragment. The first fragment is too small to contain enough of the TCP header for access control decisions.

### 5.3 ICMP — Internet Control Message Protocol

ICMP is the error-reporting and diagnostic protocol at Layer 3. It runs directly over IP (protocol number 1) and has no ports.

```
ICMP Types critical for security:
Type 0:  Echo Reply          ← Response to ping
Type 3:  Destination Unreachable
  Code 0: Net Unreachable    ← Routing problem
  Code 1: Host Unreachable   ← Host down or blocked
  Code 3: Port Unreachable   ← No service listening (UDP)
  Code 4: Fragmentation Needed ← MTU discovery
  Code 13: Communication Administratively Prohibited ← Firewall block
Type 5:  Redirect            ← Router telling host to use different route
Type 8:  Echo Request        ← Ping
Type 11: Time Exceeded       ← TTL expired (traceroute mechanism)
Type 13: Timestamp Request
Type 17: Address Mask Request
```

**ICMP Redirect Attack:**
ICMP Type 5 allows a router to tell a host "use a different gateway for this destination." An attacker can send spoofed ICMP Redirect messages to reroute traffic through the attacker's machine.

```bash
# Observe ICMP traffic
sudo tcpdump -i eth0 icmp -v

# Send ICMP ping with specific options
ping -c 4 192.168.1.1
hping3 -1 -c 4 192.168.1.1         # ICMP ping using hping3

# Test firewall ICMP filtering
ping -c 1 target                   # ICMP Echo → response tells if host is up
hping3 -S -p 80 target             # TCP SYN to port 80 → use when ICMP is blocked

# ICMP tunnel — exfiltrate data in ICMP payloads
# icmptunnel, ptunnel — tools that tunnel IP traffic inside ICMP
# Commonly used to bypass captive portals and restrictive firewalls
# Detection: ICMP packets with large or unusual payloads
# Normal ping payload: 32-64 bytes
# ICMP tunnel payload: up to 1400 bytes, consistent size, high frequency
```

### 5.4 Routing and Routing Protocols

**Static routing:** Administrator manually configures routes. Stable, predictable, but doesn't adapt to topology changes. Common in small networks and OT environments where predictability matters.

**Dynamic routing protocols:**

| Protocol | Layer | Type | Used In |
|----------|-------|------|---------|
| RIP v2 | L7 over UDP | Distance vector | Legacy, small networks |
| OSPF | L3 (IP proto 89) | Link state | Enterprise, campus |
| EIGRP | L3 (IP proto 88) | Hybrid | Cisco networks |
| BGP | L7 over TCP 179 | Path vector | Internet, ISPs |
| IS-IS | L2 (directly) | Link state | ISP backbone, large enterprise |

**Routing protocol attacks:**

**OSPF Route Injection:**
OSPF authenticates with MD5 or plain text passwords. In many deployments, authentication is disabled entirely. An attacker who can send OSPF packets (by being on the same L2 segment as a router, or by compromising a router) can inject false routes.

```
OSPF attack scenario:
1. Attacker joins OSPF domain (sends Hello packets with Area ID)
2. If authentication disabled or key known → attacker becomes OSPF neighbour
3. Attacker advertises route with low cost to a critical subnet
4. All routers update their routing tables to send traffic through attacker
5. MITM or traffic black-hole achieved at routing level

Tools: Scapy (craft OSPF packets), FRRouting (full routing suite)
Detection: Monitor for new OSPF neighbours, unexpected route changes
```

**BGP Hijacking (covered in 1.1):** Advertising false routes for IP ranges you don't own. RPKI (Resource Public Key Infrastructure) provides cryptographic route origin validation.

### 5.5 IPSec — Layer 3 Security

IPSec is the native security protocol for Layer 3. It provides:
- **Authentication Header (AH, protocol 51):** Integrity and authentication, no encryption
- **Encapsulating Security Payload (ESP, protocol 50):** Encryption + integrity + authentication
- **Internet Key Exchange (IKE, UDP 500):** Key negotiation protocol

**Two modes:**
- **Transport mode:** Encrypts only the payload, original IP header visible — used for end-to-end between hosts
- **Tunnel mode:** Encrypts entire IP packet, adds new IP header — used for VPN gateways

```bash
# Check IPSec SA (Security Association) status
sudo ip xfrm state list             # Linux (xfrm = transform framework)
sudo ip xfrm policy list            # IPSec policies

# Wireshark filters for IPSec:
# esp  → show ESP traffic (encrypted, but you can see headers)
# isakmp → show IKE key exchange
# If you have the keys, Wireshark can decrypt ESP traffic
```

> **Key Insight:** Layer 3 is where routing decisions happen, and routing decisions control which paths traffic takes. Controlling routing at L3 gives an attacker traffic interception capabilities at internet scale (BGP hijacking) or network scale (OSPF injection). Most networks deploy strong perimeter security at L3 (firewalls, ACLs) but have minimal protection for the routing protocols themselves. In OT networks, routers between zones should use authenticated routing protocols — but rarely do.

---

## 6. Layer 4 — Transport

### 6.1 What Layer 4 Does

Layer 4 is where application-to-application communication is implemented. While Layer 3 gets a packet between two machines, Layer 4 gets data between two specific **processes** running on those machines. It introduces:

- **Port numbers:** Identify which application (process) should receive the data
- **Multiplexing:** Multiple applications can use the network simultaneously on the same machine
- **Connection management (TCP):** Establishing, maintaining, and terminating connections
- **Reliability (TCP):** Acknowledgements, retransmission, flow control, congestion control
- **Connectionless delivery (UDP):** Minimal overhead, no guarantees

### 6.2 Port Numbers

Ports are 16-bit numbers (0-65535) that identify specific applications or services.

```
Port ranges:
  0-1023:     Well-Known Ports (require root/admin to bind)
  1024-49151: Registered Ports (IANA registered applications)
  49152-65535: Dynamic/Ephemeral Ports (used by clients for outgoing connections)

Critical well-known ports — know these cold:
  20/TCP  → FTP Data
  21/TCP  → FTP Control
  22/TCP  → SSH
  23/TCP  → Telnet (INSECURE)
  25/TCP  → SMTP (mail sending)
  53/TCP+UDP → DNS
  67/UDP  → DHCP Server
  68/UDP  → DHCP Client
  69/UDP  → TFTP (trivial FTP — no auth, often misconfigured)
  80/TCP  → HTTP
  88/TCP  → Kerberos
  110/TCP → POP3 (email retrieval)
  111/TCP+UDP → RPC (Remote Procedure Call)
  119/TCP → NNTP (Usenet)
  123/UDP → NTP (time synchronisation)
  135/TCP → Microsoft RPC/DCOM
  137/UDP → NetBIOS Name Service
  138/UDP → NetBIOS Datagram Service
  139/TCP → NetBIOS Session Service
  143/TCP → IMAP (email retrieval)
  161/UDP → SNMP (network management)
  162/UDP → SNMP Trap
  389/TCP+UDP → LDAP
  443/TCP → HTTPS
  445/TCP → SMB (Windows file sharing, direct over TCP)
  465/TCP → SMTPS (SMTP over TLS)
  500/UDP → IKE (IPSec key exchange)
  502/TCP → Modbus TCP (industrial — no auth!)
  514/UDP → Syslog
  587/TCP → SMTP Submission
  593/TCP → RPC over HTTP
  636/TCP → LDAPS (LDAP over TLS)
  873/TCP → rsync
  993/TCP → IMAPS
  995/TCP → POP3S
  1080/TCP → SOCKS proxy
  1194/UDP → OpenVPN
  1433/TCP → Microsoft SQL Server
  1521/TCP → Oracle Database
  1723/TCP → PPTP VPN
  2049/TCP+UDP → NFS
  2375/TCP → Docker daemon (INSECURE — no TLS)
  2376/TCP → Docker daemon (TLS)
  2483/TCP → Oracle DB with TLS
  3306/TCP → MySQL/MariaDB
  3389/TCP → RDP (Remote Desktop)
  3478/UDP → STUN (WebRTC)
  4444/TCP → Metasploit default listener
  4786/TCP → Cisco Smart Install (extremely dangerous, weaponised)
  5000/TCP → Docker Registry, Flask dev server
  5432/TCP → PostgreSQL
  5900/TCP → VNC
  5985/TCP → WinRM (HTTP)
  5986/TCP → WinRM (HTTPS)
  6379/TCP → Redis (often exposed with no auth!)
  6443/TCP → Kubernetes API server
  8080/TCP → HTTP alternate (common for web apps, Burp proxy default)
  8443/TCP → HTTPS alternate
  9200/TCP → Elasticsearch (often exposed with no auth!)
  27017/TCP → MongoDB (often exposed with no auth!)
  47808/UDP → BACnet (building automation — no auth)
  44818/TCP → EtherNet/IP (industrial — CIP protocol)
  102/TCP → S7comm (Siemens PLC — Stuxnet used this)
  20000/TCP → DNP3 over TCP (power grid SCADA)
```

### 6.3 TCP — Transmission Control Protocol

TCP provides a reliable, ordered, error-checked byte stream between two applications. It achieves this through:

**The Three-Way Handshake — Connection Establishment:**
```
Client                          Server
  │                               │
  │──── SYN (seq=x) ────────────→ │  Client initiates
  │                               │  Server: "I see your request"
  │ ←── SYN-ACK (seq=y, ack=x+1) │  Server acknowledges + sends own seq
  │                               │
  │──── ACK (ack=y+1) ──────────→ │  Client acknowledges server's seq
  │                               │
  │         [Connected]           │
  │                               │
  │──── DATA ───────────────────→ │
  │ ←── ACK ──────────────────── │

SYN: Synchronise — "I want to establish a connection, my starting sequence number is x"
ACK: Acknowledge — "I received your data up to sequence number n"
seq: Sequence number — tracks position of data in the byte stream
ack: Acknowledgement number — "I've received everything up to here, send me this next"
```

**Why sequence numbers matter for security:**
Early TCP implementations used predictable sequence numbers. An attacker could predict the server's sequence number, forge a TCP ACK, and inject data into a connection without completing the handshake — TCP session hijacking. Modern OSes use cryptographically random ISNs (Initial Sequence Numbers) per RFC 6528.

**TCP Flags — the complete set:**

| Flag | Hex | Meaning | Security Relevance |
|------|-----|---------|-------------------|
| SYN | 0x02 | Synchronise — initiate connection | SYN flood, port scanning |
| ACK | 0x10 | Acknowledge received data | ACK scan bypasses stateless firewalls |
| FIN | 0x01 | Finish — graceful close | FIN scan |
| RST | 0x04 | Reset — immediate close | RST injection to terminate connections |
| PSH | 0x08 | Push — deliver immediately | Not security-relevant |
| URG | 0x20 | Urgent — urgent pointer valid | Used in some evasion techniques |
| ECE | 0x40 | ECN-Echo — congestion signalling | Not typically security-relevant |
| CWR | 0x80 | Congestion Window Reduced | Not typically security-relevant |

**Four-Way Termination — Connection Teardown:**
```
Client                          Server
  │                               │
  │──── FIN (seq=x) ────────────→ │  Client done sending
  │ ←── ACK (ack=x+1) ─────────  │  Server acknowledges
  │                               │  [Server may still send data]
  │ ←── FIN (seq=y) ───────────── │  Server done sending
  │──── ACK (ack=y+1) ──────────→ │  Client acknowledges
  │                               │
  │         [Closed]              │
```

The TIME_WAIT state: After sending the final ACK, the client waits 2×MSL (Maximum Segment Lifetime, typically 60-240 seconds) before fully closing. This ensures the final ACK was received. TIME_WAIT exhaustion is a DoS vector — flood connections to force TIME_WAIT states until the system runs out of ephemeral ports.

**TCP SYN Flood:**
```
SYN flood attack:
1. Attacker sends large volume of SYN packets (often with spoofed source IPs)
2. Server allocates resources for each half-open connection (SYN_RECEIVED state)
3. Server sends SYN-ACK to spoofed addresses (no response comes back)
4. Server's connection table fills up
5. Legitimate connection requests are rejected — DoS

Mitigation: SYN cookies
  Instead of allocating state on SYN, server encodes connection parameters
  into the SYN-ACK sequence number cryptographically
  State is only allocated when valid ACK comes back
  No state for half-open connections → SYN flood ineffective

Check SYN cookie status on Linux:
cat /proc/sys/net/ipv4/tcp_syncookies
# 1 = enabled (default on modern kernels when under attack)
# 0 = disabled
```

### 6.4 UDP — User Datagram Protocol

UDP provides a minimal transport with no connection establishment, no acknowledgements, no flow control, and no ordering guarantees.

```
UDP Header (8 bytes — much simpler than TCP's 20 bytes):
┌─────────────────┬─────────────────┐
│  Source Port    │  Dest Port      │  2 + 2 = 4 bytes
├─────────────────┼─────────────────┤
│    Length       │    Checksum     │  2 + 2 = 4 bytes
└─────────────────┴─────────────────┘
│         Data                      │
└───────────────────────────────────┘
```

UDP is used when:
- **Speed matters more than reliability:** DNS (retry is easy), VoIP, video streaming
- **Application-level reliability:** The application handles retransmission if needed
- **Broadcast/Multicast:** TCP cannot broadcast; UDP can
- **Simple request/response:** DHCP, DNS, SNMP — one packet out, one packet back

**UDP-based amplification DDoS:**
UDP's connectionless nature enables amplification attacks. The attacker sends a small UDP request with a spoofed source IP (victim's IP) to a server with a large response. The server sends a large response to the victim.

```
Amplification factors:
  DNS:     28-54x (small query, large response with DNSSEC)
  NTP:     556x (monlist command — CVE-2013-5211)
  SSDP:    30x
  Memcached: 51,000x (CVE-2018-1000115 — this was the 1.7 Tbps attack)
  CLDAP:   70x

Attack formula:
  1. Attacker sends 100 Mbps of spoofed UDP queries
  2. With 50x amplification → victim receives 5 Gbps
  3. With 1,000 reflectors → 5 Tbps saturates any link

Mitigation:
  BCP38: ISPs filter spoofed source IPs (prevents amplification source)
  Rate limiting: Limit DNS response rate per source IP
  Disable unused services: NTP monlist disabled by default since ntpd 4.2.7
```

**QUIC — The Modern Transport:**
QUIC (Quick UDP Internet Connections) is a L4 protocol built on UDP, developed by Google, standardised in RFC 9000 (2021). It powers HTTP/3.

```
QUIC advantages:
  - Zero RTT connection establishment (vs TCP's 1 RTT + TLS's 1-2 RTT)
  - Built-in encryption (TLS 1.3 integrated — not optional)
  - Independent streams (one stream's loss doesn't block others)
  - Connection migration (IP address can change without dropping connection)
  - Used by: Google services, Cloudflare, Meta, ~25% of internet traffic (2024)

Security implications:
  - QUIC traffic is UDP, which many firewalls/IDS process less thoroughly than TCP
  - Always encrypted → prevents inspection without interception
  - Connection migration → complicates network forensics (connection ID instead of 5-tuple)
  - Fallback to TCP+TLS if UDP blocked → attackers cannot force QUIC only
```

> **Key Insight:** The transport layer is where most network security controls operate — firewalls filter by port number, IDS/IPS inspect transport-layer behaviour, connection tracking is at Layer 4. Understanding TCP state (SYN, SYN-ACK, established, TIME_WAIT) and UDP's statelessness is essential for understanding how firewalls work, how to evade them, and how to build detection rules. Every port scanner, every firewall rule, every network IDS signature starts at Layer 4.

---

## 7. Layer 5 — Session

### 7.1 What Layer 5 Does

Layer 5 manages **sessions** — logical dialogues between applications. It provides:
- Session establishment, maintenance, and termination
- Session synchronisation (checkpoints for recovery)
- Session multiplexing (multiple sessions over one transport connection)

In practice, the Session layer is the most abstract and least distinctly implemented of the seven layers. In the TCP/IP world, its functions are largely absorbed by the Application layer and the Transport layer. But conceptually it remains important, and several protocols and mechanisms specifically implement Session layer functionality.

### 7.2 Session Layer Protocols

**NetBIOS (Network Basic Input/Output System):**
NetBIOS provides session services for Windows networking — name registration, name resolution, and session establishment. Runs over UDP 137-138 (NetBIOS Name Service and Datagram Service) and TCP 139 (NetBIOS Session Service).

NetBIOS is legacy technology but remains pervasive in enterprise environments for backward compatibility. It is the basis of several critical attack techniques:

```bash
# NetBIOS name resolution (legacy Windows name resolution)
nmblookup -A 192.168.1.100          # NetBIOS names for IP address
nmblookup "WORKGROUP"               # Find all machines in workgroup

# NetBIOS scanning — enumerate Windows machines
nbtscan 192.168.1.0/24

# NetBIOS names have specific suffixes indicating service:
# <00> = Workstation service
# <20> = File Server service
# <1D> = Master Browser
# <1B> = Domain Master Browser
```

**RPC — Remote Procedure Call:**
RPC allows a program to call functions on a remote system as if they were local. Microsoft's implementation (MSRPC) is the foundation of:
- Active Directory (Kerberos, LDAP, replication use RPC)
- Windows management (WMI)
- SMB
- DCOM

```
RPC uses a portmapper (TCP/UDP 111 on Unix, TCP 135 on Windows)
to tell clients which port a specific RPC service is listening on.
This is why Windows systems have many high ports open — RPC services
bind to random high ports and register with the portmapper.
```

**RPC attacks:**
- MS03-026 (2003): Buffer overflow in Windows RPC service — used by Blaster and Welchia worms to infect millions of machines
- MS17-010 (2017): EternalBlue — exploited SMBv1 over RPC, used by WannaCry and NotPetya
- CVE-2022-26809: Windows RPC RCE vulnerability, CVSS 9.8, required no authentication

### 7.3 TLS Handshake — Session Layer in Practice

TLS (Transport Layer Security) is commonly described as a Presentation layer protocol (for its encryption), but its handshake and session establishment functions are clearly Session layer. The TLS handshake establishes:
- Which cipher suite to use
- Server (and optionally client) authentication via certificates
- Session key derivation

```
TLS 1.3 Handshake (simplified):
Client                              Server
  │                                   │
  │── ClientHello ─────────────────→  │  Supported ciphers, TLS version, random
  │   + key_share (Diffie-Hellman)    │  Client's DH public key
  │                                   │
  │ ←─ ServerHello ─────────────────  │  Selected cipher, server's DH public key
  │ ←─ {Certificate} ───────────────  │  Server's certificate (encrypted in TLS 1.3)
  │ ←─ {CertificateVerify} ─────────  │  Proof server owns the private key
  │ ←─ {Finished} ──────────────────  │
  │                                   │
  │── {Finished} ───────────────────→ │
  │                                   │
  │═══════════[Encrypted Data]════════│

{} = already encrypted using derived session key
Key: Both sides compute identical session key from DH exchange
     (Perfect Forward Secrecy — key not derived from certificate private key)
```

**TLS attack surface:**
- **Downgrade attacks:** POODLE (CVE-2014-3566) forced SSLv3; DROWN (CVE-2016-0800) exploited SSLv2
- **BEAST (CVE-2011-3389):** Exploited CBC mode in TLS 1.0
- **Heartbleed (CVE-2014-0160):** OpenSSL heap buffer over-read in TLS heartbeat extension — leaked server memory including private keys, session tokens, passwords. One of the most impactful vulnerabilities ever discovered.
- **Certificate validation failures:** Many implementations historically failed to properly validate certificates (wrong hostname, expired, self-signed). HTTPS everywhere means certificate validation is now enforced in browsers.

```bash
# Check TLS configuration of a server
openssl s_client -connect target:443 -tls1_2    # Force TLS 1.2
openssl s_client -connect target:443            # Negotiate highest supported

# SSLScan — comprehensive TLS testing
sslscan target:443

# TestSSL.sh — detailed TLS security testing
testssl.sh target:443
# Shows: supported versions, cipher suites, vulnerabilities (BEAST, POODLE, etc.)

# Check certificate details
openssl s_client -connect target:443 </dev/null 2>/dev/null | \
    openssl x509 -noout -text | grep -E "Subject:|Issuer:|Not After"

# Enumerate TLS certificate information (useful for OSINT)
# Certificates reveal: organisation name, internal hostnames (SANs),
# email addresses, sometimes infrastructure details
```

> **Key Insight:** The Session layer is where authentication and encryption sessions are established. Attacking TLS (the most important session protocol in existence) is a rich field — every major TLS vulnerability has had massive real-world impact because TLS is on every HTTPS connection. Understanding how TLS establishes sessions is prerequisite to understanding SSL stripping, certificate pinning bypass, TLS interception proxies, and the entire HTTPS ecosystem.

---

## 8. Layer 6 — Presentation

### 8.1 What Layer 6 Does

Layer 6 is responsible for **data format translation**. It ensures that data from the application layer of one system can be read by the application layer of another system, regardless of internal representation differences. It handles:

- **Encoding/decoding:** Converting data to a transmittable format and back
- **Encryption/decryption:** Transforming data to protect confidentiality
- **Compression/decompression:** Reducing data size for transmission

Like Layer 5, Layer 6 is not implemented as a distinct layer in TCP/IP. Its functions are performed by specific protocols (TLS for encryption, HTTP Content-Encoding for compression) or by the application itself.

### 8.2 Data Encoding Formats

**ASCII and Unicode:**
Every text character transmitted on a network is encoded as a numeric value. ASCII (7-bit, 128 characters) is the historical standard. Unicode (UTF-8, UTF-16, UTF-32) extends this to cover all human writing systems.

**Security implication of encoding:**
Different systems interpret the same byte sequences differently based on encoding. This has been the source of many vulnerabilities:

```
UTF-8 multi-byte sequences and security:
  Normal: /etc/passwd  = 0x2F 0x65 0x74 0x63 ...
  Encoded: /%65%74%63/passwd  (URL encoding of 'e', 't', 'c')
           = /etc/passwd after decoding
           
  Some web application firewalls decode only once.
  Double encoding: %%36%35 → %65 → 'e' after two decode steps
  Some WAFs only decode once, missing the double-encoded attack
  
Unicode normalisation attacks:
  Some characters look visually identical but have different code points
  U+002F = "/" (normal slash)
  U+FF0F = "／" (fullwidth solidus) — visually identical
  A system that normalises before validation may accept ／etc/passwd
  and then access /etc/passwd after normalisation
```

**Base64:**
Base64 encodes binary data as printable ASCII characters. It is NOT encryption — it is encoding. Base64 is used to:
- Transmit binary data in text-based protocols (email attachments in MIME)
- Obfuscate (not secure) data from casual inspection
- Encode credentials in HTTP Basic Authentication
- Encode PowerShell commands to bypass simple keyword detection

```bash
# Encode
echo "admin:password" | base64      # YWRtaW46cGFzc3dvcmQ=

# Decode
echo "YWRtaW46cGFzc3dvcmQ=" | base64 -d   # admin:password

# HTTP Basic Auth header:
# Authorization: Basic YWRtaW46cGFzc3dvcmQ=
# This is NOT encrypted or secure — trivially decoded
# Only safe over HTTPS

# Detecting base64 in logs (common in PowerShell attacks)
grep -P '[A-Za-z0-9+/]{50,}={0,2}' /var/log/auth.log
# PowerShell -EncodedCommand is always base64
# Defenders must decode and inspect these
```

### 8.3 Compression and Security

**CRIME and BREACH — Compression Oracle Attacks:**
If data is compressed before being encrypted, and an attacker can inject data into the stream and observe the encrypted output length, they can infer information about the plaintext. Compression reduces repetition — if an attacker's injected string reduces the compressed size, it means the string appears in the plaintext.

- **CRIME (CVE-2012-4929):** Exploited TLS-level compression (DEFLATE) to recover HTTPS cookies. Fixed by disabling TLS-level compression.
- **BREACH (2013):** Exploited HTTP-level compression (gzip). Not a CVE but a design weakness. HTTPS body compression can leak secrets even when TLS is uncompromised.

```
BREACH attack in brief:
1. Attacker can make victim's browser send authenticated HTTP requests
   (through JavaScript injection on another page)
2. HTTP response is compressed+encrypted
3. Attacker injects guesses into the URL: ?csrf_guess=a, ?csrf_guess=b, etc.
4. Measures encrypted response length
5. When guess matches part of the real CSRF token, compression is more effective
   and encrypted response is shorter
6. Character by character, attacker recovers the full CSRF token

This works because gzip compresses repeated strings efficiently.
If the secret appears twice (real + attacker's guess), the compressed size drops.
```

### 8.4 Encryption at Layer 6

While IPSec operates at Layer 3, TLS at Layers 5-6, and application-level encryption at Layer 7, the Presentation layer is conceptually where encryption transforms plaintext to ciphertext and back.

For security professionals, the critical understanding is:

```
Encryption placement matters enormously:

End-to-end (application layer encryption, e.g., PGP email):
  [User A] → [encrypted] → [Server] → [encrypted] → [User B]
  Server sees: only encrypted data. Cannot read content.
  
TLS (transport/presentation encryption, e.g., HTTPS):
  [User A] → [encrypted] → [Server] → [plaintext] → [User B's server]
  The TLS-terminating server sees plaintext.
  CDN, load balancers, inspection proxies: all see plaintext
  
Network layer encryption (IPSec):
  [Host A] → [encrypted] → [VPN Gateway] → [plaintext] → [internal network]
  Everything beyond the VPN gateway is plaintext
  Lateral movement after VPN access is unencrypted unless additional layers exist
```

This hierarchy is why Zero Trust architectures use end-to-end or application-level encryption even inside the "trusted" network — because TLS termination points and VPN gateways represent points where traffic is cleartext.

> **Key Insight:** Layer 6 is where data format vulnerabilities live — encoding attacks, compression oracles, serialisation vulnerabilities. It is also where encryption is logically applied, and understanding which layer terminates encryption determines what any given system can inspect. A CDN that terminates TLS sees your plaintext. An IPSec VPN gateway sees plaintext past the gateway. This shapes both attack and defence architecture.

---

## 9. Layer 7 — Application

### 9.1 What Layer 7 Does

Layer 7 is the layer closest to the user. Application layer protocols define the rules for specific types of communication — how web browsers request pages, how email is delivered, how domain names are resolved, how files are transferred, and how industrial controllers receive commands.

Layer 7 is where the vast majority of security vulnerabilities exist. SQL injection, XSS, CSRF, command injection, authentication bypasses — these are all Layer 7 vulnerabilities. The application's logic, not the network infrastructure, is the attack surface.

### 9.2 Critical Application Layer Protocols

**HTTP/HTTPS:**
```
HTTP Request:
  GET /index.html HTTP/1.1          ← Method, URI, version
  Host: example.com                 ← Target host
  User-Agent: Mozilla/5.0...        ← Client identification
  Accept: text/html                 ← Content types accepted
  Cookie: session=abc123            ← Session token ← ATTACK TARGET
  Authorization: Bearer <JWT>       ← Auth token ← ATTACK TARGET
  Content-Length: 0
  [blank line]
  
HTTP Response:
  HTTP/1.1 200 OK
  Content-Type: text/html
  Set-Cookie: session=xyz789; HttpOnly; Secure; SameSite=Strict
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  Content-Security-Policy: default-src 'self'
  X-Frame-Options: DENY
  [blank line]
  [body]

Security headers in responses:
  HSTS: Forces HTTPS for specified duration
  CSP: Controls what resources can load (prevents XSS impact)
  X-Frame-Options: Prevents clickjacking
  X-Content-Type-Options: nosniff: prevents MIME sniffing
```

**DNS:**
```
DNS Transaction:
  Query:   A record for www.example.com?
  Response: www.example.com → 93.184.216.34

DNS record types and security:
  A:    IPv4 address mapping       ← Forward lookup
  AAAA: IPv6 address mapping
  CNAME: Alias to another name     ← Dangling CNAME = subdomain takeover vulnerability
  MX:   Mail server                ← Target for email spoofing if SPF/DKIM/DMARC missing
  TXT:  Arbitrary text             ← SPF, DKIM, DMARC verification records live here
  NS:   Authoritative nameservers  ← NS takeover = complete domain hijacking
  PTR:  Reverse lookup (IP → name)
  SOA:  Zone authority information
  SRV:  Service location           ← Used by Active Directory (Kerberos, LDAP SRV records)
  
SPF (Sender Policy Framework):
  TXT record listing which IPs may send email for a domain
  "v=spf1 ip4:203.0.113.0/24 include:sendgrid.net -all"
  Without SPF: anyone can send email claiming to be from your domain

DKIM (DomainKeys Identified Mail):
  Email digitally signed with private key
  Public key in DNS TXT record
  Without DKIM: email content can be forged/modified in transit
  
DMARC (Domain-based Message Authentication):
  Policy for handling emails that fail SPF/DKIM
  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
  p=reject: reject emails failing authentication
  Without DMARC with reject: phishing emails appear to come from your domain
```

**SMB — Server Message Block:**
SMB is the Windows file and printer sharing protocol. It runs on TCP 445 (direct) and TCP 139 (over NetBIOS). SMB is the most attacked protocol in enterprise environments.

```
SMB versions and security:
  SMBv1: No encryption, no integrity, multiple critical vulnerabilities
         EternalBlue (MS17-010) exploits SMBv1 — WannaCry, NotPetya
         Should be DISABLED everywhere. Microsoft disabled it by default in Windows 10/Server 2019
         
  SMBv2: Introduced in Vista/2008. Improved performance and security.
  SMBv3: Introduced in Windows 8/2012. Full encryption support.

SMB signing:
  Authentication and integrity protection for SMB sessions
  Prevents NTLM relay attacks (where captured NTLM authentication is relayed to another server)
  Required on domain controllers but NOT enforced client-side by default
  This is why NTLM relay attacks (Responder + ntlmrelayx) work so effectively

Check SMB signing:
nmap --script smb2-security-mode -p 445 target_ip
# "message signing enabled but not required" → vulnerable to relay attack
# "message signing enabled and required" → relay attack prevented
```

**SNMP — Simple Network Management Protocol:**
SNMP manages and monitors network devices. Runs on UDP 161 (queries) and UDP 162 (traps).

```
SNMP versions and security (critical for OT environments):
  SNMPv1: Community strings (plaintext passwords), no encryption
           Default communities: "public" (read), "private" (read/write)
           
  SNMPv2c: Minor improvements, still plaintext community strings
  
  SNMPv3: Authentication (MD5/SHA) + Encryption (DES/AES)
           Only secure version — should be the only one deployed
           
SNMP attack scenarios:
  Reconnaissance: Read MIB (Management Information Base) to get:
    - Device model, firmware version (for targeted exploitation)
    - Interface configurations, routing tables, ARP tables
    - System uptime, CPU/memory utilisation
    - Installed software list (Windows SNMP)
    
  Exploitation: Write access with default "private" community:
    - Change device configuration
    - Disable interfaces
    - Redirect routing
    - On managed switches: change VLAN assignments, disable ports

# SNMP enumeration
snmpwalk -v2c -c public 192.168.1.1                    # Walk entire MIB
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.1     # System info
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.4.20  # IP address table
snmp-check -c public -v 2c 192.168.1.1                 # Comprehensive enumeration

# SNMP brute force community string
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 192.168.1.1
```

**OT/ICS Application Layer Protocols:**

These deserve extended treatment because they are unique to industrial environments and have almost no security built in.

```
Modbus TCP (TCP 502):
  Designed in 1979 for RS-232 serial communication
  No authentication, no encryption, no authorisation
  Anyone on the network can:
    - Read any coil/register (FC01, FC02, FC03, FC04)
    - Write any coil/register (FC05, FC06, FC15, FC16)
    - Execute any function code
    - Cause denial of service by flooding
    
  Function Codes:
    0x01: Read Coil Status
    0x02: Read Input Status
    0x03: Read Holding Registers      ← Most common
    0x04: Read Input Registers
    0x05: Force Single Coil           ← Write output — direct physical control
    0x06: Preset Single Register
    0x0F: Force Multiple Coils
    0x10: Preset Multiple Registers   ← Set parameters — change setpoints
    0x11: Report Slave ID             ← Device fingerprinting
    0x17: Read/Write Multiple Registers
    
  Attack example — read all registers:
    import pymodbus.client as ModbusClient
    client = ModbusClient.ModbusTcpClient('192.168.1.100', port=502)
    client.connect()
    result = client.read_holding_registers(0, 100, slave=1)  # Read 100 registers
    print(result.registers)
    # No authentication required
    
DNP3 (TCP 20000, UDP 20000):
  Used in electric power, water, oil/gas SCADA
  Supports authentication (SA) in DNP3 Secure Authentication v5 (SAv5)
  but baseline DNP3 has no security
  
  Attack: spoofed DNP3 requests can control field devices
  Stuxnet used a variant of this concept
  
S7comm (TCP 102 — Siemens S7 PLCs):
  Siemens-proprietary PLC communication protocol
  Used by Stuxnet to communicate with Siemens S7-315 and S7-417 PLCs
  No authentication in original versions
  S7CommPlus (S7-1200/1500) has encryption but has been broken
  
  Tools: s7-200 (Python library), Snap7 library
  
EtherNet/IP / CIP (TCP 44818, UDP 2222):
  Used by Allen-Bradley/Rockwell Automation PLCs
  Common Industrial Protocol (CIP) over Ethernet
  No authentication by default
  
BACnet (UDP 47808):
  Building Automation and Control protocol
  Used for HVAC, lighting, access control in buildings
  No authentication in baseline protocol
  Many BACnet devices exposed on the internet via Shodan
```

> **Key Insight:** Layer 7 is simultaneously the most critical and most vulnerable layer. All user-visible functionality — and virtually all business logic — is implemented here. Application-layer attacks (SQLi, XSS, command injection) cause the most breaches. Industrial protocols at Layer 7 were designed for reliability in isolated networks, not for security in connected ones. The absence of authentication in Modbus, DNP3, and BACnet is not an oversight — it is a design decision from an era when network isolation was assumed. That assumption is now fatally broken.

---

## 10. Encapsulation and Decapsulation — The Full Picture

### 10.1 The Journey of a Packet

Understanding the complete journey of data from application to physical medium and back is essential for packet analysis, attack design, and forensics. Here is a complete example: your browser requesting http://192.168.1.100/.

```
APPLICATION (Layer 7):
  Browser constructs HTTP request:
  "GET / HTTP/1.1\r\nHost: 192.168.1.100\r\nUser-Agent: ...\r\n\r\n"

SESSION/PRESENTATION (Layers 5-6):
  If HTTPS: TLS encrypts the HTTP data (assume plain HTTP for this example)

TRANSPORT (Layer 4):
  TCP wraps HTTP data in a segment:
  [Src Port: 54321][Dst Port: 80][Seq: 1000][Ack: 0][Flags: ACK+PSH]
  [HTTP Data: "GET / HTTP/1.1..."]
  ↑ Note: Three-way handshake already completed before this data segment

NETWORK (Layer 3):
  IP wraps TCP segment in a packet:
  [Version: 4][TTL: 64][Protocol: 6 (TCP)]
  [Src IP: 192.168.1.5][Dst IP: 192.168.1.100]
  [TCP Segment]

DATA LINK (Layer 2):
  ARP resolves 192.168.1.100 to MAC 11:22:33:44:55:66 (already in cache)
  Ethernet wraps IP packet in a frame:
  [Dst MAC: 11:22:33:44:55:66][Src MAC: AA:BB:CC:DD:EE:FF]
  [EtherType: 0x0800 (IPv4)]
  [IP Packet]
  [FCS: CRC32]

PHYSICAL (Layer 1):
  Ethernet frame converted to electrical signals on the wire
  10101010... transmitted as voltage levels on Cat6 cable

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

At the RECEIVING END — Decapsulation (reverse order):

PHYSICAL (Layer 1):
  Electrical signals → bits → Ethernet frame

DATA LINK (Layer 2):
  Frame received: is Dst MAC mine? YES (or broadcast)
  FCS valid? YES → pass up
  Strip Ethernet header and trailer → expose IP packet

NETWORK (Layer 3):
  IP packet: is Dst IP mine? YES (192.168.1.100)
  TTL valid? YES → decrement (now 63)
  Protocol: 6 (TCP) → pass TCP segment up to TCP handler

TRANSPORT (Layer 4):
  TCP segment: Dst Port 80 → is there an application listening on port 80? YES
  Check sequence numbers, acknowledge
  Pass HTTP data to web server application

SESSION/PRESENTATION (Layers 5-6):
  Not applicable for plain HTTP

APPLICATION (Layer 7):
  Web server receives: "GET / HTTP/1.1\r\nHost: 192.168.1.100..."
  Process request, generate response
```

### 10.2 Where Security Tools Operate

```
Wireshark: Operates at ALL layers — can decode from L1 statistics up to L7 application data
           Use: Full packet analysis, protocol debugging, forensics

tcpdump: Primarily L2-L4 — captures frames/packets/segments with filters
         Use: Quick capture, scripting, production environments

Nmap: Primarily L3-L4 — sends crafted IP packets and TCP/UDP segments
      OS detection uses L3 (TTL, IP options) and L4 (TCP window size, options)
      Service detection uses L7 (banner grabbing, protocol responses)
      Use: Port scanning, service enumeration, OS fingerprinting

iptables/nftables: L3-L4 — filter based on IP addresses and port numbers
                   L7 extension: --match string for application data (limited)
                   Use: Host-based firewall

Snort/Suricata: All layers — L2 MAC rules through L7 application patterns
                Use: Intrusion detection/prevention

Burp Suite: L7 only — HTTP/HTTPS proxy
            Operates at application layer, doesn't handle TCP/IP directly
            Use: Web application testing

Metasploit: L4-L7 — exploits operate at transport/application level
            Network modules include L3 (ICMP) and L2 (ARP) capabilities
            Use: Exploitation framework

ARP tools (arpspoof, Bettercap): L2 — manipulate ARP at Layer 2
                                  Use: MITM setup
```

---

## 11. OSI vs TCP/IP — Where Theory Meets Reality

### 11.1 The TCP/IP Model

The TCP/IP model (DoD model) is the practical model that actually describes how the internet works. It has four layers:

```
OSI Model              TCP/IP Model
─────────────────      ───────────────────
7. Application    ─┐
6. Presentation   ─┼─→  Application
5. Session        ─┘
4. Transport       ──→  Transport
3. Network         ──→  Internet
2. Data Link      ─┐
1. Physical       ─┴─→  Network Access
```

The TCP/IP model collapses OSI's L5-L7 into Application and L1-L2 into Network Access. This reflects reality — TCP/IP protocols don't strictly observe the OSI layer boundaries.

### 11.2 Why Both Models Matter

Use OSI when:
- **Troubleshooting:** "Is this a Layer 1 problem (cable unplugged) or Layer 3 (routing)?"
- **Security analysis:** "This attack operates at Layer 2 — what Layer 2 controls exist?"
- **Describing attack techniques:** "This is a Layer 7 attack (HTTP) that uses a Layer 4 mechanism (TCP connection flooding)"
- **Vendor communication:** The OSI model is the universal reference — every security professional understands it

Use TCP/IP when:
- **Protocol specification reading:** RFCs describe TCP/IP protocols
- **Implementation details:** Understanding actual protocol behaviour
- **Network engineering:** How protocols actually interact

In practice: know OSI by name and layer number. Know TCP/IP for implementation details. Switch between them naturally depending on context. This is what professionals do.

---

## 12. Attacking Across the Stack — Layer-by-Layer Threat Map

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Layer │ Key Attacks                    │ Key Defences                    │
├───────┼────────────────────────────────┼─────────────────────────────────┤
│  L7   │ SQLi, XSS, CSRF, Command inj.  │ WAF, input validation, CSP      │
│  App  │ SSRF, XXE, IDOR, Deserialisat. │ Secure coding, DAST scanning    │
│       │ DNS cache poisoning, BGP hijack│ DNSSEC, RPKI, DMARC             │
│       │ Modbus/DNP3/SNMP exploitation  │ Protocol authentication (IEC 62351)│
├───────┼────────────────────────────────┼─────────────────────────────────┤
│  L6   │ Encoding attacks (UTF-8 abuse) │ Input normalisation, sanitisation│
│ Pres. │ CRIME/BREACH compression oracle│ Disable TLS compression         │
│       │ SSL/TLS downgrade attacks      │ TLS 1.2+ only, HSTS             │
│       │ Heartbleed (CVE-2014-0160)     │ Patch OpenSSL, cert rotation    │
├───────┼────────────────────────────────┼─────────────────────────────────┤
│  L5   │ Session hijacking              │ Secure session tokens, HTTPS    │
│ Sess. │ RPC exploitation (MS03-026)    │ Firewall port 135, patch        │
│       │ NetBIOS/LLMNR poisoning        │ Disable LLMNR/NBT-NS, DNSSEC   │
├───────┼────────────────────────────────┼─────────────────────────────────┤
│  L4   │ SYN flood                      │ SYN cookies, rate limiting      │
│ Trans.│ UDP amplification DDoS         │ BCP38, rate limiting services   │
│       │ TCP session hijacking          │ Randomised ISNs (modern OSes)   │
│       │ Port scanning                  │ Firewall, port knocking         │
│       │ TIME_WAIT exhaustion           │ Tune TCP stack parameters       │
├───────┼────────────────────────────────┼─────────────────────────────────┤
│  L3   │ IP spoofing                    │ BCP38 ingress filtering         │
│  Net  │ ICMP redirect                  │ Disable ICMP redirect accept    │
│       │ Fragmentation attacks          │ Fragment reassembly at firewall │
│       │ OSPF/BGP route injection       │ Routing protocol authentication │
│       │ TTL manipulation (IDS evasion) │ Normalise TTL in IDS            │
├───────┼────────────────────────────────┼─────────────────────────────────┤
│  L2   │ ARP spoofing/poisoning         │ Dynamic ARP Inspection (DAI)    │
│ Data  │ MAC flooding (CAM overflow)    │ Port security, MAC limiting     │
│ Link  │ VLAN hopping (DTP/double-tag)  │ Disable DTP, change native VLAN │
│       │ STP attacks (root bridge)      │ BPDU Guard, Root Guard          │
│       │ CDP/LLDP info disclosure       │ Disable on untrusted ports      │
│       │ GOOSE injection (IEC 61850)    │ IEC 62351-6 authentication      │
├───────┼────────────────────────────────┼─────────────────────────────────┤
│  L1   │ Physical wiretapping           │ Physical security, fibre+alarm  │
│ Phys. │ Signal jamming                 │ RF shielding, redundant paths   │
│       │ Rogue device insertion         │ 802.1X port authentication      │
│       │ Hardware implants              │ Supply chain verification, tamper│
│       │ Power analysis side-channel    │ Constant-time crypto, shielding │
└───────┴────────────────────────────────┴─────────────────────────────────┘
```

---

## 13. OSI in OT/ICS/SCADA Environments

### 13.1 How Industrial Protocols Map to OSI

The Purdue Model (covered in Stage 12) describes OT network architecture in functional zones. OSI describes communication within and between those zones. Together they form the complete framework for OT security analysis.

```
IEC 61850 Protocol Stack vs OSI:
┌─────────────┐     ┌──────────────────────────────────┐
│    OSI      │     │         IEC 61850 Stack           │
├─────────────┤     ├──────────────────────────────────┤
│ Application │←───→│ MMS (Manufacturing Message Spec.) │
│ Presentation│←───→│ ASN.1/BER encoding               │
│ Session     │←───→│ ISO Session Protocol              │
│ Transport   │←───→│ TCP (for MMS/ICCP)               │
│ Network     │←───→│ IP                               │
│ Data Link   │←───→│ Ethernet (GOOSE/SV directly here)│
│ Physical    │←───→│ Copper/Fibre Ethernet            │
└─────────────┘     └──────────────────────────────────┘

GOOSE and Sampled Values bypass L3-L7 entirely → directly over L2
This is why IP firewalls cannot filter GOOSE traffic
```

```
Modbus TCP vs OSI:
┌─────────────┐     ┌─────────────────┐
│    OSI      │     │   Modbus TCP    │
├─────────────┤     ├─────────────────┤
│ Application │←───→│ Modbus PDU      │ ← Function code, data
│ Pres./Sess. │     │ (not present)   │ ← No session management
│ Transport   │←───→│ TCP (port 502)  │
│ Network     │←───→│ IP              │
│ Data Link   │←───→│ Ethernet        │
│ Physical    │←───→│ Copper/Fibre    │
└─────────────┘     └─────────────────┘

Note: Modbus does not implement Presentation or Session layers.
Sessions are implicit — if the TCP connection is open, commands are executed.
Authentication: NONE at any layer.
```

### 13.2 OT Security Controls by Layer

```
Layer-by-layer OT security controls:

L1 — Physical:
  ✓ Physical access control to cabinets and field devices
  ✓ Cable labelling and documentation
  ✓ Tamper-evident seals on hardware
  ✓ Locked enclosures in remote locations
  ✗ Often: exposed USB ports, unguarded network jacks

L2 — Data Link:
  ✓ GOOSE authentication (IEC 62351-6) — rarely deployed
  ✓ Port security on managed switches
  ✗ Often: unmanaged switches (no port security possible)
  ✗ Often: flat L2 network (no VLAN separation)
  ✗ Often: GOOSE with no authentication

L3 — Network:
  ✓ Firewalls between IT and OT (DMZ)
  ✓ Whitelist-based ACLs (only known devices can communicate)
  ✗ Often: no inspection of Modbus/DNP3 payload
  ✗ Often: no logging of L3 traffic
  Note: Modbus TCP on port 502 can be filtered at L3, but payload not validated

L4 — Transport:
  ✓ Port filtering (block everything except known service ports)
  ✗ Often: wide-open port ranges for "legacy compatibility"

L7 — Application:
  ✓ Industrial protocol gateways with command inspection
  ✓ OPC UA with security mode (authentication + encryption)
  ✓ DNP3 Secure Authentication v5
  ✗ Often: Modbus with no authentication accepted by field devices
  ✗ Often: SNMP v1/v2c on network-connected devices
```

---

## 14. Hands-On Exercises

### Exercise 1: Layer-by-Layer Packet Dissection (1 hour)

```bash
# Capture a full HTTP connection and manually identify each OSI layer

# Start capture
sudo tcpdump -i eth0 -w /tmp/http_full.pcap 'host neverssl.com and tcp port 80' &

# Generate traffic
curl -v http://neverssl.com/

# Stop capture
kill %1

# Open in Wireshark: wireshark /tmp/http_full.pcap
# For each packet in the TCP handshake (SYN, SYN-ACK, ACK):
# 1. Expand "Ethernet II" → identify L2 fields (Dst MAC, Src MAC, EtherType)
# 2. Expand "Internet Protocol" → identify L3 fields (Src IP, Dst IP, TTL, Protocol)
# 3. Expand "Transmission Control Protocol" → identify L4 fields (ports, flags, seq, ack)
# 4. Find the HTTP GET request packet → expand "Hypertext Transfer Protocol" → L7

# Answer these questions:
# - What is the Ethernet EtherType in hex?
# - What IP protocol number identifies TCP?
# - What TCP flags are set in the SYN packet?
# - What TTL does the server's response have? What OS does this suggest?
# - Can you find the HTTP response code?
```

### Exercise 2: ARP Observation and Poisoning (Lab Only) (1 hour)

```bash
# This exercise MUST be done in an isolated lab (two VMs only)
# NEVER on production or shared networks

# VM1 (Attacker - Kali): 192.168.100.10
# VM2 (Target):          192.168.100.20
# Gateway (simulated):   192.168.100.1

# On Target (VM2) — observe normal ARP
arp -a
# Record the gateway's MAC address

# On Attacker (VM1) — start ARP poisoning
sudo arpspoof -i eth0 -t 192.168.100.20 192.168.100.1 &
sudo arpspoof -i eth0 -t 192.168.100.1 192.168.100.20 &
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# On Target (VM2) — check ARP again
arp -a
# The gateway's MAC has changed to Attacker's MAC → ARP poisoning confirmed

# On Attacker (VM1) — observe intercepted traffic
sudo tcpdump -i eth0 -n 'host 192.168.100.20'

# Questions:
# What changed in the ARP cache?
# Can you see target's traffic in tcpdump?
# Can you detect this attack programmatically?

# Detection (on any machine on the same segment):
sudo arpwatch -i eth0    # Logs MAC address changes — would alert on this
```

### Exercise 3: Build a Layer-by-Layer Attack Map (45 minutes)

Using only a packet capture and Wireshark, answer these questions about a network:

```bash
# Download a sample capture
wget https://wiki.wireshark.org/uploads/afae4d9c6a5c0b96db05df03d00c97b0/http.cap
wireshark http.cap

# L1 analysis:
# - Is the capture from Ethernet or Wi-Fi?
# - What is the maximum frame size observed?

# L2 analysis:
# - What are the unique MAC addresses?
# - Look up their OUIs: what manufacturers made these devices?
# - Is there any ARP traffic? What does it reveal?
# - Filter: arp

# L3 analysis:
# - What are the unique IP addresses?
# - What TTLs do you observe? What OSes?
# - Filter: ip

# L4 analysis:
# - What TCP connections exist? (Wireshark Statistics → Conversations → TCP)
# - What is the SYN timestamp? The FIN/RST timestamp? How long was the connection?
# - Filter: tcp.flags.syn == 1 to find all connection initiations

# L7 analysis:
# - What HTTP requests were made? (File → Export Objects → HTTP)
# - What user-agent string reveals the browser/OS?
# - Filter: http.request
```

### Exercise 4: Wireshark OSI Layer Filters (30 minutes)

```bash
# Master Wireshark filters organised by OSI layer

# L2 filters:
eth.dst == ff:ff:ff:ff:ff:ff          # Broadcast frames
eth.type == 0x0806                     # ARP frames only
eth.type == 0x8100                     # 802.1Q VLAN tagged
eth.src == AA:BB:CC:DD:EE:FF           # Specific source MAC
eth.addr == AA:BB:CC:DD:EE:FF          # Source OR destination MAC

# L3 filters:
ip.src == 192.168.1.100               # Specific source IP
ip.dst == 192.168.1.1                 # Specific destination IP
ip.ttl < 10                           # Low TTL (dying packets or traceroute)
ip.frag_offset > 0                    # Fragmented packets (not first fragment)
ip.flags.mf == 1                      # More fragments flag set
icmp                                   # All ICMP traffic
icmp.type == 8                        # ICMP Echo Request (ping)

# L4 filters:
tcp.port == 80                        # TCP port 80 either direction
tcp.dstport == 443                    # HTTPS traffic
tcp.flags.syn == 1 and tcp.flags.ack == 0   # SYN only (new connections)
tcp.flags.rst == 1                    # RST packets (rejected connections)
tcp.analysis.retransmission           # TCP retransmissions (network problems/scanning)
udp.port == 53                        # DNS traffic

# L7 filters:
http.request.method == "POST"         # HTTP POST requests
http.response.code == 200             # Successful HTTP responses
http.response.code >= 400             # HTTP errors
dns.qry.name contains "evil"          # DNS queries containing "evil"
dns.flags.response == 0               # DNS queries only
smb2                                  # SMB2 traffic
```

---

## 15. Module Summary

| OSI Layer | Number | PDU | Key Protocols | Primary Security Attacks | Key Defences |
|-----------|--------|-----|---------------|--------------------------|--------------|
| Application | 7 | Data | HTTP, DNS, SMTP, SMB, Modbus, DNP3, SNMP | SQLi, XSS, DNS poisoning, command injection, Modbus exploitation | WAF, input validation, DNSSEC, IEC 62351 |
| Presentation | 6 | Data | TLS, SSL, JPEG, ASN.1 | CRIME/BREACH, SSL downgrade, Heartbleed, encoding attacks | TLS 1.3, disable TLS compression, patch OpenSSL |
| Session | 5 | Data | NetBIOS, RPC, TLS handshake | Session hijacking, RPC exploitation, LLMNR poisoning | Disable LLMNR/NBT-NS, firewall RPC, HTTPS |
| Transport | 4 | Segment/Datagram | TCP, UDP, QUIC | SYN flood, UDP amplification, port scanning, TIME_WAIT exhaustion | SYN cookies, BCP38, rate limiting, firewall |
| Network | 3 | Packet | IPv4, IPv6, ICMP, OSPF, BGP, IPSec | IP spoofing, ICMP redirect, fragmentation attacks, route injection | BCP38, RPKI, routing authentication, firewall |
| Data Link | 2 | Frame | Ethernet, 802.1Q, ARP, STP, LLDP, GOOSE | ARP spoofing, MAC flooding, VLAN hopping, STP attack, GOOSE injection | DAI, port security, BPDU Guard, IEC 62351-6 |
| Physical | 1 | Bits | Copper, Fibre, 802.11, RS-485 | Wiretapping, jamming, rogue device, hardware implant | Physical security, 802.1X, supply chain audit |

---

> **Next Module:** [Stage 1.3 — TCP/IP Model](./stage-1.3-tcpip-model.md)  
> **Previous Module:** [Stage 1.1 — Network Concepts](./stage-1.1-network-concepts.md)  
> **Series Index:** [Full Roadmap](../../README.md)

---

*This document is part of the Cybersecurity × OT/ICS Security Full Roadmap series. All techniques are presented for educational purposes, authorised security research, and defensive security practice. Always obtain proper authorisation before testing any system.*