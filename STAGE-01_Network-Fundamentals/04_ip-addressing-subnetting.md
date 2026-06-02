# Stage 1.4 — IP Addressing and Subnetting
### From Zero to Cybersecurity Professional | Complete Roadmap Series

> **Series:** Cybersecurity × OT/ICS Security — Full Roadmap  
> **Stage:** 1 — Network Fundamentals  
> **Module:** 1.4 — IP Addressing and Subnetting  
> **Level:** Beginner → Advanced  
> **Prerequisites:** Stage 1.3 — TCP/IP Model  
> **Next Module:** 1.5 — Core Protocols

---

## Table of Contents

1. [Why IP Addressing Is a Security Skill, Not Just a Network Skill](#1-why-ip-addressing-is-a-security-skill-not-just-a-network-skill)
2. [IPv4 Structure — Octets, Binary, and Everything Underneath](#2-ipv4-structure--octets-binary-and-everything-underneath)
3. [Address Classes — A, B, C and Why They Still Matter](#3-address-classes--a-b-c-and-why-they-still-matter)
4. [Public vs Private IP — The Trust Boundary](#4-public-vs-private-ip--the-trust-boundary)
5. [CIDR Notation — The Modern Standard](#5-cidr-notation--the-modern-standard)
6. [Subnet Mask Calculation — From Binary to Practice](#6-subnet-mask-calculation--from-binary-to-practice)
7. [Subnetting — Designing and Breaking Networks](#7-subnetting--designing-and-breaking-networks)
8. [VLSM — Variable Length Subnet Masking](#8-vlsm--variable-length-subnet-masking)
9. [NAT — Network Address Translation](#9-nat--network-address-translation)
10. [PAT — Port Address Translation](#10-pat--port-address-translation)
11. [DHCP — How IP Addresses Are Assigned](#11-dhcp--how-ip-addresses-are-assigned)
12. [DNS — How Names Become Addresses](#12-dns--how-names-become-addresses)
13. [DNS Record Types — The Full Map](#13-dns-record-types--the-full-map)
14. [IP Addressing in OT/ICS Environments](#14-ip-addressing-in-otics-environments)
15. [Hands-On Exercises](#15-hands-on-exercises)
16. [Module Summary](#16-module-summary)

---

## 1. Why IP Addressing Is a Security Skill, Not Just a Network Skill

IP addressing is universally taught as a network engineering topic. Most security courses treat it the same way — cover the basics, move on to "real security." This is a mistake that costs professionals dearly in practice.

**Concrete examples of how IP addressing knowledge directly enables or prevents attacks:**

**Reconnaissance:** Every penetration test begins with identifying the target's IP ranges. CIDR notation determines your scan scope. Understanding which ranges are public vs private tells you what is directly exposed vs behind NAT. Misidentifying the scope means missing assets or scanning out-of-scope systems — both are serious professional failures.

**DHCP starvation and rogue DHCP:** An attacker who understands DHCP's mechanics can exhaust a server's IP pool by repeatedly requesting addresses with spoofed MACs, then deploy a rogue DHCP server that assigns the attacker as the default gateway — a full network MITM without touching a single firewall rule.

**DNS as an attack vector:** DNS is involved in over 90% of malware C2 communications according to Cisco Talos research. DNS cache poisoning, DNS tunnelling, subdomain takeover, dangling CNAME exploitation — all require deep DNS record knowledge to execute or detect.

**NAT traversal:** Understanding how NAT works is what allows attackers to design C2 channels that reach through NAT (reverse shells, DNS tunnelling, HTTPS beaconing). It is also what allows defenders to understand why a reverse shell works when a bind shell does not.

**VLSM and network segmentation:** Designing effective network segmentation — separating user VLANs from server VLANs from OT networks — requires VLSM. Reviewing a network architecture for security flaws requires understanding whether the subnetting design actually achieves the intended isolation.

**For OT/ICS:** Substation automation systems, SCADA networks, and industrial control networks all use IP addressing. The specific subnets in use, the address allocation strategy, and the DHCP/DNS configuration determine the lateral movement paths available to an attacker who gains initial access.

The security mindset for this module: **IP addresses are not just numbers — they are the addressing scheme of the entire attack surface. Every IP, every subnet, every DNS record is a piece of the map.**

---

## 2. IPv4 Structure — Octets, Binary, and Everything Underneath

### 2.1 The Physical Reality of an IP Address

An IPv4 address is a **32-bit binary number**. Everything else — the dotted-decimal notation, the subnet masks, the network/host distinction — is a human-readable interpretation of those 32 bits.

```
192      .    168     .     1      .    100
11000000   10101000   00000001   01100100

Each group of 8 bits = 1 octet = 1 byte
Range per octet: 0 (00000000) to 255 (11111111)
Total combinations: 2^32 = 4,294,967,296
```

### 2.2 Binary Conversion — The Foundation

Every security professional must be able to convert between binary and decimal without a calculator. This is not academic — you will need to calculate network addresses, broadcast addresses, and subnet masks mentally or on paper during exams, interviews, and real assessments.

**Positional values in a single octet:**

```
Bit position:  7    6    5    4    3    2    1    0
Value:        128   64   32   16    8    4    2    1

Example: 192 in binary
  192 = 128 + 64 = 10000000 + 01000000 = 11000000 ✓
  
  Verify: 128 + 64 = 192 ✓

Example: 168 in binary
  168 = 128 + 32 + 8 = 10101000
  
  Verify: 128 + 32 + 8 = 168 ✓

Example: 255 in binary
  255 = 128 + 64 + 32 + 16 + 8 + 4 + 2 + 1 = 11111111
  
  This is the maximum value — all bits set.

Example: 0 in binary
  0 = 00000000
  All bits zero.
```

**Decimal to binary — the systematic method:**

```
Convert 172 to binary:

Step 1: Is 172 ≥ 128? YES → bit 7 = 1, remainder = 172 - 128 = 44
Step 2: Is 44 ≥ 64?  NO  → bit 6 = 0
Step 3: Is 44 ≥ 32?  YES → bit 5 = 1, remainder = 44 - 32 = 12
Step 4: Is 12 ≥ 16?  NO  → bit 4 = 0
Step 5: Is 12 ≥ 8?   YES → bit 3 = 1, remainder = 12 - 8 = 4
Step 6: Is 4 ≥ 4?    YES → bit 2 = 1, remainder = 4 - 4 = 0
Step 7: Is 0 ≥ 2?    NO  → bit 1 = 0
Step 8: Is 0 ≥ 1?    NO  → bit 0 = 0

Result: 10101100 = 172 ✓
Verify: 128 + 32 + 8 + 4 = 172 ✓
```

**Full IP address in binary:**

```
192.168.1.100

192 = 11000000
168 = 10101000
  1 = 00000001
100 = 01100100

Full binary: 11000000.10101000.00000001.01100100
As integer:  3232235876
As hex:      C0.A8.01.64  →  0xC0A80164
```

```python
# Python — complete IP representation toolkit
import ipaddress, socket, struct

def ip_analysis(ip_str):
    ip = ipaddress.ip_address(ip_str)
    
    # Binary representation
    octets = ip_str.split('.')
    binary = '.'.join(f'{int(o):08b}' for o in octets)
    
    # Integer representation
    ip_int = int(ip)
    
    # Hex representation
    ip_hex = '.'.join(f'{int(o):02X}' for o in octets)
    
    print(f"IP Address:  {ip_str}")
    print(f"Binary:      {binary}")
    print(f"Integer:     {ip_int}")
    print(f"Hex:         {ip_hex}")
    print(f"Is private:  {ip.is_private}")
    print(f"Is loopback: {ip.is_loopback}")
    print(f"Is multicast:{ip.is_multicast}")

ip_analysis("192.168.1.100")
print()
ip_analysis("10.0.0.1")
print()
ip_analysis("8.8.8.8")
```

### 2.3 Why Binary Matters for Security

**Subnet calculation:** Every subnet calculation is a binary operation. The network address is found by ANDing the IP with the subnet mask. Without understanding binary, you cannot verify these calculations.

**Firewall rules:** ACLs (Access Control Lists) on routers and firewalls use wildcard masks — the inverse of subnet masks — for matching. `192.168.1.0 0.0.0.255` matches the entire 192.168.1.0/24 range. Understanding binary makes wildcard mask manipulation intuitive.

**Packet crafting:** When you use hping3, Scapy, or Nmap with custom IP options, you are manipulating binary fields in IP headers. Knowing the binary representation of IP addresses prevents mistakes that render your tool ineffective.

**IP spoofing detection:** When analysing packet captures, recognising invalid IP address combinations (e.g., a packet claiming to be from 192.168.x.x arriving on a WAN interface) requires knowing which ranges are private and should never appear on public-facing links.

> **Key Insight:** IP addresses are 32-bit integers dressed up in dotted-decimal notation. Every network operation — subnetting, masking, routing decisions — is binary arithmetic. Professionals who cannot work in binary are operating with a conceptual gap that limits their precision in both attack and defence.

---

## 3. Address Classes — A, B, C and Why They Still Matter

### 3.1 The Historical Design

Before CIDR (1993), the internet used a classful addressing scheme where the address itself determined the network/host boundary. The first bits of the address determined the class.

```
Class A: 0xxxxxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx
  First bit:    0
  Range:        1.0.0.0 – 126.255.255.255
  Default mask: /8  (255.0.0.0)
  Networks:     126 (0 and 127 reserved)
  Hosts/net:    16,777,214  (2^24 - 2)
  
  127.0.0.0/8 is reserved for loopback (127.0.0.1 = localhost)
  
Class B: 10xxxxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx
  First bits:   10
  Range:        128.0.0.0 – 191.255.255.255
  Default mask: /16 (255.255.0.0)
  Networks:     16,384
  Hosts/net:    65,534  (2^16 - 2)
  
Class C: 110xxxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx
  First bits:   110
  Range:        192.0.0.0 – 223.255.255.255
  Default mask: /24 (255.255.255.0)
  Networks:     2,097,152
  Hosts/net:    254  (2^8 - 2)
  
Class D: 1110xxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx
  Range:        224.0.0.0 – 239.255.255.255
  Purpose:      Multicast (not assignable to hosts)
  Examples:     224.0.0.5 (OSPF all routers)
                224.0.0.251 (mDNS)
                239.255.255.250 (SSDP/UPnP)
  
Class E: 1111xxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx
  Range:        240.0.0.0 – 255.255.255.255
  Purpose:      Reserved/experimental
  255.255.255.255: Limited broadcast
```

### 3.2 Why Classes Still Matter Despite CIDR

CIDR replaced classful addressing, but class knowledge remains essential:

**Legacy OT systems:** PLCs, RTUs, and HMIs from the 1990s-2000s often have hardcoded class-based assumptions in their network stack. Some will only communicate within their class boundary. Some configuration interfaces display class-based defaults. Understanding classes is necessary to diagnose connectivity issues with legacy field devices.

**Default subnet masks:** When someone says "we use 10.x.x.x for internal addressing," the implied default mask is /8 (Class A). When a device is misconfigured with the wrong default mask, it will be unable to communicate outside its perceived local network. Diagnosing this requires knowing the class defaults.

**BGP routing:** Internet routing tables still include classful prefixes. Understanding why some routes aggregate nicely (along class boundaries) and why others do not requires class knowledge.

**Security tool output:** Nmap, Masscan, and other scanners sometimes reference class notation. Vulnerability scanners and SIEM correlation rules may use class-based patterns. Misinterpreting these references causes errors.

```bash
# Identify address class from command line:
python3 << 'EOF'
def ip_class(ip):
    first_octet = int(ip.split('.')[0])
    if first_octet == 0:
        return "Reserved (0.x.x.x)"
    elif 1 <= first_octet <= 126:
        return "Class A (default /8)"
    elif first_octet == 127:
        return "Loopback (127.x.x.x)"
    elif 128 <= first_octet <= 191:
        return "Class B (default /16)"
    elif 192 <= first_octet <= 223:
        return "Class C (default /24)"
    elif 224 <= first_octet <= 239:
        return "Class D (Multicast)"
    elif 240 <= first_octet <= 255:
        return "Class E (Reserved/Experimental)"

test_ips = ["10.0.0.1", "127.0.0.1", "172.16.0.1",
            "192.168.1.1", "8.8.8.8", "224.0.0.5", "240.0.0.1"]
for ip in test_ips:
    print(f"{ip:20} → {ip_class(ip)}")
EOF
```

> **Key Insight:** Classful addressing is deprecated but not gone. Legacy OT devices predate CIDR and may exhibit class-based behaviour. Security professionals who only know CIDR will waste hours diagnosing problems that class knowledge would solve in seconds.

---

## 4. Public vs Private IP — The Trust Boundary

### 4.1 The RFC 1918 Private Ranges

RFC 1918 (1996) defined three address ranges that are never routed on the public internet. These are the "private" address spaces:

```
10.0.0.0/8
  Range:   10.0.0.0 – 10.255.255.255
  Hosts:   16,777,214
  Class:   A
  Use:     Large enterprises, cloud internal networks, OT networks
  
172.16.0.0/12
  Range:   172.16.0.0 – 172.31.255.255
  Hosts:   1,048,574
  Class:   B
  Use:     Medium enterprises, Docker default (172.17.0.0/16)
  
192.168.0.0/16
  Range:   192.168.0.0 – 192.168.255.255
  Hosts:   65,534
  Class:   C
  Use:     Home networks, small offices, most common default
```

**Why these ranges are "safe" for internal use:**
ISPs are required (RFC 1918) to filter these ranges at their borders — packets from these addresses should never appear on the internet. If a packet arrives at a WAN interface claiming to come from 192.168.x.x, it is:
1. A misconfigured device
2. A spoofed packet from an attacker (IP spoofing)
3. A filtering failure at an upstream ISP

This is the basis of BCP38 — ISPs should implement ingress filtering to drop packets from their customers whose source IP does not match the customer's allocated range.

### 4.2 Other Special Ranges Every Security Professional Must Know

```
Range              Purpose                              Security Relevance
─────────────────────────────────────────────────────────────────────────
0.0.0.0/8          "This network" — DHCP source        Invalid as source except DHCP discover
127.0.0.0/8        Loopback                             Services binding only to 127.0.0.1 are
                                                        not network-accessible (but can be
                                                        reached via SSRF from the same machine)
100.64.0.0/10      Carrier-grade NAT (CGN)              ISP internal addresses — confuses
                                                        traceroutes, may leak in headers
169.254.0.0/16     APIPA / Link-local                   Assigned by OS when DHCP fails.
                                                        ALSO: AWS/Azure/GCP metadata service
                                                        (169.254.169.254) — critical SSRF target
192.0.2.0/24       TEST-NET-1 (RFC 5737)                Never use in production
198.51.100.0/24    TEST-NET-2 (RFC 5737)                Never use in production
203.0.113.0/24     TEST-NET-3 (RFC 5737)                Never use in production
192.88.99.0/24     6to4 relay (deprecated)              May still appear in older networks
224.0.0.0/4        Multicast                            Routing protocols, service discovery
240.0.0.0/4        Reserved                             Should never appear in normal traffic
255.255.255.255/32 Limited broadcast                    DHCP discover destination
```

### 4.3 The Cloud Metadata Service — Critical SSRF Target

The link-local address 169.254.169.254 deserves special attention. Every major cloud provider (AWS, Azure, GCP, DigitalOcean, etc.) uses this address for their instance metadata service.

```
AWS EC2 Metadata Service:
  http://169.254.169.254/latest/meta-data/
  
  Contains:
    /iam/security-credentials/           ← Temporary IAM credentials
    /iam/security-credentials/<role>/    ← Specific role credentials
    /public-ipv4                         ← Instance's public IP
    /local-ipv4                          ← Instance's private IP
    /hostname                            ← Instance hostname
    /user-data                           ← Startup script (often contains secrets)
    /placement/availability-zone         ← Where this instance is running
    /security-groups                     ← Attached security groups

Azure IMDS (Instance Metadata Service):
  http://169.254.169.254/metadata/instance
  (requires header: Metadata: true)
  
GCP Metadata Server:
  http://metadata.google.internal/ (resolves to 169.254.169.254)
  http://169.254.169.254/computeMetadata/v1/
  (requires header: Metadata-Flavor: Google)
```

**SSRF to Cloud Metadata — One of the Most Impactful Attack Chains:**

If a web application is vulnerable to SSRF (Server-Side Request Forgery), and it runs on a cloud VM, an attacker can:

1. Send SSRF payload: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
2. Get the IAM role name from the response
3. Send: `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>`
4. Receive: `AccessKeyId`, `SecretAccessKey`, `Token` — temporary AWS credentials
5. Use credentials to access S3 buckets, RDS databases, other AWS services

**Real-world impact:** The 2019 Capital One breach exposed 100 million customer records. The attacker exploited an SSRF vulnerability in a WAF configuration, reached the metadata service, obtained IAM credentials, and used them to exfiltrate data from S3. The metadata service was the pivot point.

```bash
# Test metadata service access from inside a cloud VM:
curl http://169.254.169.254/latest/meta-data/                     # AWS
curl -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"  # Azure
curl -H "Metadata-Flavor:Google" http://169.254.169.254/computeMetadata/v1/  # GCP

# AWS IMDSv2 (more secure — requires token):
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/

# Detection: 
# In AWS CloudTrail, metadata service calls don't appear (they're local)
# But the subsequent use of temporary credentials DOES appear in CloudTrail
# Alert on: IAM credential usage from unexpected IPs or at unexpected times
```

> **Key Insight:** The line between "private" and "public" is not just about RFC 1918. It is about trust. Private addresses imply internal trust. Cloud metadata services at 169.254.169.254 operate entirely on that trust assumption — no authentication, no encryption, just "you're on the network, so here are the credentials." SSRF that reaches this address is nearly always critical severity.

---

## 5. CIDR Notation — The Modern Standard

### 5.1 What CIDR Is and Why It Replaced Classes

CIDR (Classless Inter-Domain Routing, RFC 4632, 1993) solves the fundamental waste problem of classful addressing. Under the classful system, an organisation that needed 500 addresses received a Class B (/16, 65,534 hosts) — wasting 65,034 addresses. This accelerated IPv4 exhaustion.

CIDR allows any prefix length — the network/host boundary can be placed anywhere in the 32-bit address. A `/22` gives exactly 1,022 hosts, matching the real requirement.

```
CIDR Notation: IP_address/prefix_length
Example: 192.168.1.0/24

/24 means: first 24 bits are the NETWORK portion
           last 8 bits are the HOST portion
           
Binary representation:
  Network bits: 11111111.11111111.11111111.00000000 = 255.255.255.0 (subnet mask)
  
Network address:    192.168.1.0   (all host bits = 0)
Broadcast address:  192.168.1.255 (all host bits = 1)
Usable host range:  192.168.1.1 – 192.168.1.254
Usable hosts:       2^8 - 2 = 254
```

### 5.2 Prefix Length to Subnet Mask Conversion

```
/prefix → subnet mask (must memorise these):

/8  → 255.0.0.0       (11111111.00000000.00000000.00000000)
/9  → 255.128.0.0
/10 → 255.192.0.0
/11 → 255.224.0.0
/12 → 255.240.0.0
/13 → 255.248.0.0
/14 → 255.252.0.0
/15 → 255.254.0.0
/16 → 255.255.0.0     (11111111.11111111.00000000.00000000)
/17 → 255.255.128.0
/18 → 255.255.192.0
/19 → 255.255.224.0
/20 → 255.255.240.0
/21 → 255.255.248.0
/22 → 255.255.252.0
/23 → 255.255.254.0
/24 → 255.255.255.0   (11111111.11111111.11111111.00000000)
/25 → 255.255.255.128
/26 → 255.255.255.192
/27 → 255.255.255.224
/28 → 255.255.255.240
/29 → 255.255.255.248
/30 → 255.255.255.252
/31 → 255.255.255.254 (point-to-point links — RFC 3021, no broadcast)
/32 → 255.255.255.255 (single host route)
```

**The pattern:** Each bit added to the prefix doubles the number of networks and halves the number of hosts.

```
Quick host calculation from prefix:
  Hosts = 2^(32 - prefix) - 2

/24 → 2^8  - 2 = 254
/25 → 2^7  - 2 = 126
/26 → 2^6  - 2 = 62
/27 → 2^5  - 2 = 30
/28 → 2^4  - 2 = 14
/29 → 2^3  - 2 = 6
/30 → 2^2  - 2 = 2     ← Point-to-point links between routers
/31 → 2^1  - 2 = 0     ← RFC 3021: used for P2P with no broadcast
/32 → 2^0  - 2 = -1    ← Single host route (host bits all 0 or 1, no subtraction)
```

### 5.3 CIDR in Security Operations

```bash
# Nmap with CIDR — scan entire subnets:
sudo nmap -sn 10.0.0.0/8          # Scan all 16M addresses in Class A (slow)
sudo nmap -sn 192.168.1.0/24      # Scan /24 (fast, common for LAN recon)
sudo nmap -sS 10.10.10.0/24       # SYN scan of /24

# Masscan — faster for large CIDR ranges:
sudo masscan 10.0.0.0/8 -p80,443,22,3389 --rate=10000
# --rate = packets per second (be careful on production networks)

# Python CIDR operations:
python3 << 'EOF'
import ipaddress

# Check if IP is within a CIDR range:
network = ipaddress.ip_network("10.10.0.0/16")
test_ip = ipaddress.ip_address("10.10.5.100")
print(f"{test_ip} in {network}: {test_ip in network}")

# Generate all IPs in a range (useful for scripting):
for ip in list(ipaddress.ip_network("192.168.1.0/29").hosts()):
    print(ip)

# Summarise multiple subnets:
nets = [
    ipaddress.ip_network("192.168.1.0/26"),
    ipaddress.ip_network("192.168.1.64/26"),
    ipaddress.ip_network("192.168.1.128/26"),
    ipaddress.ip_network("192.168.1.192/26"),
]
collapsed = list(ipaddress.collapse_addresses(nets))
print(f"\nCollapsed: {collapsed}")  # Should show 192.168.1.0/24

# Check if two networks overlap (critical for firewall rule analysis):
net1 = ipaddress.ip_network("10.0.0.0/8")
net2 = ipaddress.ip_network("10.10.0.0/16")
print(f"\nNetworks overlap: {net1.overlaps(net2)}")  # True
EOF

# iptables/nftables use CIDR notation:
sudo iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT   # Allow entire /24
sudo iptables -A INPUT -s 10.0.0.0/8 -j DROP         # Block entire Class A

# Wireshark CIDR filter:
# ip.addr == 192.168.1.0/24    → All traffic involving this subnet
# ip.src == 10.0.0.0/8         → Traffic sourced from 10.x.x.x
```

---

## 6. Subnet Mask Calculation — From Binary to Practice

### 6.1 What the Subnet Mask Does

The subnet mask tells a device which part of an IP address is the **network portion** and which part is the **host portion**. This is how a device knows whether a destination is on the same local network (no routing needed) or on a different network (send to default gateway).

```
Operation: Bitwise AND between IP address and subnet mask

IP address:    192.168.1.100 = 11000000.10101000.00000001.01100100
Subnet mask:   255.255.255.0 = 11111111.11111111.11111111.00000000
                               ────────────────────────────────────
AND result:    192.168.1.0   = 11000000.10101000.00000001.00000000
                               ← Network address

The network address is the IP with all host bits set to 0.
```

**How a device uses this:**

```
Device: 192.168.1.100/24
Wants to send to: 192.168.1.50

Step 1: Calculate own network address
  192.168.1.100 AND 255.255.255.0 = 192.168.1.0

Step 2: Calculate destination network address
  192.168.1.50 AND 255.255.255.0 = 192.168.1.0

Step 3: Are they the same? YES
  → Destination is local, send directly (use ARP to find MAC)

───────────────────────────────────────────────────────

Device: 192.168.1.100/24
Wants to send to: 10.0.0.1

Step 1: Own network: 192.168.1.0
Step 2: Destination network: 10.0.0.0 (AND with 255.255.255.0)
Step 3: Are they the same? NO
  → Destination is remote, send to default gateway
```

### 6.2 Finding Network and Broadcast Addresses

```
Given: 192.168.10.130/25

Step 1: Convert prefix to mask
  /25 → 255.255.255.128 = 11111111.11111111.11111111.10000000

Step 2: Find network address (AND)
  IP:   11000000.10101000.00001010.10000010
  Mask: 11111111.11111111.11111111.10000000
  AND:  11000000.10101000.00001010.10000000 = 192.168.10.128

Step 3: Find broadcast address (OR with inverted mask)
  Inverted mask (wildcard): 00000000.00000000.00000000.01111111
  Network:  11000000.10101000.00001010.10000000
  Wildcard: 00000000.00000000.00000000.01111111
  OR:       11000000.10101000.00001010.11111111 = 192.168.10.255

Results:
  Network address:   192.168.10.128
  Broadcast address: 192.168.10.255
  First host:        192.168.10.129
  Last host:         192.168.10.254
  Usable hosts:      2^7 - 2 = 126
```

```bash
# Subnet calculation tools:
ipcalc 192.168.10.130/25       # Comprehensive subnet info
ipcalc -n 192.168.10.130/25    # Network address only
ipcalc -b 192.168.10.130/25    # Broadcast only

# Python:
python3 -c "
import ipaddress
net = ipaddress.ip_interface('192.168.10.130/25').network
print(f'Network:   {net.network_address}')
print(f'Broadcast: {net.broadcast_address}')
print(f'Mask:      {net.netmask}')
print(f'Wildcard:  {net.hostmask}')
print(f'First:     {list(net.hosts())[0]}')
print(f'Last:      {list(net.hosts())[-1]}')
print(f'Hosts:     {net.num_addresses - 2}')
"

# Determine subnet from any IP:
ip route get 192.168.1.50      # Linux — shows route to this IP
ip addr show                    # Shows all interfaces with CIDR notation
```

---

## 7. Subnetting — Designing and Breaking Networks

### 7.1 Why Subnetting Is a Security Design Tool

Subnetting is not just about efficient address use — it is the primary mechanism for **network segmentation**. Separate subnets, enforced by routers and firewalls, are the foundation of defence-in-depth at the network layer.

A flat network (everyone in one subnet) means:
- Broadcast traffic hits every device
- ARP poisoning reaches every device
- A compromised workstation can reach every server directly
- No choke points for traffic inspection

A segmented network means:
- Traffic between subnets must cross a router or firewall
- Security policies can be enforced at subnet boundaries
- Compromise of one subnet does not grant immediate access to others
- Lateral movement requires exploiting the routing/firewall boundary

### 7.2 Subnetting a Network — The Complete Method

**Problem:** You have 192.168.1.0/24 and need to create 4 subnets of (approximately) equal size.

```
Step 1: Determine how many subnet bits are needed
  4 subnets → need 2 bits (2^2 = 4)
  Borrow 2 bits from the host portion

Step 2: New prefix length
  Original: /24
  New:      /24 + 2 = /26

Step 3: New subnet mask
  /26 = 11111111.11111111.11111111.11000000 = 255.255.255.192

Step 4: Block size
  8 host bits - 2 subnet bits = 6 host bits
  Hosts per subnet: 2^6 - 2 = 62
  Block size: 2^6 = 64

Step 5: List all subnets
  Subnet 1: 192.168.1.0/26     → hosts: 192.168.1.1   – 192.168.1.62
  Subnet 2: 192.168.1.64/26    → hosts: 192.168.1.65  – 192.168.1.126
  Subnet 3: 192.168.1.128/26   → hosts: 192.168.1.129 – 192.168.1.190
  Subnet 4: 192.168.1.192/26   → hosts: 192.168.1.193 – 192.168.1.254

Broadcasts: .63, .127, .191, .255
```

**Security application of subnetting:**

```
Typical enterprise segmented network design:

Segment             Subnet           Purpose                Security Posture
────────────────────────────────────────────────────────────────────────────
Users               10.10.1.0/24    Workstations           Least trusted
Servers             10.10.2.0/24    Internal servers       More trusted
Management          10.10.3.0/27    Network devices        Highly restricted
DMZ                 10.10.4.0/28    Internet-facing        Partially trusted
Guest               10.10.5.0/24    Visitor WiFi           Untrusted
OT/Control          10.20.0.0/24    Industrial devices     Isolated
OT/SCADA Server     10.20.1.0/28    HMI/Historian          Isolated
Surveillance        10.30.0.0/24    CCTV cameras           Isolated

Between each segment: firewall with explicit allow rules.
Default policy: DENY ALL.
```

### 7.3 Subnetting in Attack Context

**Identifying the subnet from inside:**

```bash
# After initial access, enumerate network configuration:
ip addr show                          # Own IP + subnet
ip route show                         # Routing table (reveals other subnets)
cat /etc/hosts                        # Static hostname mappings
cat /etc/resolv.conf                  # DNS server IPs (often on internal network)
arp -a                                # Recently communicated hosts

# Infer network topology from routing table:
ip route show
# Example output:
# default via 10.10.1.1 dev eth0       ← Default gateway
# 10.10.1.0/24 dev eth0               ← Local subnet
# 10.10.2.0/24 via 10.10.1.1 dev eth0 ← Route to server subnet (gateway is router)

# The presence of routes to 10.10.2.0/24 reveals the server subnet exists
# Even if firewall blocks direct access, knowing the subnet guides further attacks
```

**Subnet scanning after initial access:**

```bash
# Fast host discovery within a discovered subnet:
# Method 1: Ping sweep (often blocked by firewalls)
for i in $(seq 1 254); do ping -c 1 -W 1 10.10.2.$i &>/dev/null && echo "10.10.2.$i alive"; done

# Method 2: ARP scan (only works on same subnet)
sudo arp-scan 10.10.1.0/24

# Method 3: TCP SYN to common ports (works across subnets)
sudo nmap -sS -p 22,80,443,445,3389 --open 10.10.2.0/24 2>/dev/null

# Method 4: Using nc for quick port checks
nc -zv -w 1 10.10.2.100 22 80 443 2>&1 | grep succeeded

# Method 5: Python ping sweep
python3 << 'EOF'
import subprocess, ipaddress, concurrent.futures

def ping(ip):
    result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)],
                           capture_output=True)
    if result.returncode == 0:
        return str(ip)
    return None

network = ipaddress.ip_network("10.10.2.0/24")
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    futures = {executor.submit(ping, host): host for host in network.hosts()}
    for future in concurrent.futures.as_completed(futures):
        result = future.result()
        if result:
            print(f"ALIVE: {result}")
EOF
```

> **Key Insight:** Subnetting is both a network design tool and a map-reading skill for attackers. From the attacker's perspective, routing tables and network configurations gathered during post-exploitation reveal the entire subnet architecture — which subnets exist, how they are connected, and what paths exist between them. Defenders must assume that an attacker who gains any foothold will enumerate the full subnet topology.

---

## 8. VLSM — Variable Length Subnet Masking

### 8.1 What VLSM Solves

Fixed-length subnetting wastes addresses. VLSM allows different subnets within the same network to have different prefix lengths — each subnet is sized exactly for its requirement.

**Problem with fixed subnetting:**
```
You need:
  - 1 subnet for 100 users    → need /25 (126 hosts)
  - 1 subnet for 20 servers   → need /27 (30 hosts)
  - 1 subnet for 10 printers  → need /28 (14 hosts)
  - 4 point-to-point links    → need /30 (2 hosts each)

Fixed /25 approach (wasteful):
  All subnets are /25 = 126 hosts each
  Servers subnet: 126 - 20 = 106 wasted addresses
  Printers subnet: 126 - 10 = 116 wasted addresses
  P2P links: 126 - 2 = 124 wasted addresses each

VLSM approach (efficient):
  User subnet:    /25 = 126 hosts ← sized correctly
  Server subnet:  /27 = 30 hosts  ← sized correctly
  Printer subnet: /28 = 14 hosts  ← sized correctly
  P2P links:      /30 = 2 hosts   ← sized correctly
```

### 8.2 VLSM Design Process

**Always start with the largest subnet and work down.**

```
Available block: 192.168.1.0/24 (254 hosts)
Requirements:
  1. Subnet A: 100 hosts
  2. Subnet B: 50 hosts
  3. Subnet C: 20 hosts
  4. Subnet D: 10 hosts
  5. Subnet E: 2 hosts (point-to-point link)

Step 1: Subnet A (100 hosts)
  Need: 2^n - 2 ≥ 100 → n=7 (2^7-2=126) → /25
  Assign: 192.168.1.0/25
  Range: 192.168.1.0 – 192.168.1.127
  Next available: 192.168.1.128

Step 2: Subnet B (50 hosts)
  Need: 2^n - 2 ≥ 50 → n=6 (2^6-2=62) → /26
  Assign: 192.168.1.128/26
  Range: 192.168.1.128 – 192.168.1.191
  Next available: 192.168.1.192

Step 3: Subnet C (20 hosts)
  Need: 2^n - 2 ≥ 20 → n=5 (2^5-2=30) → /27
  Assign: 192.168.1.192/27
  Range: 192.168.1.192 – 192.168.1.223
  Next available: 192.168.1.224

Step 4: Subnet D (10 hosts)
  Need: 2^n - 2 ≥ 10 → n=4 (2^4-2=14) → /28
  Assign: 192.168.1.224/28
  Range: 192.168.1.224 – 192.168.1.239
  Next available: 192.168.1.240

Step 5: Subnet E (2 hosts, P2P link)
  Need: 2^n - 2 ≥ 2 → n=2 (2^2-2=2) → /30
  Assign: 192.168.1.240/30
  Range: 192.168.1.240 – 192.168.1.243
  Remaining: 192.168.1.244 – 192.168.1.255 (available for future use)
```

### 8.3 VLSM and Security Architecture

VLSM is what makes proper OT network segmentation practical. Different zones have vastly different host count requirements:

```
OT Network VLSM Design Example:
  
  Corporate IT-OT DMZ:      10.20.0.0/28   (14 hosts — jump servers, historians)
  SCADA Server Zone:        10.20.0.16/29  (6 hosts — HMI servers, SCADA servers)
  Control Network:          10.20.0.24/29  (6 hosts — PLCs, RTUs)
  Field Device Network:     10.20.0.32/27  (30 hosts — sensors, actuators)
  Engineering Workstations: 10.20.0.64/28  (14 hosts — EWS)
  IT-OT Firewall Link:      10.20.0.80/30  (2 hosts — P2P firewall interfaces)
  OT-SCADA Firewall Link:   10.20.0.84/30  (2 hosts — P2P firewall interfaces)
  
  Total used: 192.168.0.0/24
  Each zone isolated with firewall — traffic only flows through permitted paths
```

```bash
# Verify VLSM design is correct (no overlaps):
python3 << 'EOF'
import ipaddress

subnets = [
    "10.20.0.0/28",
    "10.20.0.16/29",
    "10.20.0.24/29",
    "10.20.0.32/27",
    "10.20.0.64/28",
    "10.20.0.80/30",
    "10.20.0.84/30",
]

networks = [ipaddress.ip_network(s) for s in subnets]

# Check for overlaps:
overlaps = []
for i, n1 in enumerate(networks):
    for j, n2 in enumerate(networks):
        if i < j and n1.overlaps(n2):
            overlaps.append((subnets[i], subnets[j]))

if overlaps:
    print("OVERLAP DETECTED:")
    for o in overlaps:
        print(f"  {o[0]} overlaps with {o[1]}")
else:
    print("No overlaps — VLSM design is valid")
    
# Show total address space used:
total = sum(n.num_addresses for n in networks)
print(f"Total addresses allocated: {total}")
EOF
```

---

## 9. NAT — Network Address Translation

### 9.1 How NAT Works Internally

NAT maintains a **translation table** that maps {private IP, private port} to {public IP, public port} pairs.

```
NAT Translation Table:
┌────────────────────────┬────────────────────────┬──────────────────┐
│ Inside Local           │ Inside Global          │ Protocol         │
│ (Private IP:Port)      │ (Public IP:Port)       │                  │
├────────────────────────┼────────────────────────┼──────────────────┤
│ 192.168.1.10:54321     │ 203.0.113.1:12001      │ TCP              │
│ 192.168.1.10:54322     │ 203.0.113.1:12002      │ TCP              │
│ 192.168.1.20:45678     │ 203.0.113.1:12003      │ TCP              │
│ 192.168.1.30:53        │ 203.0.113.1:12004      │ UDP              │
└────────────────────────┴────────────────────────┴──────────────────┘

Outbound packet:
  Source: 192.168.1.10:54321  Destination: 8.8.8.8:53
  NAT rewrites source: 203.0.113.1:12001  Destination: 8.8.8.8:53
  Adds entry to table

Inbound packet:
  Source: 8.8.8.8:53  Destination: 203.0.113.1:12001
  NAT looks up 203.0.113.1:12001 → 192.168.1.10:54321
  Rewrites destination: 8.8.8.8:53 → 192.168.1.10:54321
  Forwards to internal host
```

### 9.2 NAT Types

**Static NAT (one-to-one):**
One private IP permanently maps to one public IP.
Used for: servers that must be reachable from the internet on their own public IP.
Security: same attack surface as a directly connected server — no protection.

**Dynamic NAT:**
Pool of public IPs, allocated on demand from private IPs.
Used when: organisation has multiple public IPs but more private hosts.
Less common in modern deployments.

**PAT / NAT Overload (most common):**
Many private IPs share one public IP, differentiated by source port.
This is what virtually every home router and most corporate NAT devices implement.
Covered in detail in Section 10.

**Port Forwarding (Destination NAT / DNAT):**
Inbound traffic to a specific public IP:port is redirected to a private IP:port.
```
Example: All traffic to 203.0.113.1:80 → 192.168.1.100:80 (internal web server)
```
Security: explicitly exposes a specific internal host to the internet.
Must be carefully controlled — unauthorised port forwarding is a security incident.

### 9.3 NAT Security Implications

**NAT is NOT a security control — it is an address translation mechanism:**

```
Common misconception: "We're behind NAT, so we're protected"

Why this is wrong:
  1. Outbound connections bypass NAT protection entirely
     Malware can establish outbound connections to C2 servers
     NAT translates and allows these — it only blocks UNSOLICITED inbound

  2. NAT traversal techniques bypass inbound filtering:
     STUN (Session Traversal Utilities for NAT): used by WebRTC
     TURN (Traversal Using Relays around NAT): relay-based bypass
     UPnP (Universal Plug and Play): applications self-configure port forwarding
     ICMP tunnelling: encapsulate traffic in ICMP (sometimes passes NAT)
     
  3. UPnP is a significant vulnerability:
     By default, applications can call UPnP to open arbitrary port forwards
     Malware does this to create persistent inbound access
     
     # Check if UPnP is running on your router:
     sudo nmap -sU -p 1900 192.168.1.1        # SSDP/UPnP discovery
     upnpc -l                                  # List current port forwards (miniupnpc package)
     
  4. Application Layer Gateway (ALG) vulnerabilities:
     NAT must understand some protocols (FTP, SIP, H.323) to translate correctly
     ALG implementations have had vulnerabilities
     NAT-ALG for FTP has been exploited to reach internal hosts
```

**Forensic implications of NAT:**

```
Problem: NAT hides the true source of connections
  Security camera records show: IP 203.0.113.1 accessed the server
  But who was it? Could be any of 5,000 internal hosts using that NAT

Solution: NAT logging is mandatory for attribution
  Every enterprise firewall/NAT device should log:
  - Timestamp of translation creation
  - Inside local IP:port
  - Inside global IP:port
  - Outside IP:port
  - Protocol
  - Duration

  Without NAT logs, incident response attribution is impossible.
  Log format: May 29 10:00:01 firewall %NAT-6-LOG: TCP src 192.168.1.50:54321
              dst 203.0.113.50:80 translated to src 203.0.113.1:12345
```

> **Key Insight:** NAT's protection is entirely passive — it blocks unsolicited inbound connections because there is no NAT entry to translate them. The moment a connection is initiated from inside (which malware always does), NAT becomes invisible. Every reverse shell, every HTTPS C2 beacon, every DNS tunnel — all traverse NAT without obstruction. NAT logging is the only forensic tool that allows attribution after an incident.

---

## 10. PAT — Port Address Translation

### 10.1 How PAT Differs from NAT

PAT (Port Address Translation), also called NAT Overload or NAPT (Network Address and Port Translation), is the specific technique that allows many private hosts to share a single public IP address by using different source port numbers to distinguish connections.

```
PAT in action — three internal hosts accessing the same web server:

Inside:                    Public:              Outside:
192.168.1.10:51000  ────→  1.2.3.4:40001 ────→  93.184.216.34:80
192.168.1.20:51000  ────→  1.2.3.4:40002 ────→  93.184.216.34:80
192.168.1.30:51000  ────→  1.2.3.4:40003 ────→  93.184.216.34:80

All three inside hosts use the same source port (51000) from their perspective.
PAT allocates unique source ports on the public side (40001, 40002, 40003).
The external server sees three connections from 1.2.3.4 on different source ports.
When response arrives to 1.2.3.4:40001, PAT knows to send it to 192.168.1.10:51000.
```

### 10.2 Port Exhaustion

PAT source ports are 16-bit (0-65535). With 1,024 reserved ports, approximately 64,511 simultaneous connections per public IP are theoretically possible. In practice, the limit is lower due to OS state, timeout timers, and memory.

**Port exhaustion attack:**
An attacker from inside the NAT could rapidly open connections to an external server, exhausting the PAT table and preventing other internal hosts from making new connections. This is a DoS attack against the NAT device itself.

**Large-scale NAT and Carrier-Grade NAT (CGN):**
ISPs use CGN (100.64.0.0/10 range) to NAT entire customer networks behind a shared IP. Multiple customers share one public IP. Port exhaustion here affects all sharing customers.

From a security/forensics perspective: CGN makes attribution even harder — millions of customers may share a single IP.

---

## 11. DHCP — How IP Addresses Are Assigned

### 11.1 The DORA Process

DHCP (Dynamic Host Configuration Protocol, RFC 2131) automates IP address assignment. The four-step process is called DORA:

```
CLIENT                                      DHCP SERVER
  │                                              │
  │ DISCOVER (broadcast, src: 0.0.0.0:68)       │
  │ ─────────────────────────────────────────→  │
  │ "I need an IP address"                       │
  │ Src IP: 0.0.0.0  (no IP yet)                │
  │ Dst IP: 255.255.255.255 (broadcast)          │
  │ Transaction ID: 0x12345678                   │
  │                                              │
  │ ←───────────────────────────────────────── │
  │ OFFER (unicast or broadcast)                 │
  │ "I offer you 192.168.1.50"                   │
  │ Offered IP: 192.168.1.50                     │
  │ Server IP: 192.168.1.1                       │
  │ Lease time: 86400 seconds (24 hours)         │
  │ Gateway: 192.168.1.1                         │
  │ DNS: 8.8.8.8, 8.8.4.4                       │
  │ Subnet mask: 255.255.255.0                   │
  │                                              │
  │ REQUEST (broadcast)                          │
  │ ─────────────────────────────────────────→  │
  │ "I accept 192.168.1.50 from server .1"       │
  │ Broadcast — informs other DHCP servers too   │
  │                                              │
  │ ←───────────────────────────────────────── │
  │ ACKNOWLEDGE (ACK)                            │
  │ "Confirmed. 192.168.1.50 is yours for 24h"  │
  │                                              │
  [Client configures interface with offered params]
```

**DHCP Options — what DHCP can configure:**

```
Option 1:   Subnet Mask
Option 3:   Default Gateway (Router)
Option 6:   DNS Servers
Option 12:  Hostname
Option 15:  Domain Name
Option 28:  Broadcast Address
Option 42:  NTP Servers
Option 43:  Vendor-specific options (used by PXE boot, VoIP phones, OT devices)
Option 51:  Lease Time
Option 54:  DHCP Server IP
Option 58:  Renewal Time (T1) — when to start renewing (50% of lease time)
Option 59:  Rebinding Time (T2) — when to broadcast for any DHCP server (87.5%)
Option 60:  Vendor Class Identifier (client announces its type)
Option 61:  Client Identifier (usually MAC address)
Option 66:  TFTP Server Name (for network boot)
Option 67:  Bootfile Name (for PXE boot)
Option 82:  DHCP Relay Agent Information (circuit ID, remote ID)
Option 119: Domain Search List
Option 121: Classless Static Routes (inject routes into clients)
Option 252: WPAD URL (web proxy auto-discovery — Option 252 is the de facto standard)
```

**Option 121 — Classless Static Routes (CVE-2024-3661 / TunnelVision):**
This is a critical vulnerability disclosed in May 2024. A rogue DHCP server can use Option 121 to inject arbitrary routes into a client's routing table. By routing all traffic through the attacker's gateway and adding a specific route for the VPN's traffic, the attacker can force VPN traffic outside the encrypted tunnel — bypassing VPN protections and enabling plaintext traffic interception.

```
Attack scenario:
1. Attacker deploys rogue DHCP server on Wi-Fi network
2. Serves Option 121: route 0.0.0.0/1 via attacker, 128.0.0.0/1 via attacker
   (Splits the default route — more specific than VPN's /0 route)
3. All traffic routes outside the VPN tunnel to the attacker
4. VPN client still shows "connected" — no indication of bypass

Affected: All OSes that honour DHCP Option 121 with VPN active
Not affected: Android (ignores Option 121), Linux with network namespace VPNs
Mitigations:
  - Run VPN in isolated network namespace (Linux)
  - Disable DHCP Option 121 processing
  - Use VPN with kill switch and route protection
```

### 11.2 DHCP Attacks

**DHCP Starvation:**

```
Attack:
  Attacker sends thousands of DHCP DISCOVER messages
  Each with a different spoofed MAC address (Option 61: Client Identifier)
  DHCP server allocates one IP per request
  IP pool is exhausted
  Legitimate clients receive no IP addresses → DoS

Tool: dhcpstarv, Yersinia
  sudo yersinia dhcp -attack 1    # DHCP starvation

Detection:
  DHCP server logs show massive number of DISCOVER/OFFER pairs
  Short time between pool exhaustion events
  Many entries in DHCP lease table with sequential MAC addresses (00:0c:29:xx:xx:xx format)

Mitigation:
  DHCP snooping on switches: limits DHCP messages per port per second
  Cisco: ip dhcp snooping limit rate 15  (15 DHCP packets/second max per port)
```

**Rogue DHCP Server:**

```
Attack:
  Attacker deploys their own DHCP server on the network
  Responds to DISCOVER messages faster than the legitimate server
  Clients accept the first OFFER received
  Attacker's OFFER configures:
    - Client's gateway: attacker's IP → all traffic through attacker (MITM)
    - Client's DNS: attacker's DNS server → DNS hijacking
    - Client's routes (Option 121): attacker's routes

This is the complete network takeover without touching a single firewall.

Detection:
  Multiple DHCP servers advertising on the network
  dhcpdump: capture all DHCP traffic and alert on unexpected server IPs
  DHCP snooping: designate trusted ports — only allow DHCP OFFER from trusted
  
Cisco DHCP snooping:
  ip dhcp snooping vlan 10          # Enable for VLAN 10
  ip dhcp snooping                  # Enable globally
  interface gi0/1
   ip dhcp snooping trust           # Uplink to real DHCP server — trusted
  interface gi0/2                   # User-facing ports — untrusted by default
   (DHCP OFFER from this port is dropped)
```

**WPAD — Web Proxy Auto-Discovery (DHCP Option 252):**

```
Attack chain:
1. DHCP server (rogue or legitimate) includes Option 252:
   wpad=http://wpad.company.local/wpad.dat
2. Browser fetches wpad.dat automatically
3. Attacker controls wpad.dat content
4. wpad.dat configures browser to use attacker as proxy
5. Attacker proxies and MITMs all HTTP/HTTPS traffic

Defence:
  Disable WPAD in browser settings
  Block port 80/8080 outbound to unknown hosts
  DHCP snooping prevents rogue DHCP from serving WPAD URL
  DNS: ensure wpad.<domain> does not resolve to attacker-controlled IP
```

```bash
# DHCP monitoring and analysis:
sudo dhcpdump -i eth0               # Monitor all DHCP traffic

# Capture DHCP traffic:
sudo tcpdump -i eth0 -n 'port 67 or port 68'

# Check DHCP lease information on Linux:
cat /var/lib/dhcp/dhclient.leases   # DHCP lease file
dhclient -v eth0 2>&1               # Verbose DHCP negotiation

# On Windows:
ipconfig /all                       # Shows DHCP server IP, lease times
ipconfig /release                   # Release current IP
ipconfig /renew                     # Get new IP from DHCP
```

> **Key Insight:** DHCP is trusted implicitly by every OS — there is no authentication mechanism. The first server to respond wins. This means physical network access (plugging into an Ethernet port or connecting to Wi-Fi) combined with a rogue DHCP server grants an attacker full network MITM capability without any exploit. DHCP snooping is the only reliable mitigation, and it requires managed switch infrastructure.

---

## 12. DNS — How Names Become Addresses

### 12.1 The DNS Hierarchy

DNS is a globally distributed, hierarchical database. Understanding its structure is essential because attacks target every level of the hierarchy.

```
DNS Hierarchy:
                          . (Root)
                         / \
                        /   \
                      .com  .org  .net  .tr  .io  ...
                      /
                  google.com
                  /          \
           www.google.com   mail.google.com

Authoritative name servers exist at every level:
  Root: 13 root server clusters (a.root-servers.net through m.root-servers.net)
  TLD:  .com managed by Verisign, .org by PIR, .tr by NIC.tr, etc.
  Domain: google.com managed by Google's own nameservers (ns1.google.com, etc.)
```

### 12.2 DNS Resolution — The Complete Process

```
Query: What is the IP address of www.example.com?

1. Client checks local DNS cache → not found
   (Linux: /etc/hosts → /etc/nsswitch.conf → resolver)

2. Client queries configured resolver (stub resolver)
   Usually: ISP's DNS, 8.8.8.8, 1.1.1.1, or internal DNS server
   Type: Recursive query ("find the answer for me, wherever it is")

3. Resolver checks its cache → not found (assume cold start)

4. Resolver queries ROOT servers (hardcoded list of 13 clusters)
   Question: "Who handles .com?"
   Root response: "Ask c.gtld-servers.net (192.26.92.30) for .com"
   (Non-recursive, referral response)

5. Resolver queries .com TLD server (c.gtld-servers.net)
   Question: "Who handles example.com?"
   TLD response: "Ask ns1.example.com (93.184.216.x) for example.com"
   (Non-recursive, referral response)

6. Resolver queries example.com's authoritative server (ns1.example.com)
   Question: "What is the IP of www.example.com?"
   Auth server response: "www.example.com → 93.184.216.34 (A record, TTL=86400)"
   (Authoritative answer)

7. Resolver caches the answer for TTL seconds (86400 = 24 hours)
   Resolver sends answer to client

8. Client caches the answer for TTL seconds
   Client connects to 93.184.216.34

Total time: typically 50-300ms for cold query, <1ms for cached
```

### 12.3 DNS Security Mechanisms

**DNSSEC — DNS Security Extensions:**
DNSSEC adds cryptographic signatures to DNS records. The resolver can verify that the answer came from the legitimate authoritative server and was not tampered with.

```
DNSSEC chain of trust:
  Root (.) signs .com
  .com signs example.com
  example.com signs www.example.com record

Without DNSSEC: anyone who controls the network path can lie about DNS
With DNSSEC: forged records are rejected (wrong signature)

Check if a domain is DNSSEC-signed:
dig +dnssec www.cloudflare.com AAAA    # Look for AD flag (Authenticated Data)
dig DS cloudflare.com @8.8.8.8        # Check delegation signer record

Check DNSSEC validation at resolver:
dig +short sigchase www.cloudflare.com  # Full DNSSEC chain validation
```

**DoH and DoT — Encrypted DNS:**

```
DNS over HTTPS (DoH, RFC 8484):
  DNS queries sent as HTTPS requests to a DoH resolver
  Port 443 — indistinguishable from web traffic
  Prevents ISP/network-level DNS monitoring
  Prevents DNS hijacking by intermediate devices
  
  Disadvantage for defenders: traditional DNS monitoring is blind to DoH
  
DNS over TLS (DoT, RFC 7858):
  DNS queries encrypted with TLS
  Port 853 — distinct port, can be blocked if needed
  Easier for enterprises to manage than DoH

Configure DoH on Linux (systemd-resolved):
  sudo nano /etc/systemd/resolved.conf
  # Add:
  DNS=1.1.1.1 8.8.8.8
  DNSOverTLS=yes
  sudo systemctl restart systemd-resolved
```

### 12.4 DNS Attack Techniques

**DNS Cache Poisoning:**

```
Attack (Kaminsky Attack, 2008, Dan Kaminsky):
  Before the fix: DNS used sequential transaction IDs (16-bit)
  
  1. Attacker triggers resolver to query attacker-controlled domain
     (Forces a DNS query to flow through the process)
  2. Attacker floods resolver with forged responses:
     Claiming to be the authoritative server for "google.com"
     Each forged response has a different transaction ID
     When the attacker guesses the right ID, the poison is injected
  3. Resolver caches the fake record for TTL seconds
  4. All clients using that resolver get the fake IP for "google.com"

Fix: DNS source port randomisation + DNSSEC validation
     Resolver now uses random source port AND random transaction ID
     Probability of guessing both: 1/65535 × 1/65535 ≈ negligible

Modern DNS cache poisoning:
  Still occurs via:
  - Compromising the authoritative name server
  - BGP hijacking the IP space of the name server
  - MITM on unencrypted DNS (DoH/DoT mitigate)
  
Detection:
  Periodic DNS consistency checks from multiple vantage points
  Alert on TTL anomalies (poisoned records often have short/wrong TTL)
  DNSSEC validation rejects poisoned responses
```

**DNS Tunnelling:**

```
Concept: Encode arbitrary data in DNS queries and responses
         DNS is allowed through most firewalls
         Data exfiltration and C2 that bypasses network controls

Mechanism:
  Exfiltration direction (client → attacker):
    Encode data as subdomains: base64(data).attacker-domain.com
    Send DNS query for this "domain"
    Attacker controls the DNS server for attacker-domain.com
    DNS server receives the query, decodes the data from the subdomain
    Returns a valid (but irrelevant) DNS response
    
  Command direction (attacker → client):
    Attacker encodes commands in DNS responses (TXT records, CNAME, MX)
    Malware queries for specific subdomains and reads the response

Tools:
  iodine: Tunnels IP over DNS
  dnscat2: DNS-based C2 framework
  DNSExfiltrator: Data exfiltration via DNS
  Cobalt Strike: DNS C2 mode (commonly used by APT groups)

Detection:
  High DNS query volume from a single host (baseline: ~100 queries/minute normal)
  DNS queries with unusually long subdomains (>50 characters is suspicious)
  DNS queries to domains with high entropy subdomain labels
  DNS queries that don't correspond to network activity (no subsequent TCP connections)
  Queries for domains with randomised names (DGA — domain generation algorithm)
  
  # Detect long DNS queries in Wireshark:
  # Filter: dns and frame.len > 200
  
  # Command-line detection:
  sudo tcpdump -i eth0 -n 'port 53' -A | grep -E '\.[A-Za-z0-9+/]{20,}\.'
  
  # Passive DNS monitoring with zeek:
  # dns.log shows all DNS activity with full query names
```

**Subdomain Takeover:**

```
How it happens:
  1. Company creates CNAME: blog.company.com → company.github.io
  2. Company stops using GitHub Pages but forgets to remove the CNAME
  3. company.github.io is now "dangling" — no content claimed on GitHub
  4. Attacker creates GitHub Pages account for company.github.io
  5. Attacker now controls what blog.company.com serves
  6. Can serve phishing pages, malware, steal cookies (same origin as company.com)

High-profile impact: Subdomain takeover has been used to steal session cookies
from users visiting company subdomains, send phishing emails from legitimate
company domains, and bypass CSP policies.

Detection and prevention:
  Enumerate all DNS records and verify each CNAME target exists and is owned
  
  # Tools: subjack, tko-subs, can-i-take-over-xyz (GitHub)
  subjack -w subdomains.txt -t 100 -o results.txt -ssl
  
  # Manual check:
  dig CNAME blog.company.com +short           # Find CNAME target
  curl -I https://company.github.io           # Verify target exists
  # If 404 or "page not found" → potentially takeable
```

```bash
# DNS reconnaissance toolkit:

# Basic lookups:
dig example.com A                   # A record (IPv4)
dig example.com AAAA                # AAAA record (IPv6)
dig example.com MX                  # Mail exchange
dig example.com TXT                 # Text records (SPF, DKIM, DMARC, etc.)
dig example.com NS                  # Name servers
dig example.com SOA                 # Start of Authority
dig -x 8.8.8.8                     # Reverse lookup (PTR record)

# Using specific DNS server:
dig @8.8.8.8 example.com A          # Use Google DNS
dig @1.1.1.1 example.com A          # Use Cloudflare DNS

# Zone transfer attempt (often blocked, but reveals misconfigured DNS):
dig axfr @ns1.example.com example.com
# If successful: dumps entire DNS zone (all records)
# This is a critical misconfiguration — exposes all internal hostnames

# Subdomain enumeration:
# Passive (no direct queries to target):
subfinder -d example.com -o subdomains.txt    # Uses passive sources
amass enum -passive -d example.com

# Active (queries target DNS):
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Brute force DNS with massDNS:
massdns -r resolvers.txt -t A -o S -w results.txt subdomains.txt

# Check for DNSSEC:
dig +dnssec example.com A

# Check SPF/DKIM/DMARC (email security):
dig TXT example.com | grep "v=spf"
dig TXT _dmarc.example.com
dig TXT default._domainkey.example.com

# Host discovery via reverse DNS (PTR records):
for i in $(seq 1 254); do
    host 192.168.1.$i 2>/dev/null | grep "domain name pointer" | awk '{print $NF}'
done
```

---

## 13. DNS Record Types — The Full Map

### 13.1 Essential DNS Record Types

```
Record  Type    Description                          Security Relevance
──────────────────────────────────────────────────────────────────────────────
A       1       IPv4 address for a hostname          Primary attack target — poison this
                example.com → 93.184.216.34          = redirect all traffic
                
AAAA    28      IPv6 address for a hostname          Same as A but for IPv6
                example.com → 2606:2800:220:1:...    Often less monitored

MX      15      Mail server(s) for a domain          Target for: email spoofing,
                Priority + hostname                  finding mail servers to attack
                10 mail.example.com                 SPF/DKIM/DMARC use MX for context
                
CNAME   5       Canonical name (alias)               Dangling CNAME = subdomain takeover
                www.example.com → example.com        Multiple subdomains → single target
                                                    CDN configuration
                
TXT     16      Arbitrary text                       SPF: v=spf1 include:... -all
                                                    DKIM: public key for email signing
                                                    DMARC: v=DMARC1; p=reject; ...
                                                    Domain verification tokens
                                                    Can contain sensitive info (leak)
                
NS      2       Authoritative name servers           Compromise NS → own entire domain
                example.com NS ns1.example.com       BGP hijack NS IP → poison all records
                
PTR     12      Reverse DNS (IP → name)             Forensics: identify IPs in logs
                34.216.184.93.in-addr.arpa →        Email: servers without PTR rejected
                example.com                         Recon: find hostnames for IPs
                
SOA     6       Start of Authority                   Zone transfer: need SOA to start AXFR
                Primary NS, admin email, serials     Serial number reveals update frequency
                
SRV     33      Service location                     Active Directory critical:
                _kerberos._tcp.domain.com →          SRV records reveal DC location,
                priority weight port target          Kerberos port, LDAP servers
                                                    Used by attackers to find DCs without
                                                    scanning
                                                    
CAA     257     Certification Authority Auth.        Restricts which CAs can issue certs
                example.com CAA "letsencrypt.org"    If missing: any CA can issue = risk
                
DNSKEY  48      DNSSEC public key                   Used to verify DNSSEC signatures
DS      43      Delegation Signer                   Links parent/child DNSSEC zones
RRSIG   46      Resource Record Signature           Cryptographic signature on records
NSEC    47      Next Secure (DNSSEC)                Zone walking: enumerate all records
NSEC3   50      Next Secure v3 (hashed)             Prevents zone walking
                
TLSA    52      TLS Authentication (DANE)            Certificate pinning via DNS
                Associate cert with domain           Requires DNSSEC
                
SPF     (TXT)   Sender Policy Framework             Which IPs may send email for domain
                v=spf1 ip4:1.2.3.0/24 -all         Missing SPF = email spoofing possible

DKIM    (TXT)   DomainKeys Identified Mail          Public key for email signature verification
                Public key for signature verify     Missing DKIM = email modification undetected

DMARC   (TXT)   Domain-based Message Auth.          Policy for SPF/DKIM failure
                v=DMARC1; p=reject                 p=none: monitor only
                rua=mailto:dmarc@example.com        p=quarantine: mark as spam
                                                   p=reject: reject → prevents phishing
```

### 13.2 Active Directory and DNS

Active Directory depends critically on DNS SRV records. When a Windows machine joins a domain, it queries DNS for SRV records to find domain controllers:

```bash
# These DNS queries reveal AD infrastructure:
dig _ldap._tcp.dc._msdcs.example.com SRV     # Find domain controllers (LDAP)
dig _kerberos._tcp.dc._msdcs.example.com SRV  # Find KDC (Kerberos)
dig _kpasswd._tcp.example.com SRV              # Find Kerberos password server
dig _gc._tcp.example.com SRV                  # Find Global Catalog server

# Example response:
# _ldap._tcp.dc._msdcs.example.com  600 IN SRV 0 100 389 dc1.example.com

# This tells an attacker: DC is at dc1.example.com on port 389
# No scanning required — DNS reveals the architecture

# Enumerate AD DNS from inside:
python3 -c "
import dns.resolver
domain = 'example.com'
for srvtype in ['_ldap._tcp.dc._msdcs', '_kerberos._tcp.dc._msdcs', '_gc._tcp']:
    try:
        answers = dns.resolver.resolve(f'{srvtype}.{domain}', 'SRV')
        for rdata in answers:
            print(f'{srvtype}: {rdata}')
    except: pass
"
```

### 13.3 Email Security DNS Records In Depth

Email spoofing — sending emails that appear to come from a legitimate domain — is trivially easy without proper DNS configuration.

**SPF — Sender Policy Framework:**

```
TXT record at the apex domain:
  v=spf1 ip4:203.0.113.0/24 include:sendgrid.net include:mailchimp.com ~all

Mechanisms:
  ip4:IP/mask    → Allow if source IP matches
  ip6:IP/mask    → Allow if source IPv6 matches
  a:hostname     → Allow if source IP is A record of hostname
  mx             → Allow if source IP is MX record of domain
  include:domain → Check that domain's SPF record too
  redirect:domain → Use another domain's SPF record entirely

Qualifiers (before mechanism):
  +  (Pass — allow): default, usually omitted
  -  (Fail — reject): hard fail
  ~  (SoftFail — mark): soft fail, usually accept but mark as suspicious
  ?  (Neutral): no assertion

All mechanism (at end):
  -all  → Hard fail all non-matching senders (recommended)
  ~all  → Soft fail all non-matching (less strict)
  +all  → Pass all (completely useless — anyone can send)
  ?all  → Neutral (nearly useless)

Security check:
dig TXT example.com | grep "v=spf1"
# No SPF record: anyone can spoof email from this domain
# SPF with +all or ?all: SPF is essentially disabled
# SPF with ~all: better, but still allows delivery
# SPF with -all: strongest protection
```

**DKIM — DomainKeys Identified Mail:**

```
TXT record at: selector._domainkey.domain.com
Example: default._domainkey.example.com

Content:
  v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...

How it works:
  1. Mail server signs outgoing email with private key
  2. Signature is added as a header: DKIM-Signature: v=1; a=rsa-sha256; ...
  3. Receiving server fetches public key from DNS
  4. Receiving server verifies signature
  5. If valid: email was not modified in transit, came from claimed domain
  
Attack without DKIM:
  Attacker intercepts email in transit
  Modifies content (changes bank account number, inserts malware link)
  No detection possible — email arrives with original From: header
  
Check DKIM:
dig TXT default._domainkey.example.com
# p= field is the public key
# If empty record or no record: DKIM not deployed
```

**DMARC — Domain-based Message Authentication:**

```
TXT record at: _dmarc.domain.com
Example: _dmarc.example.com  IN TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensics@example.com; sp=reject; adkim=s; aspf=s; pct=100"

Tags:
  p=none       Monitor only — don't reject. Use during initial deployment.
  p=quarantine Send to spam if SPF/DKIM fail. Intermediate step.
  p=reject     Reject if SPF/DKIM fail. Maximum protection.
  
  rua= Aggregate reports URI (where to send daily summaries)
  ruf= Forensic reports URI (where to send per-failure reports)
  
  sp=  Policy for subdomains (same values as p=)
  pct= Percentage of mail to apply policy to (100 = all)
  
  adkim= DKIM alignment: r=relaxed, s=strict
  aspf=  SPF alignment: r=relaxed, s=strict

DMARC without DKIM/SPF: useless
DMARC with p=none: monitoring only, no protection
DMARC with p=reject: strongest — phishing using your domain fails at delivery

Check DMARC:
dig TXT _dmarc.example.com
# No record: DMARC not deployed — spoofing possible even with SPF
# p=none: monitoring only
# p=reject: strong protection
```

```bash
# Complete email security DNS audit:
DOMAIN="example.com"

echo "=== SPF ==="
dig TXT $DOMAIN | grep "v=spf1" || echo "NO SPF RECORD"

echo "=== DMARC ==="
dig TXT _dmarc.$DOMAIN | grep "v=DMARC1" || echo "NO DMARC RECORD"

echo "=== DKIM (common selectors) ==="
for selector in default google selector1 selector2 k1 s1 mail; do
    result=$(dig TXT ${selector}._domainkey.$DOMAIN 2>/dev/null | grep "v=DKIM1")
    [ -n "$result" ] && echo "DKIM found: selector=${selector}"
done

echo "=== MX records ==="
dig MX $DOMAIN +short

echo "=== CAA records ==="
dig CAA $DOMAIN +short || echo "NO CAA RECORD — any CA can issue certificates"
```

---

## 14. IP Addressing in OT/ICS Environments

### 14.1 Addressing Challenges Unique to OT

Industrial control systems present IP addressing challenges that do not exist in enterprise IT:

**Static vs Dynamic Addressing:**
Most OT devices use static IP addresses — DHCP is rarely used for PLCs, RTUs, and IEDs. The reasons are operational:
- A PLC must be reachable at a known, fixed address for the HMI to communicate with it
- DHCP lease renewal could theoretically interrupt communication at a critical moment
- Legacy devices may not support DHCP

Static addressing in OT means:
- IP addresses are documented (if you're lucky) or undocumented (common)
- Asset inventory is manual and often out of date
- Scanning the network for asset discovery causes operational concerns

**Flat vs Segmented OT Networks:**
Many industrial networks were designed without subnetting. Everything on one flat /24 or even /16. This is operationally simple but security catastrophic:
- No segmentation between HMI, PLC, historian, engineering workstation
- ARP poisoning reaches all devices
- Compromised engineering workstation can reach all PLCs directly

**The IT-OT Boundary:**
The connection between corporate IT and OT networks is one of the most dangerous misconfiguration points. Common issues:
- Router directly connecting IT /24 to OT /24 with no firewall
- VLAN separation without firewall — same L3 router handles both
- "Air-gapped" networks with unexpected connections (maintenance laptops, remote access for vendors)

```bash
# OT network IP discovery (non-disruptive methods):
# Passive discovery — listen only, no active scanning
sudo tcpdump -i eth0 -n -q 2>/dev/null | awk '{print $3}' | sort -u
# Captures source IPs from traffic — non-disruptive

# Passive ARP monitoring:
sudo arp-scan --localnet 2>/dev/null | grep -v "^Starting\|^Interface\|packets"
# ARP scan is L2 — does not touch PLCs/RTUs (they ignore ARP they don't need to answer)

# Active scanning RISK in OT:
# Nmap to a PLC can:
#   - Crash the PLC (some cannot handle SYN flood at scan speed)
#   - Trigger watchdog reset
#   - Fill the PLC's connection table
#   - Generate alarms in the control system
# ALWAYS get explicit permission from the system owner
# ALWAYS use very low scan rates: nmap -T0 -sn (ping only, paranoid timing)
# ALWAYS test on a non-production system first
# NEVER use -sS, -sV, -A on OT devices without explicit testing

# Safe active discovery for OT:
sudo nmap -T1 -sn 10.20.0.0/24     # Ping only, slow timing
# Even this should be approved — some OT devices respond unexpectedly to ICMP
```

### 14.2 DHCP in OT Environments

While PLCs and field devices use static IPs, other OT components may use DHCP:
- Engineering workstations (EWS)
- Human-Machine Interfaces (HMI) — some
- Laptops used for maintenance
- IP cameras and physical security devices
- Network switches (management interface)

A rogue DHCP server in the OT network can poison the gateway for any DHCP-configured device. If the engineering workstation's gateway is poisoned, the attacker sees all communication between the EWS and the PLCs — including ladder logic uploads, configuration changes, and diagnostic data.

### 14.3 DNS in OT Environments

Most OT field devices (PLCs, RTUs) do not use DNS — they communicate by IP address directly, configured statically. However:

- **HMI and SCADA servers** often use DNS to resolve historian server names, license servers, update servers
- **Engineering workstations** use DNS for everything a standard Windows machine uses DNS for
- **Some modern PLCs** (Siemens S7-1500, Allen-Bradley CompactLogix) support DNS for tag name resolution

**DNS for OT attack reconnaissance:**
Internal OT hostnames often follow naming conventions that reveal the network structure:
```
plc-production-1.ot.company.local
hmi-controlroom.ot.company.local
historian-01.ot.company.local
ews-engineer-1.ot.company.local
```

If an attacker gains access to a DNS server or captures DNS traffic, these hostnames reveal the OT architecture without any active scanning.

---

## 15. Hands-On Exercises

### Exercise 1: Binary and Subnetting Mastery (45 minutes)

```bash
# Build a subnetting calculator from scratch in Python:
cat > /tmp/subnet_calc.py << 'EOF'
#!/usr/bin/env python3
"""
Manual subnetting calculator — build intuition by doing it step by step
"""

def decimal_to_binary(n):
    """Convert decimal to 8-bit binary string."""
    return format(n, '08b')

def ip_to_binary(ip):
    """Convert IP string to binary string."""
    octets = [int(o) for o in ip.split('.')]
    return '.'.join(decimal_to_binary(o) for o in octets)

def binary_to_ip(binary):
    """Convert 32-bit binary string to IP."""
    # Remove dots if present
    clean = binary.replace('.', '')
    octets = [int(clean[i:i+8], 2) for i in range(0, 32, 8)]
    return '.'.join(str(o) for o in octets)

def prefix_to_mask(prefix):
    """Convert prefix length to subnet mask."""
    mask_binary = '1' * prefix + '0' * (32 - prefix)
    return binary_to_ip(mask_binary)

def subnet_info(ip, prefix):
    """Calculate all subnet information."""
    print(f"\n{'='*50}")
    print(f"Input: {ip}/{prefix}")
    print(f"{'='*50}")
    
    # Convert to binary
    ip_bin = ip_to_binary(ip).replace('.', '')
    mask = prefix_to_mask(prefix)
    mask_bin = ip_to_binary(mask).replace('.', '')
    
    # Network address (AND)
    net_bin = ''.join('1' if ib == '1' and mb == '1' else '0'
                      for ib, mb in zip(ip_bin, mask_bin))
    
    # Broadcast (OR with inverted mask)
    wildcard_bin = ''.join('0' if b == '1' else '1' for b in mask_bin)
    bcast_bin = ''.join('1' if nb == '1' or wb == '1' else '0'
                        for nb, wb in zip(net_bin, wildcard_bin))
    
    network = binary_to_ip(net_bin)
    broadcast = binary_to_ip(bcast_bin)
    mask_str = mask
    wildcard = binary_to_ip(wildcard_bin)
    
    # Host count
    host_bits = 32 - prefix
    total = 2 ** host_bits
    usable = max(0, total - 2)
    
    # First and last host
    first_bin = net_bin[:-1] + '1' if prefix < 32 else net_bin
    last_bin = bcast_bin[:-1] + '0' if prefix < 32 else bcast_bin
    first_host = binary_to_ip(first_bin)
    last_host = binary_to_ip(last_bin)
    
    print(f"\nBinary representations:")
    print(f"  IP:       {ip_to_binary(ip)}")
    print(f"  Mask:     {ip_to_binary(mask)}")
    print(f"  Network:  {ip_to_binary(network)}")
    print(f"  Broadcast:{ip_to_binary(broadcast)}")
    
    print(f"\nDecimal values:")
    print(f"  Network address:   {network}")
    print(f"  Subnet mask:       {mask_str}")
    print(f"  Wildcard mask:     {wildcard}")
    print(f"  Broadcast address: {broadcast}")
    print(f"  First host:        {first_host}")
    print(f"  Last host:         {last_host}")
    print(f"  Usable hosts:      {usable}")

# Test cases:
subnet_info("192.168.1.100", 24)
subnet_info("10.0.0.1", 8)
subnet_info("172.16.5.200", 20)
subnet_info("192.168.10.130", 25)
EOF
python3 /tmp/subnet_calc.py
```

### Exercise 2: DNS Reconnaissance (45 minutes)

```bash
# Complete DNS reconnaissance of a target domain
TARGET="cloudflare.com"   # Use a public domain — always legal to query public DNS

echo "=== Basic Records ==="
dig A $TARGET +short          # IPv4
dig AAAA $TARGET +short       # IPv6
dig MX $TARGET +short         # Mail servers
dig NS $TARGET +short         # Name servers
dig SOA $TARGET +short        # SOA

echo "=== Email Security ==="
dig TXT $TARGET | grep -E "v=spf1|v=DKIM1"
dig TXT _dmarc.$TARGET +short

echo "=== Zone Transfer Attempt ==="
NS=$(dig NS $TARGET +short | head -1)
dig axfr @$NS $TARGET 2>&1 | head -5
# Should fail with "Transfer failed" — success would be a misconfiguration

echo "=== Subdomain Enumeration (passive) ==="
# Using certificate transparency logs (no active scanning):
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
names = set()
for cert in data:
    for name in cert.get('name_value', '').split('\n'):
        if name.endswith('.$TARGET'.replace('cloudflare.com', '')):
            names.add(name.strip())
for name in sorted(names)[:20]:
    print(name)
" 2>/dev/null || echo "crt.sh query failed"

echo "=== DNSSEC Check ==="
dig +dnssec A $TARGET | grep -E "RRSIG|AD flag" || echo "DNSSEC info check"

echo "=== Reverse DNS on Found IPs ==="
for ip in $(dig A $TARGET +short); do
    ptr=$(dig -x $ip +short 2>/dev/null)
    echo "$ip → $ptr"
done
```

### Exercise 3: DHCP Analysis (30 minutes)

```bash
# Capture and analyse DHCP traffic

# Start DHCP capture:
sudo tcpdump -i eth0 -n -v 'port 67 or port 68' &
TCPDUMP_PID=$!

# Trigger DHCP renewal:
sudo dhclient -v -r eth0 2>&1          # Release
sleep 1
sudo dhclient -v eth0 2>&1            # Renew

sleep 5
kill $TCPDUMP_PID 2>/dev/null

# Questions to answer from the capture:
echo "=== DHCP Analysis Questions ==="
echo "1. What is the DHCP server IP?"
echo "2. What IP was offered to you?"
echo "3. What is the default gateway option?"
echo "4. What DNS servers were provided?"
echo "5. What is the lease time in seconds? In hours?"
echo "6. What is the subnet mask?"
echo "7. What Transaction ID was used? (Shows request-response matching)"

# Check current DHCP lease:
cat /var/lib/dhclient/dhclient.leases 2>/dev/null || \
cat /var/lib/NetworkManager/dhclient-*.conf 2>/dev/null || \
nmcli device show eth0 2>/dev/null | grep DHCP
```

### Exercise 4: NAT and IP Masquerading (30 minutes)

```bash
# Configure Linux as a NAT router between two interfaces
# (Requires two network interfaces — suitable for VM lab)

# Identify interfaces:
ip link show

# Enable IP forwarding:
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Configure NAT (masquerade):
# Assume: eth0 is WAN (internet side), eth1 is LAN (internal)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# Verify NAT table:
sudo iptables -t nat -L -n -v

# Test from a client on eth1 side:
# Client should be able to reach internet through this machine

# Enable NAT logging (critical for forensics):
sudo iptables -t nat -A POSTROUTING -o eth0 -j LOG --log-prefix "NAT: " --log-level 6
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# View NAT log:
sudo dmesg | grep "NAT:"
# Or: journalctl -k | grep "NAT:"

# View current NAT connections:
sudo conntrack -L 2>/dev/null    # Requires conntrack package
# Shows all active NAT translations in real time
```

### Exercise 5: Complete Network Audit Script

```bash
# Build a network audit script that combines all concepts from this module

cat > /tmp/network_audit.sh << 'EOF'
#!/bin/bash
# Network Security Audit — Stage 1.4 Exercise
# Collects network configuration and highlights security concerns

echo "===== NETWORK SECURITY AUDIT ====="
echo "Timestamp: $(date)"
echo ""

echo "--- Interfaces and Addresses ---"
ip addr show | grep -E "^[0-9]|inet "
echo ""

echo "--- Routing Table ---"
ip route show
echo ""

echo "--- Default Gateway ---"
ip route | grep default
echo ""

echo "--- ARP Cache (recently seen hosts) ---"
ip neigh show
echo ""

echo "--- DNS Configuration ---"
cat /etc/resolv.conf
echo ""

echo "--- Active Connections ---"
ss -tulnp | head -20
echo ""

echo "--- DHCP Lease ---"
cat /var/lib/dhclient/dhclient.leases 2>/dev/null | grep -E "lease|fixed-address|routers|domain-name-servers" | head -10
echo ""

echo "--- Security Checks ---"

# Check for RFC1918 addresses:
echo "RFC1918 interfaces:"
ip addr | grep -oE '(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]+\.[0-9]+/[0-9]+'

# Check IP forwarding:
fwd=$(cat /proc/sys/net/ipv4/ip_forward)
[ "$fwd" = "1" ] && echo "[!] IP FORWARDING ENABLED — is this machine a router?" || echo "[OK] IP forwarding disabled"

# Check ICMP redirect acceptance:
redir=$(cat /proc/sys/net/ipv4/conf/all/accept_redirects)
[ "$redir" = "1" ] && echo "[!] ICMP REDIRECTS ACCEPTED — potential route hijack risk" || echo "[OK] ICMP redirects disabled"

# Check for unusual listening services:
echo ""
echo "Listening on all interfaces (0.0.0.0 or :::):"
ss -tlnp | grep -E "0\.0\.0\.0|:::"

echo ""
echo "===== AUDIT COMPLETE ====="
EOF
chmod +x /tmp/network_audit.sh
bash /tmp/network_audit.sh
```

---

## 16. Module Summary

| Concept | Core Mechanism | Attack Relevance | Defence |
|---------|---------------|-----------------|---------|
| **IPv4 Binary** | 32-bit number in dotted-decimal | Foundation of all addressing calculations | Must understand for subnet design and firewall rules |
| **Address Classes** | Historical classful boundaries | Legacy OT devices may use class defaults | Know class defaults to diagnose legacy device issues |
| **Public vs Private** | RFC 1918 ranges never routed publicly | IP spoofing detection, cloud metadata SSRF | BCP38 filtering, restrict metadata service access |
| **Cloud Metadata** | 169.254.169.254 serves cloud credentials | SSRF → metadata → credential theft (Capital One 2019) | IMDSv2, firewall metadata endpoint, least-privilege IAM |
| **CIDR** | Variable prefix length, replaces classful | Scope definition for scans, subnet calculation | Design minimal subnets, audit CIDR firewall rules |
| **Subnet Mask** | Binary AND determines network vs host | Network boundary calculation, routing decisions | Correct mask prevents unintended reachability |
| **Subnetting** | Dividing address space into segments | Lateral movement: routing tables reveal all subnets | Segmentation reduces blast radius of any compromise |
| **VLSM** | Different prefix lengths per subnet | Efficient segmentation design | Right-size each zone, isolate OT with dedicated subnets |
| **NAT** | IP translation via state table | NAT hides source for forensics, C2 bypasses NAT | Log all NAT translations — required for incident response |
| **PAT** | Port-based multiplexing of many-to-one | Port exhaustion DoS, forensic attribution challenges | Enable NAT logging, track source ports |
| **DHCP** | Automatic IP assignment via DORA | Starvation, rogue server → MITM, Option 121 TunnelVision | DHCP snooping, trusted port designation |
| **DNS Resolution** | Hierarchical recursive lookup | Cache poisoning, DNS tunnelling, C2 via DNS | DNSSEC, DoH/DoT, DNS monitoring |
| **DNS Attacks** | Cache poisoning, tunnelling, takeover | C2 over DNS, data exfiltration, phishing | Query rate monitoring, DNSSEC validation, TTL anomaly detection |
| **A/AAAA records** | Hostname to IP mapping | Cache poisoning target | DNSSEC, monitor for unexpected changes |
| **MX records** | Mail server identification | Target for email infrastructure attacks | Firewall, SPF/DKIM/DMARC |
| **CNAME records** | Alias to another hostname | Subdomain takeover via dangling CNAME | Audit all CNAMEs, remove stale entries |
| **TXT records** | Arbitrary text (SPF, DKIM, DMARC) | Missing SPF/DMARC → email spoofing | p=reject DMARC + SPF -all + DKIM |
| **NS records** | Authoritative nameservers | NS compromise → total DNS control | Secure registrar, DNSSEC, monitor NS changes |
| **PTR records** | Reverse DNS | Reconnaissance, mail rejection without PTR | Maintain PTR records, use for anomaly detection |
| **SRV records** | Service location (AD) | AD enumeration without scanning | Monitor SRV queries for reconnaissance patterns |
| **OT Addressing** | Mostly static, flat networks common | Static IPs predictable, flat = lateral movement | Segmentation with VLSM, passive-only asset discovery |

---

> **Next Module:** [Stage 1.5 — Core Protocols](./stage-1.5-core-protocols.md)  
> **Previous Module:** [Stage 1.3 — TCP/IP Model](./stage-1.3-tcpip-model.md)  
> **Series Index:** [Full Roadmap](../../README.md)

---

*This document is part of the Cybersecurity × OT/ICS Security Full Roadmap series. All techniques are presented for educational purposes, authorised security research, and defensive security practice. Always obtain proper authorisation before testing any system.*