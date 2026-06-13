# Stage 1.8 — Network Analysis Tools
### From Zero to Cybersecurity Professional | Complete Roadmap Series

> **Series:** Cybersecurity × OT/ICS Security — Full Roadmap  
> **Stage:** 1 — Network Fundamentals  
> **Module:** 1.8 — Network Analysis Tools  
> **Level:** Beginner → Advanced  
> **Prerequisites:** Stage 1.7 — Wireless Networks  
> **Next Stage:** Stage 2 — Cybersecurity Core

---

## Table of Contents

1. [Why Network Analysis Tools Define Your Career Ceiling](#1-why-network-analysis-tools-define-your-career-ceiling)
2. [Wireshark — The Packet Analyst's Primary Weapon](#2-wireshark--the-packet-analysts-primary-weapon)
3. [tcpdump — The Command-Line Packet Capture Engine](#3-tcpdump--the-command-line-packet-capture-engine)
4. [Netstat and ss — Connection State Intelligence](#4-netstat-and-ss--connection-state-intelligence)
5. [Nmap — The Network Mapper](#5-nmap--the-network-mapper)
6. [Traceroute and Tracert — Path Discovery](#6-traceroute-and-tracert--path-discovery)
7. [Ping — The Fundamental Connectivity Test](#7-ping--the-fundamental-connectivity-test)
8. [ipconfig and ifconfig — Interface Configuration](#8-ipconfig-and-ifconfig--interface-configuration)
9. [Additional Critical Tools](#9-additional-critical-tools)
10. [Tool Integration — Building Investigation Workflows](#10-tool-integration--building-investigation-workflows)
11. [Network Analysis in OT/ICS Environments](#11-network-analysis-in-otics-environments)
12. [Hands-On Exercises](#12-hands-on-exercises)
13. [Module Summary](#13-module-summary)

---

## 1. Why Network Analysis Tools Define Your Career Ceiling

There is a direct correlation between how deeply you understand these tools and how far you progress in cybersecurity. Every discipline — penetration testing, incident response, threat hunting, SOC analysis, OT security assessment — requires the ability to observe, interrogate, and interpret network behaviour. The tools in this module are not beginner tools you graduate from. They are the tools professionals use every day regardless of seniority.

**Real incidents where these tools were decisive:**

**Stuxnet Discovery (2010):** The Stuxnet worm was partially identified through anomalous network traffic analysis. Kaspersky researchers used packet capture tools to observe unusual communication patterns with Siemens WinCC databases and later identified the C2 protocol embedded in industrial communications. Without deep packet analysis, the world's first known cyber-weapon aimed at physical infrastructure might have remained undiscovered far longer.

**APT1/Comment Crew Exposure (2013):** Mandiant's landmark report exposing Chinese APT1 operations relied heavily on network analysis of captured traffic. Nmap scans revealed attack infrastructure; packet captures documented exfiltration patterns; netstat data from compromised hosts showed persistent connections to C2 infrastructure. The entire forensic reconstruction was built on network analysis data.

**Colonial Pipeline (2021):** The incident response teams deployed after the ransomware attack used network analysis tools to understand the blast radius — which systems had communicated with the initially compromised systems, which had received malicious payloads, what lateral movement paths had been used. Packet capture evidence helped reconstruct the attack timeline.

**For OT/ICS specifically:** When a PLC stops responding or a SCADA system behaves erratically, the first question is always: "What is happening at the network level?" Wireshark captures of Modbus traffic can reveal unauthorised write commands. Nmap scans (conducted carefully) identify rogue devices. Ping reveals whether a field device is reachable. These tools are the diagnostic instruments of industrial network security.

The security mindset for this module: **You cannot defend what you cannot see. You cannot investigate what you cannot measure. These tools are your senses on the network — developing fluency with them is not optional.**

---

## 2. Wireshark — The Packet Analyst's Primary Weapon

### 2.1 What Wireshark Is and How It Works

Wireshark is the world's most widely used network protocol analyser. It captures packets from a network interface, decodes them according to hundreds of protocol dissectors, and presents them in a structured, searchable interface. It can also open packet capture files in pcap, pcapng, and dozens of other formats.

**How Wireshark captures packets:**

```
Normal NIC Operation:
  Network traffic → NIC → [NIC accepts only MY packets] → OS → Applications

Promiscuous Mode:
  Network traffic → NIC → [NIC accepts ALL packets on segment] → OS → Wireshark
  
Monitor Mode (wireless):
  All wireless frames → Wireless NIC → [ALL frames regardless of encryption] → Wireshark
  (Monitor mode captures encrypted frames but cannot decrypt without key)
  
Capture Pipeline:
  Physical medium → NIC driver → WinPcap/Npcap (Windows) or libpcap (Linux/macOS)
  → Capture engine → Packet buffer → Dissectors → Display engine
  
Packet dissection:
  Raw bytes → Layer 2 decoder (Ethernet, 802.11, etc.)
             → Layer 3 decoder (IPv4, IPv6, ARP, etc.)
             → Layer 4 decoder (TCP, UDP, ICMP, etc.)
             → Layer 7 decoder (HTTP, DNS, SMB, Modbus, DNP3, etc.)
  Each layer reveals its fields → displayed in protocol tree
```

### 2.2 Wireshark Interface Deep Dive

```
Wireshark Main Window Layout:

┌─────────────────────────────────────────────────────────────┐
│ Filter Bar: [    Display Filter Expression           ] [Apply]│
├─────────────────────────────────────────────────────────────┤
│ Packet List (one row per packet):                           │
│ No.  Time      Source          Dest          Protocol  Info │
│ 1    0.000000  192.168.1.5    8.8.8.8       DNS       Who  │
│ 2    0.012345  8.8.8.8        192.168.1.5   DNS       Resp │
│ 3    0.013000  192.168.1.5    93.184.216.34 TCP       SYN  │
├─────────────────────────────────────────────────────────────┤
│ Packet Details (protocol tree for selected packet):         │
│ ▼ Frame 1: 74 bytes on wire                                 │
│   ▼ Ethernet II: Src: AA:BB:CC:DD:EE:FF, Dst: 11:22:33... │
│     Destination: 11:22:33:44:55:66                         │
│     Source: AA:BB:CC:DD:EE:FF                               │
│     Type: IPv4 (0x0800)                                     │
│   ▼ IPv4: Src 192.168.1.5, Dst 8.8.8.8                    │
│     Version: 4                                              │
│     ...                                                     │
│   ▼ UDP: Src Port 54321, Dst Port 53                       │
│   ▼ DNS: Standard Query                                     │
├─────────────────────────────────────────────────────────────┤
│ Packet Bytes (hex + ASCII):                                 │
│ 0000  11 22 33 44 55 66 aa bb  cc dd ee ff 08 00 45 00  │
│ 0010  ...                                                   │
└─────────────────────────────────────────────────────────────┘
```

### 2.3 Display Filters — The Core Skill

Display filters are the most important Wireshark skill. They do not remove packets from the capture — they show or hide packets while the underlying capture remains complete.

```
Filter Syntax: field operator value (logical operators: and, or, not)

Basic Filters:
  ip.addr == 192.168.1.1          All traffic involving this IP (src or dst)
  ip.src == 192.168.1.5           Traffic FROM this IP
  ip.dst == 8.8.8.8               Traffic TO this IP
  tcp.port == 443                 TCP on port 443 (either direction)
  tcp.dstport == 80               TCP destined for port 80
  udp.port == 53                  UDP port 53 (DNS)
  
Protocol Filters:
  tcp                             All TCP traffic
  udp                             All UDP traffic
  icmp                            All ICMP traffic
  arp                             All ARP traffic
  dns                             All DNS traffic
  http                            All HTTP traffic (decoded)
  tls                             All TLS/SSL traffic
  smb                             All SMB traffic
  smb2                            All SMB2 traffic
  ftp                             All FTP control traffic
  ssh                             All SSH traffic
  modbus                          All Modbus traffic (ICS)
  dnp3                            All DNP3 traffic (ICS)
  
TCP Flags:
  tcp.flags.syn == 1              SYN packets (new connections)
  tcp.flags.syn == 1 and tcp.flags.ack == 0   SYN only (not SYN-ACK)
  tcp.flags.reset == 1            RST packets (connection resets)
  tcp.flags.fin == 1              FIN packets (connection close)
  
Content Filters:
  http.request.method == "POST"   HTTP POST requests
  http.response.code == 200       HTTP 200 OK responses
  http.response.code >= 400       HTTP errors
  dns.qry.name contains "evil"    DNS queries containing "evil"
  frame contains "password"       Any frame containing the string "password"
  data contains 50:41:53:53       Frames containing hex bytes (PASS)
  
Combining Filters:
  ip.src == 192.168.1.5 and tcp.dstport == 80
  not arp and not icmp            Exclude ARP and ICMP (reduce noise)
  ip.addr == 10.10.10.0/24        Any IP in this subnet
  tcp.port in {80 443 8080 8443}  Traffic on any of these ports
  
Comparison Operators:
  ==  equal to
  !=  not equal to
  >   greater than
  <   less than
  >=  greater than or equal
  <=  less than or equal
  contains  string/bytes contained within
  matches   regex match (~~)
  
Security-Specific Filters:
  # Find potential SQL injection in HTTP:
  http.request.uri contains "'"
  http.request.uri contains "UNION"
  http.request.uri contains "SELECT"
  
  # Find potential XSS:
  http.request contains "<script"
  
  # Detect password transmission in cleartext:
  ftp.request.command == "PASS"
  pop.request.command == "PASS"
  imap contains "LOGIN"
  
  # Detect ARP spoofing (duplicate IP):
  arp.duplicate-address-detected
  
  # Find Nmap SYN scans:
  tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size <= 1024
  
  # Detect Metasploit Meterpreter (default SSL cert):
  tls.handshake.type == 11        # Certificate in TLS
  # Then check certificate details for known Metasploit cert
  
  # Modbus write commands (ICS):
  modbus.func_code == 5           # Force Single Coil
  modbus.func_code == 6           # Preset Single Register
  modbus.func_code == 15          # Force Multiple Coils
  modbus.func_code == 16          # Preset Multiple Registers
```

### 2.4 Statistics and Analysis Features

```bash
# Statistics menu — essential for pattern analysis:

# Protocol Hierarchy:
# Statistics → Protocol Hierarchy
# Shows: percentage of traffic per protocol
# Security use: unexpected protocols (Tor, unusual ports) stand out

# Conversations:
# Statistics → Conversations → TCP/UDP/IP
# Shows: top talkers, bytes transferred per connection
# Security use: identify exfiltration (large outbound transfers)
# Security use: lateral movement (many connections from one source)

# Endpoints:
# Statistics → Endpoints
# Shows: all unique IP/MAC addresses in capture
# Security use: discover new/unexpected hosts on network

# IO Graphs:
# Statistics → I/O Graph
# Shows: traffic volume over time
# Security use: identify spikes (DDoS, exfiltration, scanning)

# Follow TCP Stream:
# Right-click packet → Follow → TCP Stream
# Shows entire TCP conversation as text
# Security use: see complete HTTP request/response, FTP session, etc.
# Most useful command in Wireshark for protocol analysis

# Export Objects:
# File → Export Objects → HTTP/SMB/FTP/TFTP
# Extracts transferred files from the capture
# Security use: extract malware downloaded via HTTP
# Security use: extract sensitive files exfiltrated via SMB

# Expert Information:
# Analyze → Expert Information
# Shows: errors, warnings, protocol anomalies
# Security use: malformed packets, checksum errors, unusual sequences
```

### 2.5 Capture Filters vs Display Filters

```
Capture Filters (BPF syntax — applied at capture time):
  These are applied BEFORE packets are stored
  Packets not matching are discarded
  Use when: you need to reduce capture size, focus on specific traffic
  Syntax: Berkeley Packet Filter (libpcap/BPF), different from display filters
  
  Examples:
  host 192.168.1.1                 Only traffic to/from this IP
  net 192.168.1.0/24               Only traffic in this subnet
  port 80                          Only traffic on port 80
  tcp                              Only TCP traffic
  not arp                          Exclude ARP
  host 192.168.1.1 and port 80     Combined: specific host AND port
  
Display Filters (Wireshark syntax — applied to existing capture):
  Applied after capture — original data preserved
  Can be changed without re-capturing
  Richer syntax than capture filters
  
The critical difference:
  If you set a capture filter: excluded packets are GONE
  If you set a display filter: excluded packets are hidden but still there
  For forensics: always capture everything, use display filters for analysis
  Capture filter only when: storage/performance constraints
```

### 2.6 TLS Decryption in Wireshark

```bash
# Method 1: Pre-Master Secret Log (modern browsers/TLS):
# Set environment variable before starting browser:
export SSLKEYLOGFILE=/tmp/ssl_keys.log
firefox &                           # Or chromium

# In Wireshark:
# Edit → Preferences → Protocols → TLS
# (Pre)-Master-Secret log filename: /tmp/ssl_keys.log
# Now HTTPS traffic is decrypted in real-time

# Method 2: Server private key (only works for RSA key exchange, not ECDH):
# Edit → Preferences → Protocols → TLS → Edit (RSA keys list)
# Add: IP, Port, Protocol, Key file path
# Import PEM private key of the server
# Note: Does NOT work if server uses forward secrecy (ECDH/DHE) — most modern servers do

# Method 3: Manual session key import:
# If you have the session keys from another source
# Import via the TLS pre-master secret log mechanism

# Security use: decrypt HTTPS in lab environments to understand attack traffic
# Incident response: if you have server private key, decrypt historical captures
# Limitation: most modern servers use forward secrecy — key import won't work
# → Use SSLKEYLOGFILE approach for browser traffic analysis
```

### 2.7 Wireshark for Incident Response

```bash
# Command-line Wireshark (tshark):

# Basic capture:
sudo tshark -i eth0 -w /tmp/capture.pcap         # Capture to file
sudo tshark -i eth0 -c 1000                      # Capture 1000 packets
sudo tshark -i eth0 -a duration:60               # Capture for 60 seconds

# Read from file and apply filter:
tshark -r capture.pcap -Y "http.request.method == POST"

# Extract specific fields:
tshark -r capture.pcap -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.dstport \
    -e http.request.uri \
    -Y "http.request"

# Count DNS queries per domain:
tshark -r capture.pcap -T fields -e dns.qry.name \
    -Y "dns.flags.response == 0" | \
    sort | uniq -c | sort -rn | head -20

# Extract all HTTP usernames and passwords (cleartext):
tshark -r capture.pcap -T fields \
    -e http.authbasic \
    -Y "http.authbasic"

# Find large file transfers (potential exfiltration):
tshark -r capture.pcap -T fields \
    -e ip.src -e ip.dst -e tcp.stream -e tcp.len \
    | awk '{sum[$1" "$2]+=$4} END {for(k in sum) print sum[k], k}' \
    | sort -rn | head -10

# Extract files from HTTP captures:
tshark -r capture.pcap --export-objects http,/tmp/extracted_files/

# Convert pcap to readable JSON for automated analysis:
tshark -r capture.pcap -T json > analysis.json

# Find all unique external IPs (potential C2 or exfiltration):
tshark -r capture.pcap -T fields -e ip.dst \
    | grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)" \
    | sort -u
```

> **Key Insight:** Wireshark's Follow TCP Stream function is the single most powerful investigative capability in the tool. It reconstructs the entire conversation between two endpoints, showing you exactly what was said — credentials, commands, file contents, protocol exchanges. In incident response, following streams to malicious destinations reveals the attacker's exact actions. In OT security, following Modbus streams reveals every command sent to every PLC.

---

## 3. tcpdump — The Command-Line Packet Capture Engine

### 3.1 Why tcpdump Matters

tcpdump is the command-line packet analyser available on virtually every Unix-like system by default. It is the tool you use when:
- There is no GUI (server environments, embedded systems, OT devices)
- You need to capture remotely and analyse locally
- You need scripted, automated packet capture
- Performance constraints prevent running Wireshark
- You are working on a system with no desktop environment

tcpdump uses libpcap (same library as Wireshark) and produces standard pcap files that Wireshark can read.

### 3.2 tcpdump Syntax and Filters

```
tcpdump syntax:
sudo tcpdump [options] [filter expression]

Key Options:
  -i eth0          Interface to capture on (-i any = all interfaces)
  -w file.pcap     Write to pcap file (don't display)
  -r file.pcap     Read from pcap file
  -c 100           Capture only 100 packets then stop
  -n               Don't resolve IP addresses to hostnames (faster, clearer)
  -nn              Don't resolve ports either (show numbers, not service names)
  -v               Verbose (more protocol detail)
  -vv              Very verbose
  -vvv             Maximum verbosity
  -A               Print packet data in ASCII
  -X               Print packet data in hex and ASCII
  -xx              Print with link layer headers in hex
  -s 0             Capture full packet (default is 65535 bytes, -s 0 = unlimited)
  -S               Print absolute sequence numbers (useful for TCP analysis)
  -e               Print link-layer header (MAC addresses)
  -l               Line-buffer output (for piping to grep/awk in real-time)
  -q               Quiet mode (less protocol detail)
  -t               Don't print timestamp
  -tt              Print Unix epoch timestamp (useful for log correlation)
  -ttt             Print delta between packets
  -tttt            Print date and time
  -D               List available interfaces
  -Z user          Drop privileges to user after opening interface
  
Filter Syntax (BPF — Berkeley Packet Filter):
  Primitives: host, net, port, src, dst, proto
  Logical: and (&&), or (||), not (!)
  
  host 192.168.1.1              Traffic to or from this IP
  src host 192.168.1.5          Traffic FROM this IP
  dst host 192.168.1.1          Traffic TO this IP
  net 192.168.1.0/24            Traffic in subnet
  port 80                       Traffic on port 80 (TCP or UDP)
  tcp port 443                  TCP port 443
  udp port 53                   UDP port 53
  portrange 1-1024              Any port in range
  not port 22                   Exclude SSH
  tcp and not port 22           TCP, excluding SSH
  host 192.168.1.1 and port 80  Specific host + port
  
Protocol Primitives:
  ip, ip6, arp, rarp, tcp, udp, icmp, icmp6
  proto 89                       OSPF (IP protocol 89)
  
Advanced BPF (byte offset matching):
  tcp[tcpflags] & tcp-syn != 0    SYN packets
  tcp[tcpflags] & tcp-rst != 0    RST packets
  tcp[tcpflags] == tcp-syn        ONLY SYN (not SYN-ACK)
  ip[8] <= 5                      TTL <= 5 (traceroute-like packets)
  ip[6:2] & 0x3fff != 0          IP fragmented packets
```

### 3.3 Essential tcpdump Commands

```bash
# Basic capture and display:
sudo tcpdump -i eth0                              # Basic capture, all traffic
sudo tcpdump -i eth0 -nn                          # No name resolution
sudo tcpdump -i eth0 -nn -v                       # More detail
sudo tcpdump -i any -nn                           # All interfaces

# Save and read:
sudo tcpdump -i eth0 -w /tmp/capture.pcap         # Save to file
sudo tcpdump -r /tmp/capture.pcap -nn             # Read from file

# Targeted captures:
sudo tcpdump -i eth0 host 192.168.1.100           # Specific host
sudo tcpdump -i eth0 port 80                      # Port 80
sudo tcpdump -i eth0 'tcp port 80 and host 192.168.1.100'

# Show packet content:
sudo tcpdump -i eth0 -A port 80                   # ASCII content
sudo tcpdump -i eth0 -X port 80                   # Hex + ASCII

# Capture only specific number:
sudo tcpdump -i eth0 -c 100 -w /tmp/100pkts.pcap  # Capture 100 packets

# Time-limited capture:
timeout 60 sudo tcpdump -i eth0 -w /tmp/60sec.pcap  # 60 seconds

# Capture and pipe to analysis:
sudo tcpdump -i eth0 -l -A port 80 | grep "GET\|POST\|Host:"
# -l: line buffered (necessary for real-time piping)

# Security-specific captures:
# Capture all new TCP connections (SYN only):
sudo tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0'

# Capture DNS traffic:
sudo tcpdump -i eth0 -nn udp port 53

# Capture ICMP:
sudo tcpdump -i eth0 icmp

# Capture ARP:
sudo tcpdump -i eth0 arp

# Detect SYN flood (high rate of SYN packets):
sudo tcpdump -i eth0 -nn 'tcp[tcpflags] == tcp-syn' | \
    awk '{print $3}' | cut -d. -f1-4 | \
    sort | uniq -c | sort -rn | head

# Capture credentials in cleartext protocols:
sudo tcpdump -i eth0 -A -s0 'port 21 or port 23 or port 110 or port 143' | \
    grep -iE "user|pass|login"

# Large file capture with rotation:
sudo tcpdump -i eth0 -w /tmp/capture-%Y%m%d%H%M%S.pcap \
    -G 3600 \                    # Rotate every 3600 seconds (1 hour)
    -C 100                       # Max 100MB per file

# Remote capture (capture on remote host, analyse locally):
ssh user@remote_host "sudo tcpdump -i eth0 -w - -U host 192.168.1.1" | \
    wireshark -k -i -
# -w -: write to stdout
# -U: flush after each packet (real-time)
# wireshark -k: start capturing immediately
# wireshark -i -: read from stdin
```

### 3.4 tcpdump in Security Contexts

```bash
# Incident Response: capture evidence before it's lost
sudo tcpdump -i eth0 \
    -w /evidence/$(hostname)_$(date +%Y%m%d%H%M%S).pcap \
    -s 0 \                       # Full packets (forensic-grade)
    -tttt \                      # Timestamp with date
    &                            # Background — continue collecting

# SOC: monitor for specific IOCs (Indicators of Compromise)
SUSPICIOUS_IP="185.220.101.5"    # Example known malicious IP
sudo tcpdump -i eth0 -nn -A \
    "host $SUSPICIOUS_IP" | \
    tee /var/log/suspicious_traffic.log

# Detect C2 beaconing (regular interval connections to same IP):
sudo tcpdump -i eth0 -nn -t 'tcp[tcpflags] & tcp-syn != 0' | \
    awk '{print $3}' | cut -d. -f1-4 | \
    uniq -c | \
    awk '$1 > 5 {print "Possible beacon: "$2" ("$1" connections)"}'

# Monitor for data exfiltration (large outbound transfers):
sudo tcpdump -i eth0 -nn 'src net 192.168.0.0/16' | \
    awk '{
        split($3, src, ".")
        split($5, dst, ".")
        # Flag if source is internal, dst is external
        if (src[1] != dst[1]) sum[dst[1]"."dst[2]"."dst[3]"."dst[4]] += length($0)
    }
    END {
        for (ip in sum)
            if (sum[ip] > 1000000) print "Large transfer to "ip": "sum[ip]" bytes"
    }'

# OT: Monitor Modbus commands (port 502):
sudo tcpdump -i eth0 -nn -A port 502 | \
    grep -A5 "502"
# For detailed Modbus analysis: use Wireshark with Modbus dissector
```

> **Key Insight:** tcpdump's strength is its availability and scriptability. On a compromised server during incident response, Wireshark may not be installed — tcpdump almost always is. Knowing how to capture and filter with tcpdump means you can gather evidence from any Unix system regardless of what security tools are installed. The output is standard pcap, readable by Wireshark for deeper analysis later.

---

## 4. Netstat and ss — Connection State Intelligence

### 4.1 Netstat — The Legacy Connection Inspector

netstat displays network connections, routing tables, interface statistics, masquerade connections, and multicast memberships. While being replaced by `ss` on modern Linux, netstat remains ubiquitous (Windows, macOS, older Linux).

```
netstat output columns:
  Proto:     Protocol (tcp, udp, tcp6, udp6)
  Recv-Q:    Data queued to receive (waiting for application to read)
  Send-Q:    Data queued to send (waiting for network)
  Local Address:  Local IP:port of the connection
  Foreign Address: Remote IP:port
  State:     TCP state (LISTEN, ESTABLISHED, TIME_WAIT, etc.)
  PID/Program: Process owning the connection (with -p flag)
```

```bash
# Linux netstat commands:
netstat -tulnp          # TCP+UDP, Listening, Numeric, with Process
# -t: TCP connections
# -u: UDP connections
# -l: Only listening sockets
# -n: Numeric (don't resolve names — faster and clearer)
# -p: Show process name and PID (requires root for other users' processes)

netstat -tan            # All TCP connections, numeric
netstat -anp            # All connections, numeric, with process
netstat -rn             # Routing table, numeric
netstat -i              # Interface statistics
netstat -s              # Statistics by protocol (errors, drops, etc.)
netstat -c 2            # Refresh every 2 seconds (continuous)

# Useful patterns:
netstat -anp | grep LISTEN                        # All listening services
netstat -anp | grep ESTABLISHED                  # Active connections
netstat -anp | grep :4444                        # Metasploit default port
netstat -anp | grep '0.0.0.0:*'                 # Services exposed on all interfaces

# Windows netstat:
netstat -ano             # All connections, numeric, with PID
netstat -ano | findstr :3389   # RDP connections
netstat -ano | findstr LISTENING  # All listening ports
netstat -b               # Show owning executable (requires admin)
netstat -r               # Routing table
```

### 4.2 ss — The Modern Replacement

`ss` (Socket Statistics) is faster than netstat, provides more information, and is the current standard on modern Linux. It reads from the kernel's netlink socket rather than /proc.

```bash
# ss commands:
ss -tulnp               # Same as netstat equivalent
# -t: TCP
# -u: UDP
# -l: Listening
# -n: Numeric
# -p: Process info

ss -tnp state established  # Only established TCP connections
ss -tnp state time-wait    # TIME_WAIT connections (post-close)
ss -tnp state syn-recv     # SYN_RECV (half-open, potential SYN flood indicator)
ss -s                      # Summary statistics
ss -4                      # IPv4 only
ss -6                      # IPv6 only

# Filtering (more powerful than netstat):
ss -tnp dst 192.168.1.100      # Connections TO this IP
ss -tnp src 192.168.1.5        # Connections FROM this IP
ss -tnp dport == :443          # Connections TO port 443
ss -tnp sport == :22           # Connections FROM port 22
ss -tnp 'dst 192.168.1.0/24'  # All connections to subnet

# Advanced ss usage:
ss -tnp | awk 'NR>1 {print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn
# Count connections per remote IP — detect port scan or DDoS source
```

### 4.3 Security Analysis with Netstat/ss

```bash
# ============ INCIDENT RESPONSE CHECKLIST ============
# Run these immediately on a suspected compromised system:

echo "=== LISTENING SERVICES ==="
ss -tulnp 2>/dev/null || netstat -tulnp
# Look for: unexpected listening services, non-standard ports, unusual processes

echo "=== ESTABLISHED CONNECTIONS ==="
ss -tnp state established 2>/dev/null || netstat -tnp | grep ESTABLISHED
# Look for: connections to unexpected external IPs, encrypted channels on unusual ports

echo "=== UNUSUAL PORTS ==="
ss -tnp | grep -vE ":22|:80|:443|:53|:3306|:5432"  # Show non-common ports
# Look for: reverse shells (4444, 5555, common Metasploit ports)
#           C2 channels (any port to external IPs)
#           Pivoting (unexpected internal connections)

echo "=== CONNECTION COUNTS BY REMOTE IP ==="
ss -tn | awk 'NR>1 {split($5,a,":"); print a[1]}' | sort | uniq -c | sort -rn | head -20
# High count from same IP = port scan or C2 beaconing

echo "=== PROCESSES WITH NETWORK ACTIVITY ==="
ss -tnp | grep -oE 'pid=[0-9]+' | sort -u | while read pid; do
    pid_num=${pid#pid=}
    proc=$(cat /proc/$pid_num/cmdline 2>/dev/null | tr '\0' ' ')
    echo "PID $pid_num: $proc"
done
# Match processes to their network activity — unexpected process making connections = suspicious

# ============ DETECT REVERSE SHELLS ============
# Reverse shells often appear as: sh/bash/python/perl connecting outbound
# Look for shell processes with established outbound connections:
ss -tnp state established | grep -E "bash|sh|python|perl|ruby|nc|ncat|netcat"

# Detect bind shells (listening shells):
ss -tlnp | grep -E "bash|sh|python|perl|nc|ncat"

# ============ DETECT PORT SCANNING ============
# Short-lived connections in TIME_WAIT = scanner was here
ss -tn state time-wait | awk '{print $4}' | cut -d: -f1 | sort | uniq -c | sort -rn | head
# Many TIME_WAIT connections from same source = port scanner

# ============ WINDOWS SPECIFIC ============
# Find processes behind suspicious connections (Windows):
netstat -ano | findstr :4444
tasklist /fi "pid eq 1234"         # Replace 1234 with PID from netstat
# Correlate PID to process name
```

**Connection States Reference:**

```
TCP Connection States and Security Meaning:

LISTEN:      Server waiting for connections. Normal for services.
             Unexpected listening ports = potential backdoor

ESTABLISHED: Active data transfer. Normal.
             Unexpected external ESTABLISHED = possible compromise

SYN_SENT:    Client initiated connection, waiting for SYN-ACK
             Many SYN_SENT to different ports = you are port scanning
             Many SYN_SENT to different IPs = lateral movement or malware

SYN_RECV:    SYN received, SYN-ACK sent, waiting for ACK
             Many SYN_RECV = you are being SYN flooded (DDoS)

FIN_WAIT_1:  Sent FIN, waiting for ACK (normal close)
FIN_WAIT_2:  Got ACK, waiting for remote FIN (normal close)
CLOSE_WAIT:  Remote sent FIN, application hasn't closed yet
             Many CLOSE_WAIT = application bug (not closing sockets properly)
             
TIME_WAIT:   Both FINs acknowledged, waiting for stragglers
             Many TIME_WAIT = heavily used server or recent scanning activity
             
CLOSED:      Connection fully terminated (not usually shown)
```

> **Key Insight:** A compromised machine almost always has evidence in its connection table — a reverse shell process with an outbound ESTABLISHED connection, an unexpected LISTENING port for a backdoor, or unusual processes associated with network connections. The netstat/ss output is one of the first things to examine in any suspected compromise. Baseline normal connection state and know what processes should be listening — any deviation is a finding.

---

## 5. Nmap — The Network Mapper

### 5.1 Nmap Architecture and Scan Types

Nmap (Network Mapper) is the industry-standard tool for network discovery and security auditing. It sends specially crafted packets and analyses responses to determine which hosts are available, what services they run, what operating system they use, and other security-relevant information.

```
Nmap Scan Types — From Stealthy to Noisy:

Stealthiness:
  Most Stealthy                                              Most Noisy
  ────────────────────────────────────────────────────────────────
  Idle  FIN  NULL XMAS ACK  SYN(Half) Connect  Version  Script  Agressive
  Scan  Scan Scan Scan Scan    Scan     Scan     Scan     Scan    Scan

Detection likelihood:
  Idle scan: virtually undetectable (uses zombie host)
  SYN scan: unlikely to be logged by target (half-open, no connection)
  Connect scan: logged by target (full connection established)
  Version scan: logged + leaves evidence of probe traffic
  Aggressive: loud, generates many entries in logs and IDS
```

### 5.2 Host Discovery

```bash
# Host discovery — determine which hosts are alive before port scanning

# ICMP echo (ping sweep) — default if not root:
nmap -sn 192.168.1.0/24
# -sn: skip port scan (ping only)
# Uses: ICMP echo, TCP SYN to 443, TCP ACK to 80, ICMP timestamp

# ICMP only (root required):
sudo nmap -sn -PE 192.168.1.0/24  # ICMP echo request
sudo nmap -sn -PP 192.168.1.0/24  # ICMP timestamp request (bypasses some firewalls)
sudo nmap -sn -PM 192.168.1.0/24  # ICMP address mask request

# TCP SYN discovery (no port scan):
sudo nmap -sn -PS22,80,443,3389 192.168.1.0/24  # Send SYN to these ports
# Hosts that respond = alive (even if they RST — they're up)

# UDP discovery:
sudo nmap -sn -PU53,161,137 192.168.1.0/24  # UDP probe

# ARP discovery (fastest on local network):
sudo nmap -sn -PR 192.168.1.0/24  # ARP (only works on same subnet)

# No ping (scan even if host appears down — useful for firewalled hosts):
sudo nmap -Pn 192.168.1.100       # Skip host discovery, scan directly

# Large network scanning with timing:
sudo nmap -sn -T4 --min-parallelism 100 10.0.0.0/8  # Fast scan of Class A
sudo nmap -sn --max-rtt-timeout 200ms --min-hosts 4096 192.168.0.0/16

# Exclude specific hosts from scan:
sudo nmap -sn 192.168.1.0/24 --exclude 192.168.1.1  # Skip router
sudo nmap -sn 192.168.1.0/24 --excludefile critical_hosts.txt
```

### 5.3 Port Scanning Techniques

```bash
# SYN Scan — default when running as root (half-open scan):
sudo nmap -sS 192.168.1.100
# Sends SYN, waits for SYN-ACK (open) or RST (closed)
# Never completes TCP handshake → fewer logs on target
# Open: received SYN-ACK, sent RST
# Closed: received RST
# Filtered: no response or ICMP unreachable

# TCP Connect Scan — default without root (full connection):
nmap -sT 192.168.1.100
# Completes full TCP handshake
# Generates connection logs on target
# Works without raw socket privileges

# UDP Scan:
sudo nmap -sU 192.168.1.100
# Sends UDP probe to each port
# Open: receives UDP response (rare — most UDP services don't respond to probes)
# Closed: receives ICMP port unreachable
# Filtered: no response (or ICMP admin prohibited)
# Open|Filtered: no response (could be open or filtered — can't tell)
# SLOW: waiting for ICMP responses + rate limiting

# Port specification:
nmap -sS 192.168.1.100 -p 80         # Single port
nmap -sS 192.168.1.100 -p 80,443,22  # Multiple ports
nmap -sS 192.168.1.100 -p 1-1024     # Port range
nmap -sS 192.168.1.100 -p-           # All 65535 ports
nmap -sS 192.168.1.100 -p U:53,T:22  # UDP 53 and TCP 22

# Top ports scan (common ports first):
nmap -sS 192.168.1.100 --top-ports 100    # Scan 100 most common ports
nmap -sS 192.168.1.100 --top-ports 1000   # Top 1000 (faster than -p-)

# Fast scan:
nmap -sS -F 192.168.1.100             # -F = fast (top 100 ports only)

# Version detection:
nmap -sV 192.168.1.100                # Detect service versions
nmap -sV --version-intensity 5        # Intensity 0-9 (0=light, 9=all probes)
nmap -sV --version-all                # Maximum version probing

# OS detection:
sudo nmap -O 192.168.1.100            # OS fingerprinting
sudo nmap -O --osscan-guess           # Guess even if not certain

# Aggressive scan (combines -sV -O -sC --traceroute):
sudo nmap -A 192.168.1.100            # Aggressive — comprehensive but noisy
```

### 5.4 Nmap Scripting Engine (NSE)

NSE is one of Nmap's most powerful features — scripts that perform automated detection, exploitation, and information gathering.

```bash
# Default scripts (safe, commonly useful):
sudo nmap -sC 192.168.1.100          # Run default scripts
# Equivalent to: --script=default

# Specific script:
sudo nmap --script smb-vuln-ms17-010 -p 445 192.168.1.100   # Check EternalBlue
sudo nmap --script http-title -p 80,443 192.168.1.0/24      # Get web page titles

# Script categories:
# auth: authentication bypass/brute force
# broadcast: network discovery via broadcast
# brute: brute force authentication
# default: safe, common scripts (run with -sC)
# discovery: enumerate network info
# dos: denial of service
# exploit: exploitation scripts (use carefully)
# external: queries external services
# fuzzer: send fuzzing data
# intrusive: may crash target systems
# malware: detect malware
# safe: won't cause harm
# version: version detection
# vuln: check for known vulnerabilities

# Vulnerability scanning scripts:
sudo nmap --script vuln 192.168.1.100     # All vulnerability scripts
sudo nmap --script vuln -p 445 192.168.1.0/24  # SMB vulns on network

# Critical vulnerability scripts:
sudo nmap --script smb-vuln-ms17-010 -p 445 192.168.1.0/24   # EternalBlue
sudo nmap --script rdp-vuln-ms12-020 -p 3389 192.168.1.100   # RDP vuln
sudo nmap --script ssl-heartbleed -p 443 192.168.1.100        # Heartbleed
sudo nmap --script ssl-poodle -p 443 192.168.1.100            # POODLE
sudo nmap --script http-shellshock -p 80,443 192.168.1.100    # Shellshock
sudo nmap --script smb-security-mode -p 445 192.168.1.0/24   # SMB signing
sudo nmap --script snmp-brute -p 161 192.168.1.0/24          # SNMP communities
sudo nmap --script ftp-anon -p 21 192.168.1.0/24             # Anonymous FTP

# Information gathering scripts:
sudo nmap --script dns-brute --script-args dns-brute.domain=target.com  # Subdomain enum
sudo nmap --script ldap-search -p 389 192.168.1.10           # LDAP enumeration
sudo nmap --script smb-enum-shares -p 445 192.168.1.100      # SMB shares
sudo nmap --script smb-enum-users -p 445 192.168.1.100       # SMB user enum
sudo nmap --script http-enum -p 80,443 192.168.1.100         # Web paths
sudo nmap --script banner -p 21,22,25,80 192.168.1.100       # Service banners

# ICS/OT scripts:
sudo nmap --script modbus-discover -p 502 192.168.1.0/24     # Modbus devices
sudo nmap --script s7-info -p 102 192.168.1.0/24             # Siemens S7 PLCs
sudo nmap --script dnp3-info -p 20000 192.168.1.0/24         # DNP3 devices
sudo nmap --script bacnet-info -p 47808 192.168.1.0/24       # BACnet devices
sudo nmap --script enip-info -p 44818 192.168.1.0/24         # EtherNet/IP
```

### 5.5 Nmap Output Formats

```bash
# Output formats:
sudo nmap -sS -oN output.txt 192.168.1.0/24      # Normal (human readable)
sudo nmap -sS -oX output.xml 192.168.1.0/24      # XML (machine readable, Metasploit import)
sudo nmap -sS -oG output.gnmap 192.168.1.0/24    # Grepable format
sudo nmap -sS -oA output 192.168.1.0/24          # All formats (.nmap, .xml, .gnmap)
sudo nmap -sS -oJ output.json 192.168.1.0/24     # JSON (with -oX then convert)

# Grep from grepable output:
grep "80/open" output.gnmap | awk '{print $2}'   # IPs with port 80 open
grep "Ports:" output.gnmap | cut -d' ' -f2-      # Extract port lists

# Parse XML with Python:
python3 << 'EOF'
import xml.etree.ElementTree as ET

tree = ET.parse('output.xml')
root = tree.getroot()

for host in root.findall('host'):
    status = host.find('status').get('state')
    if status == 'up':
        addr = host.find('address').get('addr')
        print(f"\nHost: {addr}")
        
        ports = host.find('ports')
        if ports:
            for port in ports.findall('port'):
                if port.find('state').get('state') == 'open':
                    portid = port.get('portid')
                    service = port.find('service')
                    svc = service.get('name', 'unknown') if service is not None else 'unknown'
                    version = service.get('product', '') if service is not None else ''
                    print(f"  {portid}/tcp  {svc}  {version}")
EOF
```

### 5.6 Nmap for Security Assessments — Practical Workflows

```bash
# Phase 1: Discovery
sudo nmap -sn 192.168.1.0/24 -oA phase1_discovery
# Identify live hosts first

# Phase 2: Port scan of live hosts
grep "Up" phase1_discovery.gnmap | awk '{print $2}' > live_hosts.txt
sudo nmap -sS -p- --open -T4 -iL live_hosts.txt -oA phase2_ports
# -iL: read hosts from file
# --open: only show open ports (reduce output)
# -p-: all 65535 ports
# -T4: aggressive timing

# Phase 3: Version detection on open ports
grep "open" phase2_ports.gnmap | awk '{print $2}' | sort -u > hosts_with_ports.txt
sudo nmap -sV -sC -iL hosts_with_ports.txt -oA phase3_versions

# Phase 4: Vulnerability assessment
sudo nmap --script vuln -iL hosts_with_ports.txt -oA phase4_vulns

# Combine phases for efficiency:
sudo nmap -sS -sV -sC --script vuln \
    -p- --open \
    -T4 \
    -iL live_hosts.txt \
    -oA comprehensive_scan

# Evasion techniques:
sudo nmap -sS -T1 192.168.1.100              # Paranoid timing (very slow)
sudo nmap -sS --scan-delay 1s 192.168.1.100  # 1 second between probes
sudo nmap -sS -f 192.168.1.100               # Fragment packets (8-byte fragments)
sudo nmap -sS -D RND:10 192.168.1.100        # Decoy scan (10 random decoys)
sudo nmap -sS --source-port 53 192.168.1.100 # Spoof source port (bypass some firewalls)
sudo nmap -sS --data-length 25 192.168.1.100 # Add random data to packets
```

### 5.7 Nmap in OT/ICS Environments — Critical Warnings

```
WARNING: Nmap in OT/ICS environments requires extreme caution.

Industrial devices differ from IT devices in their response to scanning:

1. PLCs (Programmable Logic Controllers):
   May CRASH or RESTART when receiving unexpected packets
   A PLC restart in a manufacturing environment = production stop
   A PLC restart during a chemical process = potential safety incident
   
2. RTUs (Remote Terminal Units):
   Some legacy RTUs have limited TCP stack resources
   Port scan may exhaust connection table → device stops responding
   
3. Network Switches (industrial grade):
   Some Hirschmann, Moxa switches have bugs triggered by SYN scans
   May cause port to err-disable or switch to restart
   
4. Safety Systems:
   Safety PLCs (SIS — Safety Instrumented Systems) are the most critical
   ANY unexpected interaction with a SIS can trigger a demand
   A spurious demand on safety system = unplanned process shutdown or worse
   NEVER scan safety systems without explicit written vendor approval
   
Safe alternatives for OT asset discovery:
  1. Passive monitoring (tcpdump/Wireshark — no traffic injection)
  2. ARP scan only (Layer 2, generally safe): nmap -sn -PR 192.168.1.0/24
  3. ICMP ping only (usually safe): nmap -sn -PE 192.168.1.0/24
  4. SNMP queries to known management IPs (pre-approved)
  5. Review existing asset inventory documentation
  6. Query SCADA/HMI system for known device list
  
If active scanning is required:
  - Get written approval from operations/safety team
  - Schedule during planned maintenance window
  - Have operations team monitor process for abnormal behaviour
  - Have rollback plan ready
  - Start with single host, verify it doesn't cause issues
  - Use slow timing (-T1 or custom delays)
  - Never use -A, -sV, or NSE scripts on unknown OT devices
```

> **Key Insight:** Nmap's NSE scripting makes it not just a scanner but a vulnerability assessment platform. The `smb-vuln-ms17-010` script checks for EternalBlue with one command; `modbus-discover` identifies Modbus devices and queries their status. In OT environments, however, Nmap requires discipline — the wrong scan against the wrong device can stop production or create safety hazards. Passive tools first, active tools only with explicit approval.

---

## 6. Traceroute and Tracert — Path Discovery

### 6.1 How Traceroute Works

Traceroute reveals the path that packets take from source to destination by exploiting TTL (Time to Live) expiration.

```
Traceroute Mechanism:

Packet 1: TTL=1
  Source → [Router 1] → TTL decrements to 0 → Router 1 discards packet
  Router 1 sends back: ICMP Time Exceeded (Type 11, Code 0)
  Source records: Router 1's IP, round-trip time

Packet 2: TTL=2
  Source → [Router 1] → TTL=1 → [Router 2] → TTL=0 → Router 2 discards
  Router 2 sends back: ICMP Time Exceeded
  Source records: Router 2's IP, RTT

Packet 3: TTL=3
  Source → Router 1 → Router 2 → [Router 3] → TTL=0 → Time Exceeded
  ...continues until destination reached

Final Packet: TTL = number of hops
  Destination receives packet → responds normally
  Linux: ICMP Port Unreachable (UDP probe to unlikely port)
  Windows: ICMP Echo Reply

Each hop shows:
  * = no response (firewall drops ICMP, timeout)
  IP address = router's interface address
  RTT (3 measurements) = latency at that hop
```

### 6.2 Traceroute Variants

```bash
# Linux traceroute (uses UDP by default):
traceroute google.com
traceroute -n google.com              # -n: numeric, no DNS resolution
traceroute -T google.com              # TCP SYN (bypasses firewalls blocking UDP/ICMP)
traceroute -T -p 80 google.com        # TCP SYN to port 80
traceroute -I google.com              # ICMP echo (like Windows tracert)
traceroute -q 1 google.com            # -q 1: one probe per hop (faster)
traceroute -w 2 google.com            # -w 2: 2 second timeout per probe
traceroute -m 30 google.com           # -m 30: max 30 hops
traceroute -s 192.168.1.5 google.com  # -s: source IP to use
traceroute --back google.com          # Show asymmetric return path

# Windows tracert:
tracert google.com
tracert -d google.com                 # -d: no DNS resolution
tracert -h 30 google.com              # -h: max hops
tracert -w 3000 google.com            # -w: timeout in milliseconds

# mtr (My TraceRoute) — combines ping + traceroute, real-time:
mtr google.com                        # Interactive real-time view
mtr --report google.com               # Generate report
mtr --report-cycles 10 google.com     # 10 cycles then report
mtr --no-dns google.com               # No DNS resolution

# TCP traceroute variants:
tcptraceroute 192.168.1.1 22          # TCP traceroute to SSH port
hping3 --traceroute -V -S -p 80 192.168.1.1  # hping3 TCP SYN traceroute
```

### 6.3 Security Analysis with Traceroute

```bash
# Trace to identify network topology:
traceroute -n 192.168.1.100
# Reveals: number of hops, intermediate router IPs, asymmetric paths
# Security use: map network architecture without access to topology docs

# Identify firewall locations:
traceroute -n 8.8.8.8
# Where hops stop responding (*** ***) = likely firewall
# Where latency jumps significantly = network boundary

# Detect MPLS networks (ISP infrastructure):
traceroute -n 8.8.8.8
# MPLS hops may show 0ms or very low latency (hardware switching)

# Firewall type detection from traceroute responses:
# * * * at specific hop: ICMP blocked (stateless filter or DROP policy)
# !X: network unreachable (routing problem)
# !H: host unreachable
# !P: protocol unreachable
# !F: fragmentation needed
# !A: administratively prohibited (ACL REJECT rule)

# Asymmetric routing detection:
traceroute -n targetIP          # Outbound path
# Then have target traceroute back to you
# Different paths = asymmetric routing (security monitoring implications)

# Use traceroute to bypass firewalls:
traceroute -T -p 80 blocked_host.com    # TCP SYN to port 80
# If HTTP (port 80) is allowed through firewall but ICMP/UDP is not:
# TCP traceroute succeeds where normal traceroute fails
# Useful for: determining where filtering occurs, identifying firewall position

# Network change detection (baseline and compare):
traceroute -n 8.8.8.8 | tee /tmp/baseline_$(date +%Y%m%d).txt
# Compare over time: different path = routing change (possibly malicious)
# BGP hijack: traffic suddenly going through unexpected ASes
```

**Traceroute and Security Monitoring:**

```bash
# Detect traceroute probes against your network (defensive):
# In Wireshark: filter for TTL-limited packets:
# ip.ttl <= 3 and not (ip.src == your_IP)

# In tcpdump:
sudo tcpdump -i eth0 'ip[8] < 5'     # IP TTL < 5 (traceroute probes)
sudo tcpdump -i eth0 -n 'udp and ip[8] < 5'  # UDP traceroute probes

# In iptables (log traceroute probes):
sudo iptables -A INPUT -m ttl --ttl-lt 5 -j LOG --log-prefix "TRACEROUTE: "

# Detect hping3 traceroute (TCP SYN with low TTL):
sudo tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0 and ip[8] < 10'
```

> **Key Insight:** Traceroute is the network equivalent of a map — it shows where your traffic goes and how it gets there. During incident response, traceroute to C2 IP addresses reveals ISP infrastructure and geographic routing, which supports attribution. Changes in traceroute paths over time can indicate BGP hijacking. In OT environments, traceroute confirms whether traffic is properly segmented — if a traceroute from an untrusted zone reaches an OT device with fewer hops than expected, segmentation may be compromised.

---

## 7. Ping — The Fundamental Connectivity Test

### 7.1 Ping Mechanics

Ping sends ICMP Echo Request packets and waits for ICMP Echo Reply. It measures:
- Whether a host is reachable
- Round-trip time (RTT)
- Packet loss percentage

```
ICMP Echo Request/Reply:
  Type 8, Code 0: Echo Request (ping sent)
  Type 0, Code 0: Echo Reply (pong received)
  
Packet structure:
  [IP Header][ICMP Header][Identifier][Sequence Number][Data]
  Identifier: identifies the ping process (useful for multi-process analysis)
  Sequence Number: increments per packet (detects packet loss/reordering)
  Data: typically a timestamp + padding
```

### 7.2 Ping Commands

```bash
# Linux ping:
ping 192.168.1.1                     # Ping until Ctrl+C
ping -c 4 192.168.1.1                # -c 4: send 4 packets
ping -c 1 -W 1 192.168.1.1          # -W 1: 1 second timeout (quick test)
ping -i 0.2 192.168.1.1             # -i 0.2: send every 0.2 seconds (fast)
ping -s 1400 192.168.1.1            # -s 1400: packet size 1400 bytes
ping -f 192.168.1.1                 # -f: flood ping (root only — sends as fast as possible)
ping -t 64 192.168.1.1              # -t 64: set TTL to 64
ping -q 192.168.1.1                 # -q: quiet (only summary)
ping -b 192.168.1.255               # -b: broadcast ping (finds all hosts on subnet)

# ping6 (IPv6):
ping6 ::1                           # Ping IPv6 loopback
ping6 -I eth0 fe80::1               # Ping link-local (must specify interface)

# Windows ping:
ping 192.168.1.1                    # 4 packets by default
ping -t 192.168.1.1                 # Ping continuously
ping -n 10 192.168.1.1              # -n 10: 10 packets
ping -l 1000 192.168.1.1            # -l 1000: 1000 byte packets
ping -i 5 192.168.1.1               # -i 5: TTL = 5
ping -w 3000 192.168.1.1            # -w 3000: 3 second timeout

# Network sweep with ping (quick host discovery):
for i in $(seq 1 254); do
    ping -c 1 -W 1 192.168.1.$i &>/dev/null && echo "192.168.1.$i is alive"
done
# Slow — runs sequentially

# Parallel ping sweep (faster):
for i in $(seq 1 254); do
    (ping -c 1 -W 1 192.168.1.$i &>/dev/null && echo "192.168.1.$i alive") &
done
wait

# fping (faster, parallel by design):
fping -a -g 192.168.1.0/24 2>/dev/null  # -a: show alive, -g: generate range
fping -A -g 192.168.1.0/24              # -A: show addresses of alive hosts

# MTU discovery using ping:
ping -M do -s 1472 192.168.1.1     # -M do: don't fragment, -s 1472 (+28 headers = 1500 MTU)
# If MTU is smaller: "Frag needed and DF set"
# Binary search for MTU: test 1472, 1000, 1300, 1400, 1450...
```

### 7.3 Ping for Security Analysis

```bash
# Detect if ICMP is blocked by firewall:
ping -c 1 target_ip
# No response: either host down OR ICMP blocked by firewall
# Use TCP scan to disambiguate:
nmap -sT -p 80,443 -Pn target_ip    # -Pn: skip ping, assume host is up

# Detect ICMP rate limiting:
ping -f -c 1000 192.168.1.1         # Flood ping (root required)
# Rate: loss% indicates rate limiting or capacity issues
# Security: can be used to stress test, also detects DoS-resistant configs

# Identify OS via TTL (passive fingerprinting):
ping -c 1 target_ip | grep "ttl="
# ttl=64: Linux/Unix
# ttl=128: Windows
# ttl=255: Cisco/network devices
# Note: each hop decrements TTL by 1, so adjust for distance

# Covert channel detection (ICMP payload analysis):
sudo tcpdump -i eth0 icmp -A | grep -v "^--$\|bytes"
# Large or unusual ICMP payloads = potential covert channel
# Normal ping: 32 bytes (Windows) or 56 bytes (Linux) of data
# Suspicious: 1400+ bytes, non-standard patterns, encrypted-looking content

# Detect ping sweep against your network:
sudo tcpdump -i eth0 'icmp and icmp[icmptype] = icmp-echo' -n | \
    awk '{print $3}' | cut -d. -f1-4 | \
    sort | uniq -c | sort -rn | head
# High count from single source = ping sweep (reconnaissance)

# ICMP timestamp requests (OS fingerprinting):
hping3 --icmp --icmp-ts 192.168.1.1    # ICMP timestamp request
# Response reveals system time (useful for timezone identification)
```

**Ping of Death and ICMP-based Attacks:**

```bash
# Ping of Death (historical — modern OSes patched):
# Large ICMP fragments caused buffer overflow in old OSes
# ping -s 65500 target  # Would crash old Windows/Unix kernels
# Modern relevance: some embedded OT devices may still be vulnerable

# Smurf Attack (broadcast ping with spoofed source):
# Concept: ping broadcast address with victim's IP as source
# All hosts reply to victim → amplified DoS
# hping3 --icmp -a VICTIM_IP BROADCAST_ADDRESS  (do NOT run this)
# Defence: disable broadcast ping response:
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# ICMP redirect attack detection:
sudo tcpdump -i eth0 'icmp[icmptype] = icmp-redirect'
# Should almost never see ICMP redirects on secure network
# ICMP redirect from unexpected host = possible routing attack

# Block ICMP redirects:
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
```

> **Key Insight:** Ping is deceptively simple but encodes OS type (TTL), network topology (RTT changes), and reachability in every response. No response to ping doesn't mean the host is down — firewalls commonly block ICMP while allowing TCP. In OT environments, ping is the safest active tool to use — a single ICMP Echo Request is unlikely to destabilise most field devices. But even here, caution is warranted with very old RTUs and PLCs.

---

## 8. ipconfig and ifconfig — Interface Configuration

### 8.1 Windows ipconfig

ipconfig is the primary Windows command for viewing and managing IP configuration.

```cmd
# Basic commands:
ipconfig                    # Summary: IP, mask, gateway per interface
ipconfig /all               # Full details: MAC, DHCP, DNS, lease times
ipconfig /release           # Release DHCP lease (lose IP)
ipconfig /renew             # Renew DHCP lease (get new IP)
ipconfig /flushdns          # Clear DNS resolver cache
ipconfig /displaydns        # Show DNS resolver cache contents
ipconfig /registerdns       # Re-register DNS (forces DNS update)
ipconfig /showclassid *     # Show DHCP class IDs

# Security-relevant output from ipconfig /all:
# Physical Address (MAC): identifies device manufacturer, useful for inventory
# DHCP Enabled: Yes/No — is this statically or dynamically assigned?
# DHCP Server: which server assigned this IP (for forensic timeline)
# Lease Obtained: when was the IP assigned (forensic timestamp)
# Lease Expires: when will it expire
# Default Gateway: routing path — is this the expected gateway?
# DNS Servers: which servers resolve names — rogue DNS = suspicious
# DNS Suffix Search List: reveals domain membership
```

**ipconfig for Security Analysis:**

```cmd
# Check for rogue gateway/DNS (MITM indicator):
ipconfig /all | findstr /i "gateway\|dns server"
# Expected: corporate gateway and DNS IPs
# Unexpected: different IPs = possible DHCP poisoning or MITM

# Find all network interfaces (VPN, virtual adapters):
ipconfig /all | findstr /i "adapter\|IPv4\|physical"
# VPN adapters may have routes that bypass monitoring
# Unexpected adapters = possible rogue software

# DNS cache analysis (what has this machine been looking up?):
ipconfig /displaydns
# Shows: all recently resolved domains
# Forensic value: what sites has this machine visited?
# Suspicious entries: C2 domains, unusual TLDs, encoded domain names

# Clear evidence (attacker's move):
ipconfig /flushdns           # Clear DNS cache evidence
# Detection: if DNS cache is empty on an active machine = suspicious
```

### 8.2 Linux ifconfig and ip

`ifconfig` is legacy. `ip` is the modern replacement. Know both.

```bash
# Legacy ifconfig:
ifconfig                         # All interfaces
ifconfig eth0                    # Specific interface
ifconfig eth0 up                 # Bring interface up
ifconfig eth0 down               # Bring interface down
ifconfig eth0 192.168.1.100/24   # Set IP address
ifconfig eth0 promisc            # Enable promiscuous mode (packet capture)
ifconfig eth0 -promisc           # Disable promiscuous mode

# Modern ip command:
ip addr                          # Show all interfaces and IPs
ip addr show eth0                # Specific interface
ip link show                     # Link layer info (MAC, state)
ip route show                    # Routing table
ip route get 8.8.8.8             # What route would be used for this destination?
ip neigh show                    # ARP cache
ip -s link                       # Interface statistics
ip -6 addr                       # IPv6 addresses

# Adding/removing configuration:
sudo ip addr add 192.168.1.100/24 dev eth0    # Add IP
sudo ip addr del 192.168.1.100/24 dev eth0   # Remove IP
sudo ip link set eth0 up                       # Bring up interface
sudo ip link set eth0 down                     # Bring down interface
sudo ip link set eth0 address AA:BB:CC:DD:EE:FF  # Change MAC address
sudo ip route add default via 192.168.1.1       # Add default route
sudo ip route del default                        # Remove default route

# Security-relevant interface operations:
sudo ip link set eth0 promisc on     # Enable promiscuous mode
ip link show eth0 | grep -i promisc  # Check if promiscuous mode is on
# Promiscuous mode: someone is running packet capture on this interface
# Unexpected promisc = potential malicious sniffing

# Find all network interfaces (including hidden/virtual):
ip link show
# Look for: unexpected tap/tun interfaces (VPN/tunnels), br- (bridges)
# br-* = Docker bridge (container networking)
# tun0 = OpenVPN/WireGuard tunnel
# virbr* = libvirt/QEMU virtual bridge

# Check for multiple default routes (split tunnelling indicator):
ip route show | grep "default"
# Multiple default routes: possible VPN split tunnelling
# Security: traffic may not all go through monitoring infrastructure
```

### 8.3 Network Configuration for Security

```bash
# Full network configuration audit script:
cat > /tmp/network_config_audit.sh << 'EOF'
#!/bin/bash
echo "===== NETWORK CONFIGURATION AUDIT ====="
echo "Timestamp: $(date)"
echo ""

echo "--- All Interfaces ---"
ip addr show | grep -E "^[0-9]|inet "
echo ""

echo "--- MAC Addresses ---"
ip link show | grep "link/ether"
echo ""

echo "--- Routing Table ---"
ip route show
echo ""

echo "--- ARP Cache ---"
ip neigh show
echo ""

echo "--- DNS Configuration ---"
cat /etc/resolv.conf
echo ""

echo "--- Listening Services ---"
ss -tulnp 2>/dev/null | head -30
echo ""

echo "--- Promiscuous Interfaces ---"
ip link show | grep -i promisc
echo ""

echo "--- Active VPN/Tunnel Interfaces ---"
ip link show | grep -E "tun|tap|vpn|wg|ovpn"
echo ""

echo "--- Unusual Routes ---"
ip route show | grep -v "^default\|169.254\|fe80"
echo ""

echo "===== AUDIT COMPLETE ====="
EOF
chmod +x /tmp/network_config_audit.sh
bash /tmp/network_config_audit.sh
```

> **Key Insight:** ipconfig/ifconfig is the starting point for every network investigation — it establishes your current position on the network. In incident response, unexpected configurations reveal MITM attacks (wrong gateway), DNS hijacking (wrong DNS servers), and covert channels (unexpected VPN adapters or promiscuous interfaces). In OT assessments, collecting interface configuration from all devices builds the network topology without active scanning.

---

## 9. Additional Critical Tools

### 9.1 arp — ARP Table Management

```bash
# View ARP cache:
arp -a                              # All entries (Linux/Windows)
ip neigh show                       # Modern Linux equivalent

# Static ARP entries (prevent ARP spoofing of critical hosts):
sudo arp -s 192.168.1.1 AA:BB:CC:DD:EE:FF    # Add static entry (Linux)
sudo arp -d 192.168.1.1                       # Delete entry

# Windows:
arp -a                              # View all
netsh interface ip add neighbors "Local Area Connection" 192.168.1.1 AA-BB-CC-DD-EE-FF
# Add static ARP for gateway

# Detect ARP spoofing:
watch -n 1 arp -a                   # Monitor ARP table changes
# If gateway IP shows different MAC = ARP spoofing in progress
```

### 9.2 dig and nslookup — DNS Interrogation

```bash
# dig (Domain Information Groper) — primary DNS tool:
dig example.com                     # A record (default)
dig example.com A                   # Explicit A record
dig example.com AAAA                # IPv6 address
dig example.com MX                  # Mail exchange
dig example.com TXT                 # Text records (SPF, DKIM, etc.)
dig example.com NS                  # Name servers
dig example.com SOA                 # Start of Authority
dig -x 8.8.8.8                     # Reverse lookup (PTR)
dig @8.8.8.8 example.com           # Use specific DNS server
dig +short example.com              # Just the answer (IP only)
dig +trace example.com              # Full resolution trace (root → TLD → auth)
dig +nocmd +noall +answer example.com  # Clean output

# Security uses:
dig TXT _dmarc.example.com          # DMARC policy
dig TXT example.com | grep spf      # SPF record
dig AXFR @ns1.example.com example.com  # Zone transfer attempt
dig example.com ANY                 # All record types

# Detect DNS changes:
OLD_IP=$(dig +short example.com)
sleep 3600
NEW_IP=$(dig +short example.com)
[ "$OLD_IP" != "$NEW_IP" ] && echo "DNS CHANGED: $OLD_IP → $NEW_IP"

# nslookup:
nslookup example.com                # Basic lookup
nslookup example.com 8.8.8.8       # Use specific server
nslookup -type=MX example.com      # MX records
nslookup -type=any example.com     # All types (Windows compatible)
```

### 9.3 route — Routing Table Management

```bash
# View routing table:
route -n                            # Linux (legacy, numeric)
ip route show                       # Linux (modern)
netstat -rn                         # Cross-platform
route print                         # Windows

# Security implications of routing table:
ip route show
# default via 192.168.1.1 dev eth0  ← Default gateway — check this is expected
# 10.0.0.0/8 via 10.10.0.1         ← Route to internal network (VPN route)
# 192.168.2.0/24 dev eth1           ← Directly connected network

# Check for suspicious routes:
ip route show | grep -v "^default\|^192.168\|^10\.\|^172\."
# Unexpected routes to external IPs = possible MITM or routing attack

# Add/remove routes:
sudo ip route add 10.20.0.0/24 via 192.168.1.254  # Add route
sudo ip route del 10.20.0.0/24                      # Remove route

# Windows:
route add 10.20.0.0 mask 255.255.255.0 192.168.1.254  # Add route
route delete 10.20.0.0                                  # Remove route
```

---

## 10. Tool Integration — Building Investigation Workflows

### 10.1 Incident Response Workflow

```bash
#!/bin/bash
# Comprehensive network evidence collection for incident response

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
EVIDENCE_DIR="/tmp/ir_evidence_$TIMESTAMP"
mkdir -p "$EVIDENCE_DIR"

echo "Collecting network evidence to $EVIDENCE_DIR"

# 1. Current connections:
echo "=== Collecting connection state ==="
ss -tnp > "$EVIDENCE_DIR/connections_tcp.txt"
ss -unp > "$EVIDENCE_DIR/connections_udp.txt"
ss -tlnp > "$EVIDENCE_DIR/listening_services.txt"

# 2. Network configuration:
echo "=== Collecting interface config ==="
ip addr show > "$EVIDENCE_DIR/interfaces.txt"
ip route show > "$EVIDENCE_DIR/routing.txt"
ip neigh show > "$EVIDENCE_DIR/arp_cache.txt"
cat /etc/resolv.conf > "$EVIDENCE_DIR/dns_config.txt"

# 3. Active processes with network connections:
echo "=== Correlating processes to connections ==="
ss -tnp | awk 'NR>1 && /ESTABLISHED/{print $5, $6}' | sort > "$EVIDENCE_DIR/established_with_process.txt"

# 4. Start packet capture:
echo "=== Starting packet capture (60 seconds) ==="
timeout 60 tcpdump -i any -w "$EVIDENCE_DIR/traffic.pcap" -s 0 2>/dev/null &
TCPDUMP_PID=$!

# 5. DNS cache (if applicable):
echo "=== Collecting DNS cache ==="
if command -v resolvectl &>/dev/null; then
    resolvectl statistics > "$EVIDENCE_DIR/dns_stats.txt"
fi

# 6. Check for suspicious listening ports:
echo "=== Checking for unexpected listeners ==="
ss -tlnp | awk 'NR>1 {print $4, $6}' | while read addr proc; do
    port=$(echo $addr | cut -d: -f2)
    # Flag non-standard ports that are listening
    if [[ $port -gt 1024 ]] && [[ $port -ne 3306 ]] && [[ $port -ne 5432 ]]; then
        echo "Non-standard listener: $addr ($proc)" >> "$EVIDENCE_DIR/suspicious_listeners.txt"
    fi
done

wait $TCPDUMP_PID 2>/dev/null

echo "Evidence collection complete: $EVIDENCE_DIR"
ls -la "$EVIDENCE_DIR"
```

### 10.2 Network Reconnaissance Workflow (Penetration Testing)

```bash
#!/bin/bash
# Structured network reconnaissance for authorised penetration testing

TARGET_NETWORK=${1:-"192.168.1.0/24"}
OUTPUT_DIR="./recon_$(date +%Y%m%d)"
mkdir -p "$OUTPUT_DIR"

echo "=== Phase 1: Host Discovery ==="
sudo nmap -sn "$TARGET_NETWORK" -oG "$OUTPUT_DIR/phase1_hosts.gnmap" 2>/dev/null
LIVE_HOSTS=$(grep "Status: Up" "$OUTPUT_DIR/phase1_hosts.gnmap" | awk '{print $2}' | tee "$OUTPUT_DIR/live_hosts.txt")
echo "Found $(wc -l < "$OUTPUT_DIR/live_hosts.txt") live hosts"

echo "=== Phase 2: Port Scan ==="
sudo nmap -sS --top-ports 1000 --open \
    -iL "$OUTPUT_DIR/live_hosts.txt" \
    -oA "$OUTPUT_DIR/phase2_ports" 2>/dev/null
echo "Port scan complete"

echo "=== Phase 3: Service Detection ==="
sudo nmap -sV -sC \
    -iL "$OUTPUT_DIR/live_hosts.txt" \
    -oA "$OUTPUT_DIR/phase3_services" 2>/dev/null

echo "=== Phase 4: Quick Vulnerability Check ==="
sudo nmap --script "vuln and not intrusive" \
    -iL "$OUTPUT_DIR/live_hosts.txt" \
    -oA "$OUTPUT_DIR/phase4_vulns" 2>/dev/null

echo "=== Summary ==="
echo "Live hosts: $(wc -l < "$OUTPUT_DIR/live_hosts.txt")"
echo "Hosts with web services:"
grep "80/open\|443/open\|8080/open" "$OUTPUT_DIR/phase2_ports.gnmap" | wc -l
echo "Hosts with SMB:"
grep "445/open" "$OUTPUT_DIR/phase2_ports.gnmap" | wc -l
echo "Hosts with RDP:"
grep "3389/open" "$OUTPUT_DIR/phase2_ports.gnmap" | wc -l
echo ""
echo "Results saved to $OUTPUT_DIR"
```

### 10.3 Traffic Analysis Workflow

```bash
# Automated traffic analysis for SOC/threat hunting:

# Capture traffic:
sudo tcpdump -i eth0 -w /tmp/analysis.pcap -s 0 \
    'not (host 192.168.1.1 and port 22)' &  # Exclude your SSH session
sleep 300    # Capture 5 minutes
kill %1

# Analysis pipeline:
tshark -r /tmp/analysis.pcap -q -z conv,tcp | head -30   # Top TCP conversations
tshark -r /tmp/analysis.pcap -q -z io,phs                 # Protocol hierarchy
tshark -r /tmp/analysis.pcap -Y "dns.flags.response == 0" \
    -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -20  # Top DNS queries

# Find potential beaconing (regular-interval connections):
tshark -r /tmp/analysis.pcap -T fields \
    -e frame.time_epoch -e ip.dst -e tcp.dstport \
    -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" | \
    awk '{print $2":"$3}' | sort | uniq -c | sort -rn | head -20
# High count to same IP:port = possible beacon

# Find large data transfers:
tshark -r /tmp/analysis.pcap -q -z endpoints,ip | \
    awk 'NR>4 {print $3, $1}' | sort -rn | head -20
# Large bytes_sent from internal IP to external = possible exfiltration
```

---

## 11. Network Analysis in OT/ICS Environments

### 11.1 Passive vs Active Analysis in OT

The cardinal rule of network analysis in OT environments: **passive first, active only with explicit approval**.

```
Passive Analysis Tools (safe for OT):
  Wireshark/tcpdump: listen-only, no traffic injection
  - Connect via SPAN/mirror port on managed switch
  - Use network TAP (hardware device) for full-duplex capture
  - Analyse traffic generated by existing devices — no new traffic created

  Netstat/ss: local host analysis
  - Run on engineering workstations, HMI servers
  - No network traffic generated — purely local

  ipconfig/ifconfig/ip: interface configuration
  - Local host only — no network impact

Active Analysis Tools (require approval in OT):
  Ping: low risk (usually), but must be approved
  - Some legacy RTUs crash on unexpected ICMP
  - Always check with vendor before pinging OT devices
  
  Traceroute: moderate risk
  - Sends TTL-limited packets — some OT devices respond unexpectedly
  - Useful for mapping, but schedule during maintenance if possible
  
  Nmap: HIGH risk — must have written approval and operational window
  - PLCs can crash or restart on unexpected port scans
  - Safety systems: NEVER scan without vendor written approval
```

### 11.2 Industrial Protocol Analysis in Wireshark

```bash
# Wireshark dissectors for OT protocols:

# Modbus TCP (port 502):
# Wireshark automatically dissects Modbus if capture contains port 502 traffic
# Useful display filters:
# modbus.func_code == 3    (Read Holding Registers — most common)
# modbus.func_code == 16   (Preset Multiple Registers — write commands)
# modbus.func_code == 1    (Read Coil Status)
# modbus.exception_code    (Modbus error responses)

# Security analysis of Modbus:
sudo tshark -r ot_capture.pcap \
    -Y "modbus.func_code >= 5" \   # Write commands only
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e modbus.func_code \
    -e modbus.reference_num        # Register number being written

# DNP3 (port 20000):
# Filter: dnp3
# Security-relevant function codes:
# 3 = Time and Date (write)
# 4 = File Transfer
# 13 = Object 21 (frozen analog — operational data)
# 129 = Response (data from field device)

# IEC 60870-5-104 (port 2404):
# Filter: iec104
# ASDU type analysis for operational data vs control commands

# OPC-UA (port 4840):
# Filter: opcua
# Look for: unusual sessions, high data transfer, unexpected service calls

# EtherNet/IP / CIP (port 44818):
# Filter: enip or cip
# CIP services of concern:
# 0x4C = Get Attribute Single (reconnaissance)
# 0x4D = Set Attribute Single (configuration change)
# 0x10 = Set Attribute All (bulk configuration change)

# PROFINET (uses Ethernet frames directly):
# Filter: pn_io or pn_dcp
# DCP: Device discovery protocol (maps device layout)
# RT: Real-time data frames (process data)

# BACnet (UDP 47808):
# Filter: bacnet
# Service: readProperty (reconnaissance)
# Service: writeProperty (control)
```

### 11.3 OT-Specific Security Monitoring

```bash
# Baseline normal OT traffic, then alert on deviations:

# Step 1: Capture baseline during known-good operation
sudo tcpdump -i eth0 -w /tmp/ot_baseline_$(date +%H%M%S).pcap \
    -G 3600 -W 24 \                # 1 hour rotation, keep 24 files (1 day)
    'port 502 or port 20000 or port 2404 or port 44818 or port 47808'

# Step 2: Build source-destination matrix from baseline
tshark -r /tmp/ot_baseline.pcap -q -z conv,tcp | tail -n +5 | \
    awk '{print $1, "<->", $3}' | sort -u > /tmp/expected_connections.txt

# Step 3: Compare current traffic against baseline
tshark -r /tmp/current.pcap -q -z conv,tcp | tail -n +5 | \
    awk '{print $1, "<->", $3}' | sort -u > /tmp/current_connections.txt

# Connections not in baseline = potential anomaly:
comm -13 /tmp/expected_connections.txt /tmp/current_connections.txt
echo "Above connections are NEW — not seen in baseline"

# Step 4: Alert on write commands to PLCs (should be rare during operation):
sudo tshark -i eth0 -Y "modbus.func_code >= 5" \
    -T fields -e frame.time -e ip.src -e ip.dst -e modbus.func_code | \
    while read line; do
        echo "[ALERT] Modbus write command: $line" | logger -t OT_SECURITY
    done
```

---

## 12. Hands-On Exercises

### Exercise 1: Wireshark Protocol Deep-Dive (45 minutes)

```bash
# Download sample captures from Wireshark's wiki:
wget -q https://wiki.wireshark.org/uploads/afae4d9c6a5c0b96db05df03d00c97b0/http.cap \
    -O /tmp/http_sample.pcap 2>/dev/null || \
    echo "Download from wiki.wireshark.org/SampleCaptures manually"

# If no download, generate your own:
sudo tcpdump -i eth0 -w /tmp/my_capture.pcap -c 500 &
# Browse some websites, then:
curl http://neverssl.com/ > /dev/null
curl https://example.com > /dev/null
nslookup google.com > /dev/null
kill %1 2>/dev/null

# Analysis tasks (in Wireshark):
CAPTURE="/tmp/my_capture.pcap"

echo "=== Task 1: Protocol Distribution ==="
tshark -r "$CAPTURE" -q -z io,phs 2>/dev/null | head -20

echo "=== Task 2: Top 5 Talkers ==="
tshark -r "$CAPTURE" -q -z conv,ip 2>/dev/null | head -10

echo "=== Task 3: DNS Queries Made ==="
tshark -r "$CAPTURE" -Y "dns.flags.response == 0" \
    -T fields -e dns.qry.name 2>/dev/null | sort | uniq -c | sort -rn

echo "=== Task 4: HTTP Requests ==="
tshark -r "$CAPTURE" -Y "http.request" \
    -T fields -e ip.src -e http.host -e http.request.uri 2>/dev/null | head -10

echo "=== Task 5: TCP Connections ==="
tshark -r "$CAPTURE" -q -z conv,tcp 2>/dev/null | head -10

echo "=== Task 6: Open Wireshark for visual analysis ==="
echo "Commands: wireshark $CAPTURE"
echo "Try these filters:"
echo "  tcp.flags.syn == 1 and tcp.flags.ack == 0"
echo "  http.request"
echo "  dns"
echo "  ip.addr == 8.8.8.8"
```

### Exercise 2: Nmap Discovery and Scanning (30 minutes)

```bash
# Nmap exercises (on your own lab network)

NETWORK="192.168.1.0/24"  # Change to your network

echo "=== Exercise 2.1: Host Discovery ==="
sudo nmap -sn "$NETWORK" | grep -E "Nmap scan|Host is"

echo "=== Exercise 2.2: SYN scan of single host ==="
TARGET=$(sudo nmap -sn "$NETWORK" | grep "report for" | head -1 | awk '{print $NF}')
echo "Scanning $TARGET..."
sudo nmap -sS -p 1-1000 "$TARGET" 2>/dev/null | tail -20

echo "=== Exercise 2.3: Version detection ==="
sudo nmap -sV -p 22,80,443 "$TARGET" 2>/dev/null

echo "=== Exercise 2.4: NSE default scripts ==="
sudo nmap -sC -p 22,80,443 "$TARGET" 2>/dev/null | head -30

echo "=== Exercise 2.5: OS detection ==="
sudo nmap -O "$TARGET" 2>/dev/null | grep -A5 "OS details"

echo "=== Exercise 2.6: Save results ==="
sudo nmap -sS -sV -oA /tmp/nmap_exercise "$TARGET" 2>/dev/null
echo "Results saved: /tmp/nmap_exercise.{nmap,xml,gnmap}"
echo "Open XML in Metasploit: db_import /tmp/nmap_exercise.xml"
```

### Exercise 3: Network Forensics Investigation (45 minutes)

```bash
# Simulate a security incident and investigate

# Step 1: Create baseline network state
echo "=== Baseline Network State ==="
ss -tnp > /tmp/baseline_connections.txt
ip addr show > /tmp/baseline_interfaces.txt
ip route show > /tmp/baseline_routes.txt
ip neigh show > /tmp/baseline_arp.txt
echo "Baseline saved"

# Step 2: Start a background listener (simulating backdoor):
nc -l 4444 &
NC_PID=$!
echo "Simulated backdoor started on port 4444 (PID: $NC_PID)"

# Step 3: Investigate — find the "backdoor":
echo ""
echo "=== INVESTIGATION ==="

echo "--- Step A: Check for new listening ports ---"
ss -tlnp | grep -v "$(cat /tmp/baseline_connections.txt | awk '{print $4}' | grep LISTEN | tr '\n' '|')"

echo ""
echo "--- Step B: Find the specific listener ---"
ss -tlnp | grep ":4444"

echo ""
echo "--- Step C: Identify the process ---"
ss -tlnp | grep ":4444" | grep -oE 'pid=[0-9]+' | while read pid; do
    pid_num=${pid#pid=}
    echo "PID: $pid_num"
    echo "Command: $(cat /proc/$pid_num/cmdline 2>/dev/null | tr '\0' ' ')"
    echo "Executable: $(ls -la /proc/$pid_num/exe 2>/dev/null)"
done

echo ""
echo "--- Step D: Check ARP for new hosts ---"
diff /tmp/baseline_arp.txt <(ip neigh show) | grep "^>" || echo "No new ARP entries"

# Step 4: Cleanup
kill $NC_PID 2>/dev/null
echo ""
echo "=== Investigation complete. Backdoor cleaned up. ==="
```

### Exercise 4: Build a Network Monitor Script (30 minutes)

```bash
cat > /tmp/network_monitor.sh << 'SCRIPT'
#!/bin/bash
# Network security monitor — baseline and alert on changes

BASELINE_DIR="/tmp/net_baseline"
ALERT_LOG="/tmp/net_alerts.log"
mkdir -p "$BASELINE_DIR"

create_baseline() {
    echo "Creating baseline..."
    ss -tlnp | awk 'NR>1 {print $4, $6}' | sort > "$BASELINE_DIR/listeners.txt"
    ip neigh show | awk '{print $1, $5}' | sort > "$BASELINE_DIR/arp.txt"
    ip route show > "$BASELINE_DIR/routes.txt"
    echo "Baseline created at $(date)"
}

check_changes() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Check for new listeners
    CURRENT_LISTENERS=$(ss -tlnp | awk 'NR>1 {print $4, $6}' | sort)
    NEW_LISTENERS=$(comm -13 "$BASELINE_DIR/listeners.txt" <(echo "$CURRENT_LISTENERS"))
    if [ -n "$NEW_LISTENERS" ]; then
        echo "[$timestamp] NEW LISTENER DETECTED:" | tee -a "$ALERT_LOG"
        echo "$NEW_LISTENERS" | tee -a "$ALERT_LOG"
    fi
    
    # Check for new ARP entries
    CURRENT_ARP=$(ip neigh show | awk '{print $1, $5}' | sort)
    NEW_ARP=$(comm -13 "$BASELINE_DIR/arp.txt" <(echo "$CURRENT_ARP"))
    if [ -n "$NEW_ARP" ]; then
        echo "[$timestamp] NEW HOST DETECTED (ARP):" | tee -a "$ALERT_LOG"
        echo "$NEW_ARP" | tee -a "$ALERT_LOG"
    fi
    
    # Check for route changes
    CURRENT_ROUTES=$(ip route show)
    if ! diff "$BASELINE_DIR/routes.txt" <(echo "$CURRENT_ROUTES") > /dev/null 2>&1; then
        echo "[$timestamp] ROUTING TABLE CHANGED!" | tee -a "$ALERT_LOG"
        diff "$BASELINE_DIR/routes.txt" <(echo "$CURRENT_ROUTES") | tee -a "$ALERT_LOG"
    fi
}

case "${1:-check}" in
    baseline) create_baseline ;;
    check)    check_changes ;;
    monitor)
        create_baseline
        echo "Monitoring for changes... (Ctrl+C to stop)"
        while true; do
            check_changes
            sleep 30
        done
        ;;
    *)
        echo "Usage: $0 [baseline|check|monitor]"
        ;;
esac
SCRIPT

chmod +x /tmp/network_monitor.sh
echo "Usage:"
echo "  bash /tmp/network_monitor.sh baseline  # Create baseline"
echo "  bash /tmp/network_monitor.sh check     # Check for changes"
echo "  bash /tmp/network_monitor.sh monitor   # Continuous monitoring"
```

---

## 13. Module Summary

| Tool | Primary Function | Key Security Use | OT/ICS Notes |
|------|-----------------|------------------|--------------|
| **Wireshark** | GUI packet capture and analysis | Full protocol dissection, credential capture in cleartext protocols, follow TCP stream for session reconstruction | Safe (passive via SPAN/TAP); Modbus/DNP3/IEC 61850 dissectors built-in |
| **tshark** | CLI Wireshark | Scripted analysis, remote capture via SSH, automated field extraction | Same as Wireshark — passive, no impact |
| **tcpdump** | CLI packet capture | Evidence collection, real-time monitoring, piping to analysis tools | Available on embedded Linux OT systems; safest active tool |
| **netstat** | Connection state viewer | Backdoor detection (unexpected listeners), active connection analysis, process-to-port mapping | Run on HMI/SCADA servers for connection audit |
| **ss** | Modern netstat replacement | Same as netstat, faster, richer filtering | Preferred on modern Linux OT systems |
| **Nmap (host discovery)** | Identify live hosts | Network mapping, asset discovery, scope definition | Use -sn with ICMP only; get approval; schedule maintenance window |
| **Nmap (port scan)** | Identify open services | Attack surface enumeration, service version detection | HIGH risk in OT; PLC/RTU may crash; written approval mandatory |
| **Nmap NSE** | Automated vulnerability/info scripts | Vuln checking (EternalBlue, Heartbleed), OT protocol fingerprinting | OT-specific scripts (modbus-discover, s7-info) useful but still invasive |
| **Traceroute** | Path discovery | Network topology mapping, firewall location, BGP anomaly detection | Moderate risk in OT; some RTUs respond unexpectedly to TTL-limited packets |
| **Ping** | Reachability and RTT | Host discovery, latency baseline, OS fingerprinting (TTL), covert channel detection | Low risk but get approval; some legacy field devices unstable with unexpected ICMP |
| **ipconfig** | Windows interface config | MITM detection (wrong gateway/DNS), VPN adapter detection, forensic timestamps | Run on Windows HMI/engineering workstations for configuration audit |
| **ifconfig/ip** | Linux interface config | Interface configuration, promiscuous mode detection, route analysis | Run on Linux-based HMI/SCADA servers |
| **dig/nslookup** | DNS interrogation | DNS security checks (SPF/DMARC/DKIM), zone transfer, subdomain enumeration | Useful for verifying DNS configuration of OT-connected systems |
| **arp** | ARP table management | MITM detection (gateway MAC change), rogue host detection | Critical in OT: unexpected ARP entries = potential rogue device |

---

> **Next Stage:** [Stage 2 — Cybersecurity Core](../STAGE-02_CyberSecurity-Fundamentals/README.md)  
> **Previous Module:** [Stage 1.7 — Wireless Networks](./stage-1.7-wireless-networks.md)  
> **Stage Index:** [Stage 1 README](./README.md)  
> **Series Index:** [Full Roadmap](../../README.md)

---

*This document is part of the Cybersecurity × OT/ICS Security Full Roadmap series. All techniques are presented for educational purposes, authorised security research, and defensive security practice. Always obtain proper authorisation before testing any system.*