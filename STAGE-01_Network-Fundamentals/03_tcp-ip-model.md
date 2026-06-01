# Stage 1.3 — TCP/IP Model
### From Zero to Cybersecurity Professional | Complete Roadmap Series

> **Series:** Cybersecurity × OT/ICS Security — Full Roadmap  
> **Stage:** 1 — Network Fundamentals  
> **Module:** 1.3 — TCP/IP Model  
> **Level:** Beginner → Advanced  
> **Prerequisites:** Stage 1.2 — OSI Model  
> **Next Module:** 1.4 — IP Addressing and Subnetting

---

## Table of Contents

1. [Why TCP/IP Is the Foundation of Every Attack and Defence](#1-why-tcpip-is-the-foundation-of-every-attack-and-defence)
2. [TCP/IP Model — Four Layers, One Internet](#2-tcpip-model--four-layers-one-internet)
3. [TCP vs UDP — The Fundamental Choice](#3-tcp-vs-udp--the-fundamental-choice)
4. [TCP Three-Way Handshake — Deep Dive](#4-tcp-three-way-handshake--deep-dive)
5. [TCP Four-Way Termination](#5-tcp-four-way-termination)
6. [TCP Internals — What Textbooks Skip](#6-tcp-internals--what-textbooks-skip)
7. [IPv4 Addressing](#7-ipv4-addressing)
8. [IPv6 Fundamentals](#8-ipv6-fundamentals)
9. [ICMP — The Network's Diagnostic Layer](#9-icmp--the-networks-diagnostic-layer)
10. [ARP — Address Resolution Protocol](#10-arp--address-resolution-protocol)
11. [Putting It All Together — A Complete Packet's Journey](#11-putting-it-all-together--a-complete-packets-journey)
12. [TCP/IP in OT/ICS Environments](#12-tcpip-in-otics-environments)
13. [Hands-On Exercises](#13-hands-on-exercises)
14. [Module Summary](#14-module-summary)

---

## 1. Why TCP/IP Is the Foundation of Every Attack and Defence

TCP/IP is not a topic you study and move past. It is the substrate on which every network interaction in your career will happen. Every shell you catch, every packet you capture, every firewall rule you write, every alert you investigate — it all lives inside TCP/IP.

**Concrete career examples:**

When you run Metasploit and set `LHOST` and `LPORT`, you are configuring a TCP or UDP listener at the IP layer. When your reverse shell connects back, it initiates a TCP three-way handshake. When you lose the shell because the target rebooted, the TCP connection terminated via RST or timeout.

When you use Wireshark to analyse a suspected C2 beacon, you are looking at TCP streams. The beacon's timing, payload size, and connection frequency are all visible in TCP/IP metadata — even when the payload is encrypted.

When a SOC analyst sees "port 4444 outbound to 185.220.x.x," they know: that is TCP, that is Metasploit's default listener port, and that is a Tor exit node IP range. All of that reasoning comes from knowing TCP/IP deeply.

When an OT engineer says "the PLC stopped responding," the first question is: is it a Layer 3 (IP routing) problem, a Layer 4 (TCP connection state) problem, or a Layer 7 (Modbus application) problem? You cannot answer that without knowing TCP/IP.

**The security reality:** TCP/IP was designed in the 1970s-80s for a cooperative research network. Authentication was not a design requirement. Every IP address can be spoofed. Every TCP connection can be reset by a third party. ARP has no authentication. ICMP can be used to map networks and crash systems. These are not bugs — they are the protocol as designed. Understanding these properties is what allows you to exploit them offensively and defend against their exploitation defensively.

---

## 2. TCP/IP Model — Four Layers, One Internet

### 2.1 The Model

The TCP/IP model (also called the DoD model — Department of Defense, which funded its development) describes how internet protocols are organised. Unlike OSI's seven layers, TCP/IP uses four:

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 4 — Application                                      │
│  HTTP, HTTPS, DNS, SMTP, FTP, SSH, Telnet, SNMP,           │
│  Modbus TCP, DNP3, IEC 60870-5-104, OPC-UA                 │
├─────────────────────────────────────────────────────────────┤
│  Layer 3 — Transport                                        │
│  TCP (port-to-port, reliable)                               │
│  UDP (port-to-port, unreliable)                             │
│  SCTP, QUIC                                                 │
├─────────────────────────────────────────────────────────────┤
│  Layer 2 — Internet                                         │
│  IPv4, IPv6                                                 │
│  ICMP, ICMPv6                                               │
│  IPSec (AH, ESP)                                           │
├─────────────────────────────────────────────────────────────┤
│  Layer 1 — Network Access (Link)                            │
│  Ethernet, Wi-Fi (802.11), ARP                             │
│  Physical medium: copper, fibre, radio                      │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 OSI vs TCP/IP — The Mapping Every Professional Needs

```
OSI Layer          OSI Name        TCP/IP Layer     TCP/IP Name
─────────────────────────────────────────────────────────────
7                  Application   ─┐
6                  Presentation  ─┼──────────────→  Application
5                  Session       ─┘
4                  Transport      ─────────────→   Transport
3                  Network        ─────────────→   Internet
2                  Data Link     ─┐
1                  Physical      ─┴─────────────→  Network Access
```

**Why this matters:** Security tools, CVEs, and documentation reference both models. A vulnerability described as "L4 TCP RST injection" and one described as "transport layer attack" mean the same thing. An "L3 routing attack" is an "Internet layer attack" in TCP/IP terms. You must translate fluently between both.

### 2.3 The Internet Layer — The Core of TCP/IP

The Internet layer (IP) is what makes the internet work. It provides:

- **Logical addressing:** IP addresses identify hosts globally
- **Routing:** Packets are forwarded hop-by-hop toward the destination
- **Fragmentation:** Large packets split to fit link MTU
- **Connectionless delivery:** No guarantees — best effort

IP's lack of guarantees is intentional. Reliability, ordering, and error correction are pushed up to the Transport layer (TCP) or the application. This separation of concerns made the internet scalable — routers only need to forward packets, not maintain state for every connection.

---

## 3. TCP vs UDP — The Fundamental Choice

### 3.1 The Design Philosophy

TCP and UDP represent two fundamentally different answers to the question: "How should we move data between applications?"

```
TCP answer: "Reliably. I will guarantee every byte arrives, in order,
             exactly once. I will establish a connection first, track
             what was sent, retransmit what was lost, and signal when
             I'm done. Cost: overhead, latency, connection state."

UDP answer: "As fast as possible. I will send the data and forget it.
             No connection setup. No tracking. No retransmission.
             If it arrives, great. If not, the application deals with it.
             Cost: no reliability guarantees."
```

### 3.2 TCP — Transmission Control Protocol

**Header structure (20 bytes minimum):**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌───────────────────────────┬───────────────────────────────────┐
│       Source Port         │        Destination Port           │  4 bytes
├───────────────────────────┴───────────────────────────────────┤
│                    Sequence Number                             │  4 bytes
├───────────────────────────────────────────────────────────────┤
│                 Acknowledgement Number                         │  4 bytes
├────────┬───────┬─┬─┬─┬─┬─┬─┬─┬─┬───────────────────────────┤
│  Data  │Reserv.│C│E│U│A│P│R│S│F│        Window Size         │  4 bytes
│ Offset │       │W│C│R│C│S│S│Y│I│                            │
│        │       │R│E│G│K│H│T│N│N│                            │
├────────┴───────┴─┴─┴─┴─┴─┴─┴─┴─┴───────────────────────────┤
│           Checksum             │       Urgent Pointer         │  4 bytes
├───────────────────────────────────────────────────────────────┤
│                    Options (variable)                          │  0-40 bytes
└───────────────────────────────────────────────────────────────┘
```

**Critical fields and their security relevance:**

**Source Port / Destination Port (16 bits each):**
- Identify which application is communicating
- Source port on clients: ephemeral (49152-65535 typically)
- Destination port identifies the service: 22=SSH, 80=HTTP, 443=HTTPS, 502=Modbus
- **Security:** Firewall rules filter on port numbers. Port scanning (Nmap) determines which ports have listening services. Port spoofing is possible but doesn't affect server-side port allocation.

**Sequence Number (32 bits):**
- Tracks position in the byte stream
- Initial Sequence Number (ISN) is random (per RFC 6528 — cryptographically random to prevent prediction)
- Each byte of data sent increments the sequence number
- **Security:** Historical predictable ISNs enabled TCP session hijacking. Mitnick's 1994 attack against Tsutomu Shimomura predicted ISNs to forge TCP connections. Modern OSes use random ISNs, but weak ISN generation (CVE-2001-0751, others) has recurred.

**Acknowledgement Number (32 bits):**
- Next expected byte from the other side
- "I have received everything up to byte N, send me byte N+1 next"

**Flags (9 bits):**
```
CWR: Congestion Window Reduced
ECE: ECN-Echo (explicit congestion notification)
URG: Urgent pointer valid
ACK: Acknowledgement field valid — set on all packets after handshake
PSH: Push — deliver data to application immediately, don't buffer
RST: Reset — abort connection immediately
SYN: Synchronise — initiate connection (ISN negotiation)
FIN: Finish — no more data from sender (graceful close)
```

**Window Size (16 bits):**
- How many bytes the receiver is willing to accept before requiring acknowledgement
- TCP flow control mechanism
- **Security:** Window size is an OS fingerprinting signal. Linux, Windows, and macOS use different default window sizes and scaling factors. Nmap uses window size as part of OS detection.

**TCP Options (variable):**
```
Common TCP options:
  MSS (Maximum Segment Size): Maximum TCP payload per segment
                               Typically 1460 bytes (1500 MTU - 20 IP - 20 TCP)
  Window Scale: Multiplier for window size (enables large windows)
  SACK (Selective Acknowledgement): Acknowledge non-contiguous data
  Timestamps: Used for RTT measurement and PAWS (Protection Against Wrapped Seq.)
  No-Operation (NOP): Padding

Security: TCP options reveal OS. The combination of MSS, window scale,
SACK support, and timestamp presence is a reliable OS fingerprint.
Nmap's -O flag uses this — as does passive fingerprinting (p0f).
```

### 3.3 UDP — User Datagram Protocol

**Header structure (8 bytes — fixed):**

```
┌───────────────────────────┬───────────────────────────────────┐
│       Source Port         │        Destination Port           │  4 bytes
├───────────────────────────┴───────────────────────────────────┤
│           Length           │           Checksum               │  4 bytes
├───────────────────────────────────────────────────────────────┤
│                         Data                                   │
└───────────────────────────────────────────────────────────────┘
```

UDP has no:
- Sequence numbers (no ordering)
- Acknowledgements (no reliability)
- Flow control (no congestion management)
- Connection state (no handshake)

**When UDP is correct:**

| Use Case | Why UDP | Example Protocols |
|----------|---------|-------------------|
| DNS queries | Single request/response, retry easy | DNS (UDP 53) |
| Real-time media | Latency more important than reliability | VoIP, video streaming |
| Time synchronisation | Precision more important than reliability | NTP (UDP 123) |
| Network management | Simple request/response | SNMP (UDP 161) |
| Tunnelling protocols | Custom reliability at higher layer | WireGuard, QUIC |
| Multicast/Broadcast | TCP cannot multicast | DHCP, mDNS, SSDP |
| Industrial real-time | Sub-millisecond timing requirements | PROFINET RT, EtherNet/IP |

### 3.4 TCP vs UDP Security Comparison

```
Attack                      TCP        UDP       Notes
─────────────────────────────────────────────────────────────────
IP Spoofing               Limited    Effective  TCP requires handshake; UDP fire-and-forget
Amplification DDoS         No        YES        UDP has no handshake; responses sent to victim
SYN Flood                  YES       No         TCP-specific: half-open connection exhaustion
Port Scanning             Easy       Harder     TCP RST/SYN-ACK indicates open; UDP needs app response
Session Hijacking          YES       Stateless  TCP has sessions; UDP doesn't
Man-in-the-Middle          YES       YES        Both can be intercepted
C2 Communication          Common    Common      Depends on operational requirements
Firewall Bypass           Harder    Easier      Stateful firewalls track TCP; UDP often loosely filtered
```

```bash
# Identify TCP vs UDP ports in a capture
sudo tcpdump -i eth0 -n 'tcp' -c 20      # TCP traffic only
sudo tcpdump -i eth0 -n 'udp' -c 20      # UDP traffic only

# Nmap: scan both TCP and UDP
sudo nmap -sS 192.168.1.1               # TCP SYN scan (fast, stealthy)
sudo nmap -sU 192.168.1.1               # UDP scan (slower, requires responses)
sudo nmap -sS -sU -p T:80,443,22,U:53,161,123 192.168.1.1  # Both protocols

# See all open TCP/UDP ports on local system
ss -tulnp                               # TCP+UDP listening with process names
ss -t state established                 # Established TCP connections
```

> **Key Insight:** The choice between TCP and UDP is a security decision, not just a performance one. UDP-based services are harder to firewall correctly (stateless), more susceptible to spoofing-based attacks, and are the mechanism behind virtually every large-scale DDoS amplification attack. Every time you see UDP on a port that isn't expected, it deserves investigation.

---

## 4. TCP Three-Way Handshake — Deep Dive

### 4.1 The Mechanics

```
CLIENT                                         SERVER
  │                                              │
  │  ──── [SYN] seq=ISN_c ──────────────────→   │
  │       Flags: SYN                             │
  │       Seq:   100 (random ISN)               │
  │       Ack:   0 (not yet)                    │
  │       Window: 65535                         │
  │       Options: MSS=1460, SACK, Timestamps   │
  │                                              │
  │  ←─── [SYN-ACK] seq=ISN_s, ack=ISN_c+1 ───  │
  │       Flags: SYN, ACK                        │
  │       Seq:   500 (server's random ISN)      │
  │       Ack:   101 (client's ISN + 1)        │
  │       Window: 28960                         │
  │       Options: MSS=1460, SACK, Timestamps   │
  │                                              │
  │  ──── [ACK] seq=ISN_c+1, ack=ISN_s+1 ──→   │
  │       Flags: ACK                             │
  │       Seq:   101                            │
  │       Ack:   501 (server's ISN + 1)        │
  │                                              │
  │  ══════════ [CONNECTION ESTABLISHED] ══════  │
  │                                              │
  │  ──── [PSH,ACK] DATA ───────────────────→   │
  │  ←─── [ACK] ──────────────────────────────  │
```

**Why three packets, not two?**

Two-way handshake (SYN → SYN-ACK) would only confirm that the client can reach the server and that the server can send back. It does not confirm that the server's response can reach the client. The third ACK confirms bidirectional communication.

More importantly, the three-way handshake establishes **two independent sequence number spaces** — one for each direction. The client's ISN is acknowledged by the server's ACK, and the server's ISN is acknowledged by the client's final ACK. This is why it requires three messages.

### 4.2 ISN — Initial Sequence Number Security

The ISN is the single most security-critical field in the TCP handshake. Historically:

**Pre-1996 implementations:**
Many early TCP stacks incremented the global ISN counter by a fixed amount per second. An attacker could:
1. Connect to the target legitimately to observe the current ISN
2. Predict the ISN the target would use for the next connection
3. Forge a TCP connection by sending SYN with spoofed source IP, then complete the handshake using the predicted ISN
4. Inject data into a trust relationship (e.g., impersonate a trusted host)

This is exactly what Kevin Mitnick did in his 1994 attack on Tsutomu Shimomura's machines — he exploited predictable ISNs over a Christmas weekend to hijack a TCP session and access Shimomura's files.

**Modern ISN generation (RFC 6528, 2012):**
```
ISN = M + F(localhost, localport, remotehost, remoteport, secret_key)

M = 4-microsecond timer (prevents wrapping)
F = hash function (typically MD5 or SipHash)
secret_key = random value generated at system boot

Result: ISN appears random for each new connection,
        cannot be predicted without knowing the secret key,
        but can be reproduced for retransmission purposes
```

```bash
# Observe ISN randomisation in practice
# Connect three times and compare SYN sequence numbers:

python3 << 'EOF'
import socket, struct

for i in range(3):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('google.com', 80))
    # Get local port assigned by OS
    local_port = s.getsockname()[1]
    print(f"Connection {i+1}: local port {local_port}")
    s.close()
# Each connection uses different source port and different ISN
# Capture with tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0' to see ISNs
EOF

# Capture SYN packets and extract sequence numbers
sudo tcpdump -i eth0 -n 'tcp[tcpflags] & tcp-syn != 0 and not tcp[tcpflags] & tcp-ack != 0' \
    -X 2>/dev/null | grep -A2 "Flags \[S\]"
```

### 4.3 SYN Flood Attack — Exploiting the Handshake State

The three-way handshake requires the server to allocate state after receiving the first SYN — before the handshake is complete. This is the foundation of the SYN flood attack.

```
Normal handshake state machine on server:
  CLOSED → LISTEN → SYN_RECEIVED → ESTABLISHED

SYN flood:
  Attacker sends thousands of SYN packets per second
  Server allocates entry in connection table for each (SYN_RECEIVED state)
  Server sends SYN-ACK to source IP (often spoofed — no response comes back)
  Connection remains half-open, consuming memory
  After timeout (~75 seconds default), half-open connection is removed
  But attacker sends new SYNs faster than timeouts clear old ones
  Connection table fills → new legitimate connections rejected → DoS

Connection table limits:
  Linux: /proc/sys/net/ipv4/tcp_max_syn_backlog (default: 256-1024)
  Windows: Configurable, typically 200 per port
```

**SYN Cookies — The Defence:**

```
SYN Cookie algorithm (RFC 4987):
  When under attack (or always, in some implementations):
  
  1. Server receives SYN
  2. Server does NOT allocate state
  3. Server computes cookie = HMAC(srcIP, srcPort, dstIP, dstPort, secret, timestamp)
  4. Server sends SYN-ACK with cookie as the sequence number
  5. If legitimate client completes handshake, sends ACK with ack_number = cookie + 1
  6. Server verifies cookie in the ACK — valid means legitimate client
  7. Server allocates connection state ONLY for verified connections

Result: Server has zero state for half-open connections
        SYN flood has no effect — no state to exhaust

Tradeoff: TCP options (SACK, timestamps, window scaling) cannot be stored
          in the cookie; lost if SYN cookies are triggered
          Modern implementations encode some options in cookie bits

Check SYN cookie status:
cat /proc/sys/net/ipv4/tcp_syncookies
# 0 = disabled
# 1 = enabled when under attack (default on modern Linux)
# 2 = always enabled

# Monitor SYN flood detection:
watch -n 1 'netstat -s | grep -i "syn"'
# SYNs to LISTEN sockets dropped: counter increases during flood
```

### 4.4 Port Scanning — Abusing the Handshake

Different TCP flag combinations reveal different information about a port:

```
Nmap scan types and their mechanics:

TCP Connect Scan (-sT):
  Client → [SYN] → Server
  Open port:    Server → [SYN-ACK] → Client → [ACK] → [RST] → disconnect
  Closed port:  Server → [RST] → Client
  Filtered:     No response (firewall drops)
  Advantage: Works as unprivileged user
  Disadvantage: Noisy — completes full handshake, logged by target

SYN Scan / Half-Open Scan (-sS):
  Client → [SYN] → Server
  Open port:    Server → [SYN-ACK] → Client → [RST] (never completes)
  Closed port:  Server → [RST]
  Filtered:     No response
  Advantage: Faster, stealthier — many services don't log incomplete handshakes
  Disadvantage: Requires root/admin (raw socket access)
  THIS IS NMAP'S DEFAULT WHEN RUN AS ROOT

FIN Scan (-sF):
  Client → [FIN] → Server
  Open port:    Server → [no response] (RFC 793: ignore unexpected FIN)
  Closed port:  Server → [RST]
  Use: Bypass stateless firewalls that only block SYN packets
  
XMAS Scan (-sX):
  Client → [FIN, URG, PSH] → Server
  Same response as FIN scan
  Named "XMAS" because all flags lit up like a Christmas tree
  
NULL Scan (-sN):
  Client → [no flags] → Server
  Same response as FIN scan
  
ACK Scan (-sA):
  Client → [ACK] → Server
  Used to map FIREWALL RULES, not port states
  Both open and closed ports respond with RST
  Filtered = no response (firewall drops ACK packets)
  
Window Scan (-sW):
  Sends ACK packets, examines TCP window size in RST response
  Some systems use non-zero window for open ports, zero for closed
  OS-dependent and unreliable
```

```bash
# Common Nmap usage for TCP analysis:
sudo nmap -sS -p- 192.168.1.100               # All 65535 ports, SYN scan
sudo nmap -sS -sV -p 22,80,443,502 192.168.1.100  # Version detection on specific ports
sudo nmap -sS -O 192.168.1.100                # OS detection (uses TCP/IP fingerprinting)
sudo nmap -sS --scan-delay 1s 192.168.1.100   # Slow scan to evade rate-limit detection
sudo nmap -sS -D RND:10 192.168.1.100         # Decoy scan (mix real scan with fake source IPs)

# Timing templates (T0=paranoid, T5=insane):
sudo nmap -T4 -sS 192.168.1.0/24             # Aggressive timing for LAN scanning
sudo nmap -T1 -sS 192.168.1.100              # Slow, evade IDS timing detection

# Capture the SYN scan traffic to understand what it looks like:
sudo tcpdump -i eth0 -n 'host 192.168.1.100 and tcp' &
sudo nmap -sS 192.168.1.100
# Observe: rapid SYN packets, RST responses for closed, SYN-ACK for open
```

> **Key Insight:** The TCP three-way handshake is simultaneously the mechanism that makes TCP reliable AND the mechanism that makes SYN flood attacks possible. SYN cookies elegantly resolve this tension by deferring state allocation until connection completion. Understanding exactly what state is allocated where and when is the foundation of both DoS attacks and their mitigations.

---

## 5. TCP Four-Way Termination

### 5.1 Graceful Connection Close

TCP connections are full-duplex — data can flow in both directions simultaneously. Closing a TCP connection requires closing each direction independently, which is why it requires four messages instead of three:

```
CLIENT                                         SERVER
  │                                              │
  │  ──── [FIN, ACK] seq=x ─────────────────→   │  Client: "Done sending"
  │                                              │
  │  ←─── [ACK] ack=x+1 ──────────────────────  │  Server: "Got your FIN"
  │                                              │  [Server may still be sending data]
  │                                              │
  │  ←─── [FIN, ACK] seq=y ───────────────────  │  Server: "Done sending too"
  │                                              │
  │  ──── [ACK] ack=y+1 ────────────────────→   │  Client: "Got your FIN"
  │                                              │
  │  [TIME_WAIT: 2×MSL seconds]                 │  [CLOSED]
  │  [CLOSED after TIME_WAIT]                   │
```

**TIME_WAIT state:**
After sending the final ACK, the client enters TIME_WAIT for 2×MSL (Maximum Segment Lifetime, typically 60-120 seconds). This ensures:
1. The final ACK reached the server (if it was lost, server resends FIN and client can re-ACK)
2. Old duplicate packets from the connection cannot confuse a new connection using the same 4-tuple

**Security implication of TIME_WAIT:**
TIME_WAIT exhaustion is a DoS attack vector. By rapidly opening and closing connections, an attacker can fill the source port space (65535 ephemeral ports) with TIME_WAIT sockets, preventing new outbound connections.

```bash
# Count connections by state
ss -tan | awk '{print $1}' | sort | uniq -c | sort -rn
# or:
netstat -tan | awk '{print $6}' | sort | uniq -c | sort -rn

# States you'll see:
# ESTABLISHED: Active connections
# TIME_WAIT:   Waiting for network stragglers after close
# CLOSE_WAIT:  Remote end sent FIN, waiting for local application to close
# SYN_SENT:    Sent SYN, waiting for SYN-ACK
# SYN_RECEIVED: Got SYN, sent SYN-ACK, waiting for ACK
# LISTEN:      Waiting for incoming connections
# FIN_WAIT_1:  Sent FIN, waiting for ACK
# FIN_WAIT_2:  Got ACK for FIN, waiting for remote FIN
# LAST_ACK:    Sent FIN after CLOSE_WAIT, waiting for ACK
# CLOSING:     Both sides sent FIN simultaneously

# If you see thousands of TIME_WAIT: normal for busy web servers
# If you see growing SYN_RECEIVED: possible SYN flood
# If you see growing CLOSE_WAIT: application not closing sockets properly (bug)
# If you see unusual ESTABLISHED connections: potential backdoors
```

### 5.2 RST — Abrupt Connection Reset

RST (Reset) immediately terminates a connection without the four-way handshake. The receiving side discards any unacknowledged data and removes connection state immediately.

RST is sent by:
- A port that has no listening service (response to SYN on closed port)
- A system receiving a packet for a non-existent connection
- A system that wants to abort a connection immediately

**RST injection attack:**
An attacker who knows the current sequence number of an established TCP connection can forge a RST packet that terminates the connection. Sequence number guessing was historically easy on predictable ISN implementations.

```
RST injection use cases:
1. Network censorship: "Great Firewall of China" injects TCP RST packets
   to terminate connections to blocked content
   Tools: nmap can detect RST injection by comparing responses from different
   vantage points — discrepancies indicate path-level RST injection

2. Intrusion Prevention: IPS devices inject RST to both ends of a connection
   to terminate detected attack traffic

3. Offensive: Terminate an ongoing session between two victims (DoS)

4. Testing: Verify firewall blocks — does a blocked connection receive RST
   (firewall rejects) or nothing (firewall drops silently)?
```

```bash
# hping3 — craft specific TCP packets
sudo hping3 -S -p 80 -c 3 192.168.1.1           # Send 3 SYN to port 80
sudo hping3 -R -p 80 192.168.1.1                # Send RST to port 80
sudo hping3 -A -p 80 192.168.1.1                # Send ACK (firewall mapping)
sudo hping3 -F -p 80 192.168.1.1                # Send FIN (FIN scan)
sudo hping3 -SA -p 80 192.168.1.1               # SYN+ACK (unusual)

# Detect RST injection in Wireshark:
# Filter: tcp.flags.reset == 1
# Compare RST TTLs with expected TTL from destination
# If RST TTL differs significantly from normal responses, RST was injected
# by an intermediate device (firewall, IPS, censor)
```

---

## 6. TCP Internals — What Textbooks Skip

### 6.1 TCP Flow Control — The Sliding Window

Flow control prevents a fast sender from overwhelming a slow receiver. The receiver advertises how much buffer space it has (the window size), and the sender limits outstanding unacknowledged data to this window.

```
Window size = how many bytes receiver can accept without ACK

Sender                          Receiver (window = 4 bytes)
  │                               │ [Buffer: _ _ _ _] (4 empty slots)
  │──── Bytes 1-4 ──────────────→ │ [Buffer: 1 2 3 4] (full)
  │                               │
  │ ←── ACK 5, Window=4 ────────  │ [Buffer: _ _ _ _] (processed, empty)
  │──── Bytes 5-8 ──────────────→ │
  ...

Window scaling (RFC 7323):
  16-bit window field max: 65,535 bytes
  Over fast WAN links, this limits throughput
  Window Scale option multiplies window size by 2^shift_count
  Maximum effective window: 65535 × 2^14 = ~1 GB
```

**Security implication:**
Zero Window Attack: An attacker who can manipulate the receiver into advertising a zero window keeps the sender blocked indefinitely. The sender enters "persist" state, sending small "window probe" packets waiting for the window to open. This can cause connection-level DoS without flooding.

### 6.2 TCP Congestion Control

TCP automatically adapts to network congestion through four algorithms:

```
Slow Start:
  Start with small congestion window (cwnd = 1 MSS)
  Double cwnd each RTT until threshold (ssthresh)
  "Exponential growth"

Congestion Avoidance:
  After ssthresh, increase cwnd by 1 MSS per RTT
  "Linear growth"

Fast Retransmit:
  3 duplicate ACKs = probable packet loss (not timeout)
  Retransmit immediately without waiting for timeout

Fast Recovery:
  After fast retransmit, halve ssthresh and cwnd
  Resume congestion avoidance (not slow start)
```

**Security relevance:** TCP congestion control can be exploited:
- **ACK throttling:** Send ACKs slowly to the sender, reducing its throughput
- **Spurious retransmissions:** Cause the sender to believe packets were lost, triggering congestion response
- **Delayed ACK manipulation:** Exploit TCP's delayed ACK optimisation to affect throughput

### 6.3 TCP Keepalive

TCP keepalive probes are periodic empty ACK packets sent on idle connections to verify the other end is still alive.

```bash
# Linux TCP keepalive settings:
cat /proc/sys/net/ipv4/tcp_keepalive_time      # 7200 (seconds before first probe)
cat /proc/sys/net/ipv4/tcp_keepalive_intvl     # 75 (seconds between probes)
cat /proc/sys/net/ipv4/tcp_keepalive_probes    # 9 (number of probes before giving up)

# Default: 7200s (2 hours!) before first probe
# A dead connection consumes state for 2+ hours by default
# Adjust for security-sensitive applications:
sysctl -w net.ipv4.tcp_keepalive_time=60     # 60 seconds
sysctl -w net.ipv4.tcp_keepalive_intvl=10    # 10 second intervals
sysctl -w net.ipv4.tcp_keepalive_probes=3    # 3 probes then give up

# Security implication:
# Long keepalive intervals allow stealthy C2 connections to persist
# for hours between communications without the connection timing out
# This is why some C2 frameworks use long TCP idle periods
# Detection: connections with high idle time and periodic tiny packets
```

---

## 7. IPv4 Addressing

### 7.1 Structure

IPv4 addresses are 32-bit binary numbers, written as four decimal octets separated by dots.

```
192  .  168  .   1   .  100
─────    ─────    ─────    ─────
11000000 10101000 00000001 01100100

Binary representation:
11000000.10101000.00000001.01100100

Decimal: 192.168.1.100
Hex:     C0.A8.01.64  or  0xC0A80164
```

**Converting between representations:**

```python
# Python — IP address conversions
import ipaddress, socket, struct

ip = "192.168.1.100"

# String to integer
ip_int = int(ipaddress.ip_address(ip))
print(f"Integer: {ip_int}")               # 3232235876

# String to bytes
ip_bytes = socket.inet_aton(ip)
print(f"Bytes: {ip_bytes.hex()}")         # c0a80164

# Integer to string
ip_back = str(ipaddress.ip_address(ip_int))
print(f"Back: {ip_back}")                 # 192.168.1.100

# Working with network ranges
network = ipaddress.ip_network("192.168.1.0/24")
print(f"Network: {network.network_address}")   # 192.168.1.0
print(f"Broadcast: {network.broadcast_address}")  # 192.168.1.255
print(f"Hosts: {network.num_addresses - 2}")      # 254
print(f"First host: {list(network.hosts())[0]}")  # 192.168.1.1
print(f"Last host: {list(network.hosts())[-1]}")  # 192.168.1.254

# Check if IP is in a network
target = ipaddress.ip_address("192.168.1.50")
print(f"In network: {target in network}")        # True

# Useful for: checking if IP is RFC1918 private, checking if in attack scope
print(f"Is private: {target.is_private}")        # True
print(f"Is loopback: {target.is_loopback}")      # False
```

### 7.2 Address Classes (Historical but Required Knowledge)

Before CIDR (1993), IP addresses were divided into classes. Understanding classes is essential because:
1. Legacy systems, documentation, and older CVEs reference them
2. Reserved ranges are still based on class boundaries
3. Subnetting understanding builds on this foundation

```
Class A: 0xxxxxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx
  First bit: 0
  Range: 1.0.0.0 – 126.0.0.0
  Subnet mask: /8 (255.0.0.0)
  Networks: 126
  Hosts per network: 16,777,214
  Used for: Large organisations, ISPs

Class B: 10xxxxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx
  First two bits: 10
  Range: 128.0.0.0 – 191.255.0.0
  Subnet mask: /16 (255.255.0.0)
  Networks: 16,384
  Hosts per network: 65,534
  Used for: Universities, medium enterprises

Class C: 110xxxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx
  First three bits: 110
  Range: 192.0.0.0 – 223.255.255.0
  Subnet mask: /24 (255.255.255.0)
  Networks: 2,097,152
  Hosts per network: 254
  Used for: Small networks (most common)

Class D: 1110xxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx
  Range: 224.0.0.0 – 239.255.255.255
  Purpose: Multicast (not unicast hosts)
  Examples: 224.0.0.5 (OSPF), 239.255.255.250 (SSDP/UPnP)

Class E: 1111xxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx
  Range: 240.0.0.0 – 255.255.255.255
  Purpose: Reserved for experimental use
  255.255.255.255: Limited broadcast
```

### 7.3 Special Address Ranges

**RFC 1918 — Private Addresses:**
These ranges are never routed on the internet. NAT translates between private and public IPs.

```
10.0.0.0/8       10.0.0.0 – 10.255.255.255      (Class A private)
172.16.0.0/12    172.16.0.0 – 172.31.255.255    (Class B private)
192.168.0.0/16   192.168.0.0 – 192.168.255.255  (Class C private)
```

**Other special ranges every security professional must know:**

```
127.0.0.0/8          Loopback (localhost) — 127.0.0.1 is the canonical
169.254.0.0/16       APIPA (Automatic Private IP Addressing) — assigned when DHCP fails
                     Seeing 169.254.x.x means: DHCP failure
                     Also used for link-local communication (AWS metadata: 169.254.169.254)
                     
100.64.0.0/10        Carrier-grade NAT (CGN) — ISP internal addresses
                     Not RFC 1918 but also not public — confuses traceroutes
                     
0.0.0.0/8            "This network" — only valid as source for DHCP discover
192.0.2.0/24         TEST-NET-1 (RFC 5737) — documentation examples
198.51.100.0/24      TEST-NET-2 (RFC 5737) — documentation examples  
203.0.113.0/24       TEST-NET-3 (RFC 5737) — documentation examples
                     (These appear in this document's examples)
                     
192.88.99.0/24       6to4 relay (deprecated but may still appear)
224.0.0.0/4          Multicast
240.0.0.0/4          Reserved
255.255.255.255/32   Limited broadcast
```

**Security implications of special ranges:**

```bash
# AWS EC2 metadata service — critical for cloud attacks:
# 169.254.169.254 is the link-local address of the metadata service
# From inside an EC2 instance: curl http://169.254.169.254/latest/meta-data/
# Contains: IAM credentials, instance role, user-data (often contains secrets)
# SSRF vulnerabilities that reach this address are critical severity

# Check if an IP is in RFC1918:
python3 -c "
import ipaddress
ips = ['10.0.0.1', '172.16.0.1', '192.168.1.1', '8.8.8.8', '169.254.169.254']
for ip in ips:
    addr = ipaddress.ip_address(ip)
    print(f'{ip}: private={addr.is_private}, loopback={addr.is_loopback}, '
          f'link_local={addr.is_link_local}')
"
```

### 7.4 CIDR — Classless Inter-Domain Routing

CIDR (RFC 4632, 1993) replaced classful addressing. It uses a prefix length to define the network portion of an address.

```
192.168.1.0/24

/24 = prefix length = 24 bits for network
     = 32 - 24 = 8 bits for hosts
     = 2^8 - 2 = 254 usable hosts

Subnet mask from CIDR:
/8  = 255.0.0.0       = 11111111.00000000.00000000.00000000
/16 = 255.255.0.0     = 11111111.11111111.00000000.00000000
/24 = 255.255.255.0   = 11111111.11111111.11111111.00000000
/25 = 255.255.255.128 = 11111111.11111111.11111111.10000000
/26 = 255.255.255.192 = 11111111.11111111.11111111.11000000
/30 = 255.255.255.252 = 11111111.11111111.11111111.11111100
/32 = 255.255.255.255 = single host

Host formula: 2^(32-prefix) - 2
(-2 for network address and broadcast address)

/30 = 2^2 - 2 = 2 usable hosts (point-to-point links)
/29 = 2^3 - 2 = 6 usable hosts
/28 = 2^4 - 2 = 14 usable hosts
/27 = 2^5 - 2 = 30 usable hosts
/26 = 2^6 - 2 = 62 usable hosts
/25 = 2^7 - 2 = 126 usable hosts
/24 = 2^8 - 2 = 254 usable hosts
/23 = 2^9 - 2 = 510 usable hosts
/22 = 2^10 - 2 = 1022 usable hosts
/16 = 2^16 - 2 = 65534 usable hosts
/8  = 2^24 - 2 = 16,777,214 usable hosts
```

```bash
# ipcalc — subnet calculator
ipcalc 192.168.1.100/24
# Shows: network, broadcast, host range, prefix, etc.

# Determine network and broadcast from IP + mask:
python3 << 'EOF'
import ipaddress

def subnet_info(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    print(f"CIDR:          {cidr}")
    print(f"Network:       {net.network_address}")
    print(f"Broadcast:     {net.broadcast_address}")
    print(f"Subnet mask:   {net.netmask}")
    print(f"Wildcard mask: {net.hostmask}")
    print(f"Usable hosts:  {net.num_addresses - 2}")
    print(f"First host:    {list(net.hosts())[0]}")
    print(f"Last host:     {list(net.hosts())[-1]}")

subnet_info("192.168.1.100/24")
print()
subnet_info("10.0.0.0/8")
EOF

# Nmap uses CIDR notation for network scanning:
sudo nmap -sn 192.168.1.0/24    # Ping scan entire /24
sudo nmap -sn 10.0.0.0/8        # Ping scan entire Class A (16M addresses — careful)
```

### 7.5 NAT — Network Address Translation

NAT allows multiple devices to share a single public IP address. It modifies IP headers as packets traverse the NAT device.

```
Internal network: 192.168.1.0/24
NAT device (router) public IP: 203.0.113.1

Outbound:
  Host 192.168.1.5:54321 → 8.8.8.8:53 (DNS query)
  NAT rewrites: 203.0.113.1:12345 → 8.8.8.8:53
  Stores mapping: 203.0.113.1:12345 ↔ 192.168.1.5:54321

Inbound:
  8.8.8.8:53 → 203.0.113.1:12345 (DNS response)
  NAT looks up: 203.0.113.1:12345 → 192.168.1.5:54321
  NAT rewrites: 8.8.8.8:53 → 192.168.1.5:54321
  Forwards to 192.168.1.5

NAT types (important for VoIP, P2P, gaming, and some attacks):
  Full Cone: Any external host can send to mapped port
  Restricted Cone: Only hosts that internal host has contacted
  Port Restricted Cone: Only specific source port from contacted host
  Symmetric: Different mapping for each external destination (strictest)
```

**NAT security implications:**

NAT provides **implicit inbound protection** — external hosts cannot initiate connections to NAT'd internal hosts unless the NAT device is explicitly configured to allow it (port forwarding). This is why home routers with NAT provide a degree of protection even without a firewall.

However, NAT is NOT a security control:
- Internal hosts can still initiate outbound connections (C2 communication bypasses NAT)
- NAT traversal techniques (STUN, TURN, UPnP, ICMP tunnel) allow external hosts to reach internal machines
- UPnP (Universal Plug and Play) allows applications to automatically configure NAT port forwarding — malware exploits this

**Forensic implications:** NAT obscures the true source of connections. When investigating an incident, the firewall/NAT log is essential — without it, all connections appear to come from the NAT device's public IP.

---

## 8. IPv6 Fundamentals

### 8.1 Why IPv6 Exists and Why It Matters for Security

IPv4 has 2^32 = 4,294,967,296 addresses. The internet ran out of unallocated IPv4 space in 2011. IPv6 was designed to replace it.

IPv6 has 2^128 addresses. That is 340 undecillion (3.4 × 10^38) — roughly 50 octillion addresses per person on Earth. Address exhaustion is not a concern for the foreseeable future.

For security professionals, IPv6 matters because:
- Many networks have dual-stack (IPv4 + IPv6) deployments where the IPv6 side is misconfigured or unmonitored
- Security tools, firewalls, and monitoring systems are often IPv4-centric — IPv6 traffic slips through
- IPv6 has its own address types, protocols (ICMPv6, NDP), and attack surface
- IPv6 is often enabled by default on operating systems even when the network administrator thinks they are running IPv4-only

### 8.2 IPv6 Address Structure

```
IPv6 address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
              ─────────────────────────────────────────
              128 bits, 8 groups of 16 bits each, hex notation

Shorthand rules:
  1. Leading zeros in each group can be omitted:
     0db8 → db8
     0000 → 0
  
  2. One or more consecutive all-zero groups can be replaced with ::
     (only once per address):
     2001:db8:85a3:0:0:8a2e:370:7334
     → 2001:db8:85a3::8a2e:370:7334

Examples:
  ::1                    Loopback (equivalent to 127.0.0.1)
  ::                     Unspecified address (equivalent to 0.0.0.0)
  fe80::1                Link-local address
  2001:db8::/32          Documentation prefix (like 192.0.2.0/24)
  ff02::1                All nodes (link-local multicast)
  ff02::2                All routers (link-local multicast)
```

### 8.3 IPv6 Address Types

```
Global Unicast:    2000::/3  (currently 2001::-3fff::)
  Globally unique, routable on the internet
  Equivalent to public IPv4 addresses

Link-Local:        fe80::/10
  Only valid on a single link (subnet)
  Automatically configured on every IPv6-capable interface
  Used for NDP (Neighbour Discovery Protocol — IPv6 ARP replacement)
  NOT routable beyond the local link

Unique Local:      fc00::/7  (currently fd00::/8 in practice)
  Equivalent to RFC 1918 private addresses
  Routable within an organisation, not on the internet

Loopback:          ::1/128
  Equivalent to 127.0.0.1

Multicast:         ff00::/8
  No broadcast in IPv6 — broadcast replaced with multicast
  ff02::1 = all nodes on link
  ff02::2 = all routers on link
  ff02::1:ff00:0/104 = solicited-node multicast (used by NDP)

IPv4-Mapped:       ::ffff:0:0/96
  Represents IPv4 addresses in IPv6 notation
  ::ffff:192.168.1.1 = 192.168.1.1 in IPv6 format
```

### 8.4 IPv6 Security — The Hidden Attack Surface

**Dual-stack networks:**
Most modern operating systems enable IPv6 by default. Even if the network administrator has not configured IPv6, the operating system will autoconfigure a link-local address (fe80::/10) and may configure a global address via SLAAC (Stateless Address Autoconfiguration) if a router is advertising IPv6 prefixes.

This creates a hidden attack surface:

```
Scenario:
  Administrator: "We run IPv4 only, our firewall rules are IPv4"
  Reality: All Windows, Linux, macOS machines have IPv6 enabled
           If any machine has a global IPv6 address, it may be
           directly reachable from the IPv6 internet
           without going through the IPv4 firewall

Check IPv6 on Linux:
ip -6 addr show                         # All IPv6 addresses
ip -6 route show                        # IPv6 routing table
cat /proc/net/if_inet6                  # All IPv6 interfaces

Check IPv6 on Windows:
ipconfig | findstr /i "IPv6"
netsh interface ipv6 show addresses
```

**NDP — Neighbour Discovery Protocol:**
NDP is IPv6's replacement for ARP. It uses ICMPv6 messages instead of a dedicated protocol.

```
NDP messages:
  ICMPv6 Type 133: Router Solicitation (RS) — "Is there a router?"
  ICMPv6 Type 134: Router Advertisement (RA) — "I am a router, here are params"
  ICMPv6 Type 135: Neighbour Solicitation (NS) — "Who has this IPv6 address?"
  ICMPv6 Type 136: Neighbour Advertisement (NA) — "I have this IPv6 address"
  ICMPv6 Type 137: Redirect — "Use a better route"

NDP has the same fundamental vulnerability as ARP: no authentication.
NDP spoofing is the IPv6 equivalent of ARP spoofing.
```

**Rogue Router Advertisement (RA) attacks:**
An attacker can send fake Router Advertisements to:
- Redirect traffic through the attacker's machine (default route hijacking)
- Configure a malicious DNS server on victim machines
- Perform MITM on all IPv6 traffic

```bash
# Tools for IPv6 attacks:
# THC-IPv6 toolkit (pre-installed on Kali)

# Send rogue RA to assign attacker's machine as default gateway:
sudo atk6-fake_router6 eth0 2001:db8::/64

# IPv6 NDP spoofing:
sudo parasite6 eth0                     # NDP responder (like arpspoof for IPv6)

# Detect rogue RAs:
sudo radvd --debug                      # Monitor for unexpected RAs
# Or in Wireshark: icmpv6.type == 134   (Router Advertisement)
# Unexpected RAs from non-router MACs are suspicious
```

**IPv6 scanning:**
The IPv6 address space is so large that random scanning is impractical. But attackers use:
- Multicast addresses (ff02::1 reaches all hosts on the link without knowing individual addresses)
- SLAAC-based addresses are often predictable (EUI-64 format embeds the MAC address)
- DNS enumeration for IPv6 AAAA records

```bash
# Discover IPv6 hosts on local link using multicast
ping6 -I eth0 ff02::1                   # Ping all nodes multicast
# Captures responses from all IPv6-enabled hosts on the link

# Nmap IPv6 scan
sudo nmap -6 -sV 2001:db8::1           # Single IPv6 host
sudo nmap -6 --script ipv6-multicast-mld-list eth0  # Discover via multicast

# Check for AAAA records (IPv6 DNS)
dig AAAA google.com
host -t AAAA google.com
```

> **Key Insight:** IPv4 addresses are nearly exhausted and IPv6 deployment is accelerating. More importantly, IPv6 is already running on most enterprise systems — often unmonitored and unmanaged. An attacker who pivots to IPv6 on a dual-stack network may find a completely undefended path. Every network assessment must include IPv6 enumeration, and every security architecture must account for IPv6 traffic.

---

## 9. ICMP — The Network's Diagnostic Layer

### 9.1 What ICMP Is

ICMP (Internet Control Message Protocol, RFC 792) runs directly over IP (protocol number 1) and provides network diagnostic and error reporting functions. It has no ports and cannot be used for application data transfer.

ICMP is essential for network operation, but it is also one of the most abused protocols in offensive security.

### 9.2 ICMP Message Types

```
Type  Code  Name                           Security Relevance
─────────────────────────────────────────────────────────────────
0     0     Echo Reply                     Ping response — host is up
3     0     Destination Unreachable        
      0     Net Unreachable                Routing problem
      1     Host Unreachable               Host down or firewalled
      2     Protocol Unreachable           Protocol not supported
      3     Port Unreachable               No service on UDP port
      4     Fragmentation Needed           MTU path discovery
      9     Dest. Network Admin. Prohibit  Firewall block (ACL)
      10    Dest. Host Admin. Prohibit     Firewall block
      13    Comm. Admin. Prohibited        Firewall block
5     0     Redirect Datagram for Net      Route manipulation attack
      1     Redirect Datagram for Host     Route manipulation attack
8     0     Echo Request                   Ping — host discovery
11    0     Time Exceeded (TTL)            Traceroute mechanism
      0     TTL exceeded in transit        Traceroute hop
      1     Fragment reassembly timeout    Fragmentation issue
12    0     Parameter Problem              Malformed packet
13    0     Timestamp Request              OS fingerprinting
14    0     Timestamp Reply
17    0     Address Mask Request           Network enumeration (deprecated)
18    0     Address Mask Reply
```

### 9.3 ICMP in Host Discovery and Network Mapping

```bash
# Ping — ICMP Echo Request (Type 8) / Echo Reply (Type 0)
ping -c 4 192.168.1.1               # 4 pings
ping -c 1 -W 1 192.168.1.1          # Single ping, 1 second timeout
ping -b 192.168.1.255               # Broadcast ping (may reveal all hosts)

# Ping sweep — discover live hosts
# Nmap ICMP ping sweep:
sudo nmap -sn -PE 192.168.1.0/24   # ICMP Echo ping sweep
sudo nmap -sn -PP 192.168.1.0/24   # ICMP Timestamp ping sweep (bypasses some firewalls)
sudo nmap -sn -PM 192.168.1.0/24   # ICMP Address Mask ping sweep

# fping — parallel ping for faster sweeps
sudo apt install fping
fping -a -g 192.168.1.0/24 2>/dev/null  # -a = show alive, -g = generate range

# Traceroute — uses ICMP TTL exceeded responses
traceroute -n 8.8.8.8               # -n = no DNS resolution
traceroute -I 8.8.8.8               # ICMP mode (default is UDP on Linux)
traceroute -T -p 80 8.8.8.8         # TCP traceroute to port 80

# How traceroute works:
# Packet 1: TTL=1 → first router decrements to 0 → ICMP Type 11 back
# Packet 2: TTL=2 → first router: TTL-1=1, second router: TTL-1=0 → ICMP Type 11
# ...continues until destination reached (ICMP Echo Reply or ICMP Port Unreachable)
```

### 9.4 ICMP Attack Techniques

**Ping of Death (historical, CVE-1996-nnnn):**
An IPv4 packet can theoretically carry up to 65,535 bytes of data (2^16 -1 total length). An ICMP Echo Request with 65,507 bytes of payload (65,535 - 20 IP header - 8 ICMP header) is valid. However, this is larger than the maximum Ethernet frame, so it gets fragmented. On many older implementations, the reassembled packet caused a buffer overflow in the kernel's reassembly buffer — crashing or blue-screening the system. Patched in all modern OSes but still relevant for legacy embedded systems (some OT devices).

**Smurf Attack (historical but documented):**
Attacker sends ICMP Echo Request to a network's broadcast address with spoofed source IP (victim's IP). All hosts on the network reply to the victim. Amplification ratio = number of hosts on the network.

```
10 hosts on network + broadcast ping = 10× amplification
1,000 hosts on network = 1,000× amplification

Mitigation: 
  ISPs should block directed broadcast (RFC 2644)
  Hosts should not respond to broadcast pings
  sysctl net.ipv4.icmp_echo_ignore_broadcasts=1 (Linux default)
```

**ICMP Redirect Attack:**
ICMP Type 5 allows a router to tell a host "use a different gateway for this specific destination." The host updates its routing table.

```
Attack:
  Attacker sends ICMP Redirect: "For destination 8.8.8.8, use gateway 192.168.1.50 (attacker)"
  Victim host adds route: 8.8.8.8 via 192.168.1.50
  All traffic to 8.8.8.8 now goes to attacker first

Defence:
  Disable ICMP redirect acceptance:
  sysctl -w net.ipv4.conf.all.accept_redirects=0
  sysctl -w net.ipv4.conf.all.secure_redirects=0
  
  Verify:
  cat /proc/sys/net/ipv4/conf/all/accept_redirects  # 0 = disabled
```

**ICMP Tunnelling:**
ICMP Echo Request and Reply packets can carry arbitrary data in their payload. An attacker can encapsulate any TCP/IP traffic inside ICMP packets to bypass firewalls that allow ICMP but block direct TCP/UDP.

```
Normal ping payload: 32 bytes (on Windows) or 56 bytes (on Linux)
Attack: Use full 65,507 bytes of ICMP payload to tunnel data

Detection:
- ICMP packets with large payloads (>100 bytes for Echo)
- ICMP packets with unusual payload content (not repeating patterns)
- High-frequency ICMP traffic from a single host
- ICMP traffic at non-ping timing patterns

Tools: icmptunnel, ptunnel, ICMPTX

# Detect large ICMP payloads in Wireshark:
# Filter: icmp and data.len > 100

# Or with tcpdump:
sudo tcpdump -i eth0 'icmp and greater 150'   # ICMP packets > 150 bytes
```

### 9.5 ICMP Firewall Behaviour and Fingerprinting

When a firewall blocks a connection, the type of ICMP response (if any) reveals the firewall's configuration:

```
Port response analysis:
  SYN → SYN-ACK:    Port open
  SYN → RST:        Port closed (no service)
  SYN → no response: Port filtered (firewall DROP rule — silent discard)
  SYN → ICMP Type 3 Code 13: Port administratively prohibited (firewall REJECT rule)

The difference between DROP and REJECT:
  DROP:   Firewall silently discards packet → attacker doesn't know if host is up
  REJECT: Firewall sends ICMP error → tells attacker the host exists
  
  DROP is generally preferred from a security perspective (reveals less)
  REJECT is preferred from a usability perspective (faster failure, clearer error)
```

```bash
# Nmap output interpretation:
# open: SYN-ACK received
# closed: RST received
# filtered: no response or ICMP unreachable received

# Identify firewall policy (DROP vs REJECT):
sudo nmap -sS --reason 192.168.1.1
# "no-response" = DROP policy
# "admin-prohibited" = REJECT policy with ICMP Type 3 Code 13
# "reset" = no firewall, closed port

# Time-based differentiation:
# DROP: Nmap waits for timeout (slow)
# RST: Immediate response (fast)
# Compare scan timing — slow = DROP policy
```

---

## 10. ARP — Address Resolution Protocol

### 10.1 What ARP Does and Why It Has No Security

ARP (RFC 826, 1982) resolves IPv4 addresses to MAC addresses. Before sending an IP packet, a device must know the MAC address of the next hop (the destination if on the same subnet, or the gateway if not).

RFC 826 is 7 pages long. It was written in 1982 when the internet consisted of researchers who trusted each other. There is no authentication, no verification, no cryptographic integrity. Any device can claim any IP-to-MAC mapping, and other devices will believe it. This was not an oversight — it was an acceptable design decision at the time.

Forty years later, this design decision is responsible for some of the most common network attacks in existence.

### 10.2 ARP Operation

```
ARP Request (broadcast):
  Source: 192.168.1.5 (MAC: AA:BB:CC:DD:EE:FF)
  Wants to reach: 192.168.1.1
  Doesn't know: 192.168.1.1's MAC address
  
  Sends Ethernet broadcast (dst: FF:FF:FF:FF:FF:FF):
  "Who has 192.168.1.1? Tell 192.168.1.5 (AA:BB:CC:DD:EE:FF)"
  
  All devices on the segment receive this.
  Only 192.168.1.1 should respond.

ARP Reply (unicast):
  Source: 192.168.1.1 (MAC: 11:22:33:44:55:66)
  Sends directly to 192.168.1.5:
  "192.168.1.1 is at 11:22:33:44:55:66"

ARP Cache:
  Receiving device stores this mapping in ARP cache
  Linux default: 60-second TTL with garbage collection
  Windows default: 15-30 second reachable timeout, up to 45-90 seconds stale
  
  View ARP cache:
  arp -a                              # Linux/Windows
  ip neigh show                       # Linux (modern)
```

**Gratuitous ARP:**
A device can send an unsolicited ARP reply announcing its own IP-to-MAC mapping. This is used for:
- Updating the ARP cache of all neighbours after NIC replacement
- Announcing a new IP address
- High-availability failover (sending gratuitous ARP to update switches after failover)

Gratuitous ARP is the mechanism that makes ARP poisoning possible — any device can announce any mapping, and others accept it without question.

### 10.3 ARP Poisoning Attack — Full Technical Detail

```
Network:
  Gateway:        192.168.1.1  (MAC: GW:GW:GW:GW:GW:GW)
  Victim A:       192.168.1.10 (MAC: AA:AA:AA:AA:AA:AA)
  Victim B:       192.168.1.20 (MAC: BB:BB:BB:BB:BB:BB)
  Attacker:       192.168.1.50 (MAC: AT:AT:AT:AT:AT:AT)

Attack:
  Attacker sends to 192.168.1.10:
    "192.168.1.1 is at AT:AT:AT:AT:AT:AT"  (lie about gateway MAC)
    
  Attacker sends to 192.168.1.1:
    "192.168.1.10 is at AT:AT:AT:AT:AT:AT" (lie about victim MAC)

Result on 192.168.1.10's ARP cache:
  BEFORE: 192.168.1.1 → GW:GW:GW:GW:GW:GW ✓
  AFTER:  192.168.1.1 → AT:AT:AT:AT:AT:AT  ← POISONED

Traffic flow:
  192.168.1.10 sends packet to "gateway" (AT:AT:AT:AT:AT:AT)
  Attacker receives it, reads it (MITM), forwards to real gateway
  Response returns via same path (attacker also poisoned gateway's ARP)
  
Attacker sees all traffic between victim and gateway.
With IP forwarding enabled, communication continues normally — 
victim has no indication of the attack.
```

```bash
# ARP poisoning tools:

# arpspoof (dsniff package) — classic tool
sudo arpspoof -i eth0 -t 192.168.1.10 192.168.1.1
# -t = target (who to poison)
# last argument = IP to impersonate
# This sends gratuitous ARPs to 192.168.1.10 claiming 192.168.1.1's IP

# For bidirectional MITM, run two arpspoof instances:
sudo arpspoof -i eth0 -t 192.168.1.10 192.168.1.1 &
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.10 &
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward  # Enable forwarding

# Bettercap — modern, comprehensive
sudo bettercap -iface eth0
# In bettercap console:
# net.probe on              # Discover hosts
# arp.spoof.targets 192.168.1.10,192.168.1.20  # Target specific hosts
# arp.spoof on              # Start poisoning
# net.sniff on              # Capture traffic

# Ettercap — all-in-one MITM
sudo ettercap -T -q -M arp:remote /192.168.1.1// /192.168.1.10//
# -T = text mode, -q = quiet, -M = MITM mode arp:remote
```

### 10.4 Detecting and Mitigating ARP Attacks

**Detection:**

```bash
# arpwatch — monitors ARP activity, alerts on changes
sudo apt install arpwatch
sudo arpwatch -i eth0               # Run and log to syslog
# Alerts on: new station, changed ethernet address, flip-flop (rapid MAC changes)

# Manual detection — look for duplicate IP with different MAC:
ip neigh show | awk '{print $1}' | sort | uniq -c | sort -rn
# Multiple entries for same IP = suspicious

# Wireshark detection:
# Edit → Find Packet → Packet Details → ARP
# Look for: "duplicate use of <IP> detected"
# Wireshark automatically alerts on duplicate IP-to-MAC mappings

# Detect in Python:
python3 << 'EOF'
from scapy.all import sniff, ARP
from collections import defaultdict

ip_mac_map = defaultdict(set)

def detect_arp_spoofing(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP Reply
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        ip_mac_map[ip].add(mac)
        if len(ip_mac_map[ip]) > 1:
            print(f"[!] ARP POISONING DETECTED: {ip} claimed by MACs: {ip_mac_map[ip]}")

print("Monitoring ARP traffic...")
sniff(filter="arp", prn=detect_arp_spoofing, store=0)
EOF
```

**Mitigation:**

```
1. Dynamic ARP Inspection (DAI) — Cisco switch feature
   Switch maintains DHCP snooping binding table (IP→MAC→Port→VLAN)
   Validates ARP packets against binding table
   Drops ARP packets that don't match
   Prevents ARP poisoning from untrusted ports
   
   Cisco configuration:
   ip dhcp snooping vlan 10
   ip arp inspection vlan 10
   interface GigabitEthernet0/1
    ip dhcp snooping limit rate 15    # Limit DHCP to 15 pps
   interface GigabitEthernet0/2
    ip arp inspection trust           # Trust this port (uplink to router)

2. Static ARP entries
   Add critical mappings (gateway) as permanent static entries:
   arp -s 192.168.1.1 GW:GW:GW:GW:GW:GW
   ip neigh add 192.168.1.1 lladdr GW:GW:GW:GW:GW:GW dev eth0 nud permanent
   
   Limitation: manual maintenance, doesn't scale

3. 802.1X Port Authentication
   Authenticates devices before granting network access
   Combined with DAI: only authenticated devices can poison ARP

4. Private VLANs
   Prevents communication between hosts in the same subnet
   No direct L2 access between clients → no ARP poisoning possible

5. End-to-end encryption (TLS)
   Even if ARP is poisoned and traffic intercepted,
   TLS prevents reading or modifying the content
   This is why ARP poisoning + SSL stripping requires both steps
```

### 10.5 ARP in OT/ICS Networks

ARP poisoning in OT environments is particularly dangerous because:

1. **No encryption:** Modbus, DNP3, and other industrial protocols transmit in plaintext. An ARP MITM gives complete visibility into and control over industrial protocol traffic.

2. **No authentication:** Writing to a Modbus register or sending a DNP3 command requires only network access. ARP poisoning provides that access.

3. **No security monitoring:** Most OT networks have no ARP inspection, no arpwatch, no DAI. ARP poisoning can run undetected indefinitely.

4. **Physical consequences:** A MITM position on an OT network allows:
   - Passive: Monitoring of all process values and setpoints
   - Active: Modification of commands sent to PLCs
   - Denial of service: Dropping commands to field devices

5. **Legacy switches:** Many OT environments use unmanaged switches. DAI requires managed switches. Unmanaged switches cannot enforce port security.

> **Key Insight:** ARP's complete lack of authentication is not a vulnerability that will be patched — it is the protocol as designed, and replacing it would require replacing the entire Ethernet ecosystem. DAI and 802.1X are the correct mitigations, but they require managed infrastructure. In their absence, every device on the same L2 segment can impersonate every other device. In OT environments where this is combined with unauthenticated industrial protocols, a single compromised or rogue device has full control over the physical process.

---

## 11. Putting It All Together — A Complete Packet's Journey

### 11.1 The Full Stack in Motion

To solidify all concepts in this module, trace a complete DNS query from a workstation to Google's DNS server.

```
Workstation: 192.168.1.5 (MAC: WS:WS:WS:WS:WS:WS)
Gateway:     192.168.1.1 (MAC: GW:GW:GW:GW:GW:GW)
Target DNS:  8.8.8.8
Query:       "What is the IP of example.com?"

STEP 1: Does workstation know gateway's MAC?
  Check ARP cache: 192.168.1.1 → ?
  If not found: Send ARP broadcast "Who has 192.168.1.1?"
  Gateway replies: "192.168.1.1 is at GW:GW:GW:GW:GW:GW"
  ARP cache updated.

STEP 2: Construct DNS UDP packet

  Application layer builds DNS query:
    DNS header + question: A record for "example.com"

  Transport layer adds UDP header:
    Source port: 54321 (ephemeral)
    Destination port: 53 (DNS)
    Length: [calculated]
    Checksum: [calculated]

  Internet layer adds IP header:
    Source IP: 192.168.1.5
    Destination IP: 8.8.8.8
    TTL: 64 (Linux default)
    Protocol: 17 (UDP)

  Network Access layer adds Ethernet header:
    Destination MAC: GW:GW:GW:GW:GW:GW (gateway — not 8.8.8.8, different subnet)
    Source MAC: WS:WS:WS:WS:WS:WS
    EtherType: 0x0800 (IPv4)

STEP 3: Frame sent on wire to gateway

STEP 4: Gateway receives frame
  Layer 2: Is dst MAC mine? Yes → accept
  Layer 3: Is dst IP mine? No (8.8.8.8 is not 192.168.1.1)
  → Route packet toward 8.8.8.8
  → Build new Ethernet frame with next hop's MAC
  → Decrement TTL (now 63)
  → Send out WAN interface

STEP 5: Packet traverses internet (multiple hops, TTL decrements)

STEP 6: 8.8.8.8 receives packet
  DNS server processes query
  Constructs response
  Response travels back (same process in reverse)

STEP 7: Gateway receives response, routes to workstation
  ARP resolves 192.168.1.5 → WS:WS:WS:WS:WS:WS
  Forwards frame

STEP 8: Workstation receives response
  UDP → port 54321 → DNS resolver → application
  Application knows: example.com → 93.184.216.34
```

---

## 12. TCP/IP in OT/ICS Environments

### 12.1 TCP/IP Adoption in Industrial Networks

Modern OT networks increasingly use standard TCP/IP. This brings interoperability benefits but also exposes industrial systems to the full TCP/IP threat landscape.

**Protocols that run over TCP/IP in OT:**

```
Modbus TCP:      TCP 502    — No authentication, direct register access
DNP3:            TCP/UDP 20000 — Limited authentication (SA v5)
EtherNet/IP:     TCP 44818, UDP 2222 — CIP over Ethernet
IEC 60870-5-104: TCP 2404   — Power grid SCADA
IEC 61850 MMS:   TCP 102    — Substation automation
OPC-UA:          TCP 4840   — Modern, has security model
PROFINET:        TCP/UDP (various) — Siemens fieldbus over Ethernet
BACnet/IP:       UDP 47808  — Building automation
```

### 12.2 TCP/IP Attacks Specific to OT Context

**Fragmentation attacks against PLCs:**
Industrial devices often have limited resources and may not handle malformed or fragmented IP packets correctly. Sending fragmented packets (Teardrop-style, overlapping offsets) can crash PLCs or cause them to restart.

```bash
# Fragmentation attack simulation (lab only):
sudo hping3 --frag --data 1000 --mtu 8 192.168.1.100
# --frag = fragment packets
# --data = payload size
# --mtu = force fragmentation at this size
# Result: 8-byte fragments → many overlap scenarios possible
```

**TCP RST injection against SCADA HMI connections:**
If an attacker can observe the sequence numbers of an active TCP connection between an HMI and a SCADA server, they can inject RST packets to terminate the connection. This disrupts operator visibility.

**ARP poisoning + Modbus command injection:**
The most dangerous combined attack:
1. ARP poison: Position attacker between HMI and PLC
2. Intercept: Capture legitimate Modbus TCP commands
3. Modify or inject: Change setpoints, force coil states, or replay commands

```python
# Conceptual Modbus command interception using Scapy (educational):
from scapy.all import *
from scapy.contrib.modbus import ModbusADURequest

# In a real attack scenario (authorized lab only):
# ARP poisoning positions attacker in path
# Then capture and modify Modbus TCP traffic passing through

def inspect_modbus(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].dport == 502:
        print(f"Modbus command from {pkt[IP].src} to {pkt[IP].dst}")
        # Payload is the Modbus ADU
        if pkt.haslayer(Raw):
            data = bytes(pkt[Raw])
            if len(data) >= 8:
                func_code = data[7]
                print(f"  Function code: {func_code} ({hex(func_code)})")

sniff(filter="tcp port 502", prn=inspect_modbus, store=0)
```

### 12.3 TCP/IP Security Controls for OT

```
Priority 1 — Network Segmentation:
  OT network MUST be isolated from IT network
  Use: dedicated firewall, DMZ for data exchange
  Not acceptable: direct routing between IT and OT VLANs
  
Priority 2 — Protocol Whitelisting:
  Firewall between zones should only allow specific OT protocols
  Allow: Modbus TCP (502) from HMI IPs to PLC IPs ONLY
  Block: All other traffic by default
  Log: All denied traffic for anomaly detection
  
Priority 3 — IP Addressing:
  Use RFC1918 addresses not routable from internet
  Separate OT subnets from IT subnets (different /24 ranges)
  Document all static IP assignments
  
Priority 4 — ARP/NDP Monitoring:
  Deploy arpwatch or commercial OT asset monitoring (Claroty, Nozomi)
  Alert on any ARP changes in OT network
  OT networks change slowly — any ARP change is suspicious
  
Priority 5 — Encrypted Management:
  Use SSH instead of Telnet for device management
  Use SNMPv3 instead of v1/v2c
  Disable HTTP management, use HTTPS
  VPN with MFA for remote access
```

---

## 13. Hands-On Exercises

### Exercise 1: TCP Handshake Analysis (45 minutes)

```bash
# Capture a complete TCP session and analyse every field

# Start capture — focus on HTTP (unencrypted for full visibility)
sudo tcpdump -i eth0 -w /tmp/tcp_session.pcap 'host neverssl.com and port 80'

# In another terminal:
curl -v http://neverssl.com/ 2>&1 | head -30

# Stop capture (Ctrl+C in tcpdump terminal)

# Open in Wireshark:
wireshark /tmp/tcp_session.pcap

# Tasks:
# 1. Find the SYN packet — what is the client's ISN?
#    Filter: tcp.flags.syn==1 and tcp.flags.ack==0
#
# 2. Find the SYN-ACK — what is the server's ISN?
#    What TCP options does the server advertise?
#    Filter: tcp.flags.syn==1 and tcp.flags.ack==1
#
# 3. Find the final ACK — verify: ack = server_ISN + 1
#
# 4. Find the HTTP GET request
#    What sequence number does it start with?
#    How large is the payload?
#    Filter: http.request
#
# 5. Find the FIN packets — count the four-way termination
#    Filter: tcp.flags.fin==1
#
# 6. Statistics → TCP Stream Graph → Time Sequence (tcptrace)
#    Visualise the sequence numbers over time

# Command-line analysis with tshark:
tshark -r /tmp/tcp_session.pcap -Y "tcp" -T fields \
    -e frame.time_relative \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport \
    -e tcp.flags \
    -e tcp.seq \
    -e tcp.ack \
    -e tcp.window_size_value
```

### Exercise 2: ARP Analysis and Simulation (1 hour)

```bash
# Part 1: Capture and analyse normal ARP
sudo tcpdump -i eth0 -n 'arp' -v &   # Background capture
sleep 2
ping -c 1 $(ip route | grep default | awk '{print $3}')   # Ping gateway (triggers ARP)
sleep 2
kill %1

# Analyse:
# - What was the ARP request? (broadcast to FF:FF:FF:FF:FF:FF)
# - What was the ARP reply?
# - What EtherType identifies ARP?
# - What is the difference in packet size between request and reply?

# Part 2: Examine your ARP cache
ip neigh show
# For each entry, note:
# - IP address
# - Device (interface)
# - MAC address
# - State: REACHABLE/STALE/DELAY/PROBE/FAILED

# Part 3: Write an ARP detection script
cat > /tmp/arp_monitor.py << 'EOF'
#!/usr/bin/env python3
"""
ARP Monitor — detect MAC address changes indicating ARP poisoning
"""
from scapy.all import sniff, ARP, Ether
from collections import defaultdict
import time

ip_mac_map = {}

def process_arp(pkt):
    if pkt.haslayer(ARP):
        if pkt[ARP].op == 2:  # ARP Reply (is-at)
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            timestamp = time.strftime('%H:%M:%S')
            
            if ip in ip_mac_map:
                if ip_mac_map[ip] != mac:
                    print(f"[{timestamp}] [ALERT] ARP CHANGE DETECTED!")
                    print(f"  IP: {ip}")
                    print(f"  OLD MAC: {ip_mac_map[ip]}")
                    print(f"  NEW MAC: {mac}")
                    print(f"  Possible ARP poisoning attack!")
                else:
                    print(f"[{timestamp}] [OK] {ip} → {mac} (unchanged)")
            else:
                ip_mac_map[ip] = mac
                print(f"[{timestamp}] [NEW] {ip} → {mac}")

print("ARP monitor started. Watching for MAC changes...")
sniff(filter="arp", prn=process_arp, store=0)
EOF
chmod +x /tmp/arp_monitor.py
sudo python3 /tmp/arp_monitor.py
```

### Exercise 3: IPv4 Subnetting Practice (30 minutes)

```bash
# Use Python to build intuition for subnetting:
python3 << 'EOF'
import ipaddress

# Common subnetting scenarios in security:

# 1. Given an IP and subnet, find all hosts:
net = ipaddress.ip_network("10.10.10.0/24", strict=False)
print(f"Network: {net}")
print(f"Total addresses: {net.num_addresses}")
print(f"Usable hosts: {net.num_addresses - 2}")
print(f"First host: {list(net.hosts())[0]}")
print(f"Last host: {list(net.hosts())[-1]}")
print(f"Broadcast: {net.broadcast_address}")

# 2. Determine if two IPs are on the same subnet:
ip1 = ipaddress.ip_interface("192.168.1.50/24")
ip2 = ipaddress.ip_interface("192.168.1.100/24")
ip3 = ipaddress.ip_interface("192.168.2.50/24")
print(f"\n{ip1.ip} and {ip2.ip} same network? {ip1.network == ip2.network}")
print(f"{ip1.ip} and {ip3.ip} same network? {ip1.network == ip3.network}")

# 3. Summarise a list of addresses (useful for firewall rules):
addresses = [
    "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4",
    "10.0.0.5", "10.0.0.6", "10.0.0.7"
]
addr_objects = [ipaddress.ip_address(a) for a in addresses]
summary = list(ipaddress.collapse_addresses(addr_objects))
print(f"\nSummarised {len(addresses)} IPs into {len(summary)} range(s):")
for s in summary:
    print(f"  {s}")

# 4. Split a network into subnets (useful for network design):
big_net = ipaddress.ip_network("192.168.0.0/22")
subnets = list(big_net.subnets(new_prefix=24))
print(f"\n/22 split into /24 subnets:")
for s in subnets:
    print(f"  {s} — {s.num_addresses - 2} hosts")
EOF
```

### Exercise 4: ICMP Recon and Detection (30 minutes)

```bash
# ICMP-based network reconnaissance:

# 1. Host discovery using different ICMP types
sudo nmap -sn -PE 192.168.1.0/24    # Echo Request (standard ping)
sudo nmap -sn -PP 192.168.1.0/24    # Timestamp Request (Type 13)
sudo nmap -sn -PM 192.168.1.0/24    # Address Mask Request (Type 17)
# Compare results — some hosts respond to some types but not others

# 2. Traceroute analysis
mtr --report --report-cycles 5 8.8.8.8
# Save output and analyse:
# - Which hops have 100% packet loss? (ICMP Type 11 not returned — not necessarily down)
# - Which hops have variable latency? (congestion)
# - Where does the TTL drop occur geographically? (infer location from latency)

# 3. Detect and block ICMP tunnel attempts
# ICMP tunnels use large payloads — detect with:
sudo tcpdump -i eth0 'icmp and (icmp[icmptype] = icmp-echo or icmp[icmptype] = icmp-echoreply) and length > 200'

# 4. Block ICMP redirect acceptance (hardening):
sudo sysctl net.ipv4.conf.all.accept_redirects          # Check current
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0     # Disable
sudo sysctl -w net.ipv4.conf.all.secure_redirects=0     # Disable even from gateways
sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1   # Disable broadcast ping response
```

---

## 14. Module Summary

| Topic | Core Mechanism | Attack Relevance | Defence |
|-------|---------------|-----------------|---------|
| **TCP/IP Model** | 4-layer encapsulation | Every attack traverses the stack | Defence must cover all layers |
| **TCP** | Reliable, ordered, connection-oriented byte stream | SYN flood, session hijacking, RST injection, port scanning | SYN cookies, stateful firewalls, randomised ISN |
| **UDP** | Connectionless, unreliable, low overhead | Amplification DDoS, IP spoofing, loose firewall bypass | BCP38, rate limiting, stateful UDP tracking |
| **TCP Handshake** | SYN→SYN-ACK→ACK establishes bidirectional ISN exchange | SYN flood exploits half-open state | SYN cookies defer state allocation |
| **TCP Termination** | FIN→ACK→FIN→ACK graceful close | TIME_WAIT exhaustion, RST injection | RST validation, TIME_WAIT tuning |
| **TCP Internals** | Sliding window, congestion control, keepalive | Zero-window DoS, ACK throttling | Tune keepalive, monitor window behaviour |
| **IPv4** | 32-bit hierarchical addressing | IP spoofing, ICMP attacks, fragmentation attacks | BCP38, fragment reassembly at border |
| **Special ranges** | RFC1918, APIPA, loopback, multicast | AWS metadata (169.254.169.254) SSRF, internal recon | Firewall cloud metadata endpoints |
| **CIDR/Subnetting** | Variable-length prefix for network/host split | Network enumeration, scope determination | Minimal subnet sizes, VLAN isolation |
| **NAT** | Port-based translation of private to public IP | Hides internal network topology, C2 bypasses NAT | Logging NAT translations for forensics |
| **IPv6** | 128-bit addressing, NDP, multicast-based | Rogue RA attacks, NDP spoofing, bypasses IPv4-only security | RA Guard, dual-stack firewalling, disable unused IPv6 |
| **ICMP** | Network diagnostic and error reporting | Ping of Death, Smurf, ICMP redirect, ICMP tunnel | Drop/rate-limit ICMP, disable redirects, detect large payloads |
| **ARP** | L2 IP-to-MAC resolution, no authentication | ARP poisoning → MITM → intercept plaintext protocols | DAI, arpwatch, 802.1X, static critical entries |

---

> **Next Module:** [Stage 1.4 — IP Addressing and Subnetting](./stage-1.4-ip-addressing-subnetting.md)  
> **Previous Module:** [Stage 1.2 — OSI Model](./stage-1.2-osi-model.md)  
> **Series Index:** [Full Roadmap](../../README.md)

---

*This document is part of the Cybersecurity × OT/ICS Security Full Roadmap series. All techniques are presented for educational purposes, authorised security research, and defensive security practice. Always obtain proper authorisation before testing any system.*