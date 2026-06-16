# Stage 2.2 — Cryptography Fundamentals
### From Zero to Cybersecurity Professional | Complete Roadmap Series

> **Series:** Cybersecurity × OT/ICS Security — Full Roadmap  
> **Stage:** 2 — Cybersecurity Core  
> **Module:** 2.2 — Cryptography Fundamentals  
> **Level:** Beginner → Advanced  
> **Prerequisites:** Stage 2.1 — Core Security Concepts  
> **Next Module:** 2.3 — Identity and Access Management

---

## Table of Contents

1. [Why Cryptography Is the Bedrock of All Digital Security](#1-why-cryptography-is-the-bedrock-of-all-digital-security)
2. [What Is Encryption — First Principles](#2-what-is-encryption--first-principles)
3. [Encoding vs Encryption vs Hashing](#3-encoding-vs-encryption-vs-hashing)
4. [Symmetric Encryption — AES, DES, 3DES, Blowfish](#4-symmetric-encryption--aes-des-3des-blowfish)
5. [Asymmetric Encryption — RSA, ECC, Diffie-Hellman](#5-asymmetric-encryption--rsa-ecc-diffie-hellman)
6. [Hash Functions — MD5, SHA-1, SHA-256, SHA-3](#6-hash-functions--md5-sha-1-sha-256-sha-3)
7. [Salt and Pepper — Password Hashing](#7-salt-and-pepper--password-hashing)
8. [Digital Signatures](#8-digital-signatures)
9. [PKI — Public Key Infrastructure](#9-pki--public-key-infrastructure)
10. [SSL/TLS — How Secure Connections Work](#10-ssltls--how-secure-connections-work)
11. [TLS Handshake — Deep Dive](#11-tls-handshake--deep-dive)
12. [Cryptographic Randomness](#12-cryptographic-randomness)
13. [Steganography](#13-steganography)
14. [Cryptography in OT/ICS Environments](#14-cryptography-in-otics-environments)
15. [Module Summary](#15-module-summary)

---

## 1. Why Cryptography Is the Bedrock of All Digital Security

Every security control that matters depends on cryptography. HTTPS exists because of TLS. Password storage is only safe because of hashing. Code signing, SSH, VPN, MFA apps, email signing, blockchain, digital certificates, secure boot — every one of these is cryptography applied to a specific problem. When cryptography breaks, everything built on it breaks simultaneously.

**Concrete failures with massive real-world consequences:**

**MD5 Collision Attack → Rogue CA Certificate (2008):** MD5 was known to be weak, but CAs still used it to sign certificates. Researchers at CWI Amsterdam and others demonstrated that MD5's collision vulnerability could be exploited to create a rogue Certificate Authority certificate indistinguishable from a legitimate one. Any HTTPS connection could be silently intercepted. The entire HTTPS trust system — protecting every bank, government, and healthcare site — was compromised by a 30-year-old hash function that nobody had bothered to replace.

**RSA 512-bit factored → FREAK attack (CVE-2015-0204):** "Export grade" cryptography mandated by 1990s US government regulations required weak RSA (512-bit) for exports. Attackers could factor 512-bit keys in hours using cloud computing and downgrade victims to export cipher suites. HTTPS connections to affected servers (including major banks and US government websites) could be decrypted.

**Heartbleed (CVE-2014-0160):** Not a cryptographic break, but a bug in OpenSSL's heartbeat extension that exposed 64KB of server memory per request — including private keys. When a private key is compromised, all past TLS sessions encrypted with that key (if not using Perfect Forward Secrecy) can be decrypted. Every certificate using the compromised key must be revoked and reissued. 17% of all secure web servers were affected simultaneously.

**DUHK (Don't Use Hard-coded Keys, 2017):** Some VPN implementations used a hardcoded seed value for their random number generator, making it possible to predict all encryption keys. A weak PRNG is as devastating as no encryption — the mathematics are correct, but the key material is predictable.

**For OT/ICS:** Industrial protocols from the 1980s-2000s (Modbus, DNP3 baseline, PROFIBUS) have no cryptography whatsoever — no authentication, no integrity, no confidentiality. IEC 62351 was developed specifically to add cryptographic security to these protocols, but adoption remains low. Understanding cryptography tells you exactly why a Modbus write command can be forged by anyone on the network and what it would take to prevent it.

---

## 2. What Is Encryption — First Principles

### 2.1 The Core Concept

Encryption transforms readable data (plaintext) into unreadable data (ciphertext) using a mathematical algorithm and a key. Only parties possessing the correct key can reverse the process (decryption) to recover the plaintext.

```
Encryption:
  Plaintext + Key + Algorithm → Ciphertext
  "Hello"  + "K"  + AES      → "x7Kp2mQ9..."
  
Decryption:
  Ciphertext + Key + Algorithm → Plaintext
  "x7Kp2mQ9..." + "K" + AES   → "Hello"

The algorithm (cipher) is typically PUBLIC — Kerckhoffs's principle:
  "A cryptosystem should be secure even if everything about the
   system, except the key, is public knowledge."
  
  Rationale: If security depends on algorithm secrecy ("security through
  obscurity"), once the algorithm is discovered (and it will be), all
  security is lost. Security must come from key secrecy alone.
  
  Corollary: Proprietary/secret encryption algorithms are a red flag.
  They haven't been publicly scrutinised — they are almost certainly weaker
  than publicly reviewed standards like AES.
```

### 2.2 The Mathematics of Security

Encryption security is based on mathematical problems that are easy to perform in one direction but computationally infeasible to reverse without the key.

```
Easy vs Hard Problems in Cryptography:

Symmetric (AES):
  Hard problem: Given ciphertext, find key without the key
  Security: Exhaustive search (brute force) of keyspace
  AES-128: 2^128 possible keys = 3.4 × 10^38 keys
  At 10^18 guesses/second: 1.07 × 10^13 years (longer than universe age)
  
Asymmetric (RSA):
  Hard problem: Integer Factorisation
  Given N = p × q (product of two large primes), find p and q
  Easy: multiply 2 large primes (milliseconds)
  Hard: factor the product (currently infeasible for 2048-bit)
  
Asymmetric (ECC):
  Hard problem: Elliptic Curve Discrete Logarithm Problem (ECDLP)
  Given P and Q = k×P (on an elliptic curve), find k
  Currently infeasible for 256-bit curves
  
  Key insight: 256-bit ECC ≈ 3072-bit RSA in security level
  ECC keys are much shorter for equivalent security
  
Hash Functions:
  Hard problem: Finding a collision or preimage
  Given H(x), find x (preimage resistance)
  Given H(x), find x' where H(x') = H(x) (second preimage)
  Find any x, x' where H(x) = H(x') (collision resistance)
```

### 2.3 Key Length and Security Levels

```
NIST Recommended Key Sizes (2024):

Security Level  Symmetric  RSA/DH  ECC
──────────────────────────────────────────────────
80-bit          2TDEA       1024    160 (MINIMUM — deprecated)
112-bit         3TDEA       2048    224 (acceptable transitional)
128-bit         AES-128     3072    256 (recommended minimum)
192-bit         AES-192     7680    384
256-bit         AES-256    15360    521

"Security level" = approximate bits of work for best known attack

Future threat — Quantum Computing:
  Shor's algorithm breaks RSA and ECC entirely (exponential speedup)
  Grover's algorithm halves symmetric key security (128-bit → 64-bit effective)
  
  Post-Quantum Cryptography (PQC) — NIST finalists (2024):
  CRYSTALS-Kyber: Key encapsulation (replaces RSA/ECDH)
  CRYSTALS-Dilithium: Digital signatures (replaces RSA/ECDSA)
  FALCON: Digital signatures
  SPHINCS+: Hash-based signatures (no quantum threat to hash functions)
  
  Timeline: quantum computers capable of breaking RSA-2048 estimated 10-20 years
  Harvest now, decrypt later: attackers capturing encrypted traffic today
  to decrypt when quantum computers become available
  → "Cryptographically relevant quantum computer" (CRQC) threat
```

---

## 3. Encoding vs Encryption vs Hashing

These three are routinely confused. The confusion has security consequences.

```
┌─────────────────┬──────────────────────────┬──────────────┬────────────────────┐
│                 │ Purpose                  │ Reversible?  │ Key Required?      │
├─────────────────┼──────────────────────────┼──────────────┼────────────────────┤
│ ENCODING        │ Format conversion        │ YES (trivial)│ NO                 │
│                 │ for transmission         │              │                    │
├─────────────────┼──────────────────────────┼──────────────┼────────────────────┤
│ ENCRYPTION      │ Confidentiality          │ YES (with key)│ YES               │
│                 │ (hide data from          │              │                    │
│                 │ unauthorised parties)    │              │                    │
├─────────────────┼──────────────────────────┼──────────────┼────────────────────┤
│ HASHING         │ Integrity verification   │ NO           │ NO                 │
│                 │ (one-way fingerprint)    │ (by design)  │                    │
└─────────────────┴──────────────────────────┴──────────────┴────────────────────┘
```

### 3.1 Encoding

Encoding converts data from one format to another for compatibility or transmission purposes. It provides **zero security** — it is trivially reversed by anyone.

```
Common encodings:

Base64:
  Converts binary to printable ASCII
  Used: email attachments (MIME), HTTP Basic Auth, JWT tokens, data URIs
  "Hello" → "SGVsbG8="
  
  NOT encryption — security implication:
  "Authorization: Basic YWRtaW46cGFzc3dvcmQ=" in HTTP header
  Base64 decode → admin:password (instant)
  
URL Encoding (Percent Encoding):
  Converts special characters for URL safety
  "Hello World" → "Hello%20World"
  "/" → "%2F"
  
  Security: URL encoding bypass of WAFs/filters
  /etc/passwd → /%65%74%63/%70%61%73%73%77%64
  Some WAFs decode only once; double-encoded input bypasses them
  
ASCII/Unicode:
  Character ↔ number mapping
  'A' = 65 = 0x41
  No security provided
  
Hex encoding:
  Binary → hexadecimal representation
  0x48 0x65 0x6C 0x6C 0x6F = "Hello"
  
ROT13:
  Caesar cipher (rotate letters 13 positions)
  NOT encryption — symmetric but trivially reversed
  Used as "spoiler protection", never for security
```

```bash
# Encoding demonstrations:

# Base64 encode/decode:
echo "admin:password" | base64                    # Encode: YWRtaW46cGFzc3dvcmQ=
echo "YWRtaW46cGFzc3dvcmQ=" | base64 -d          # Decode: admin:password

# URL encode/decode with Python:
python3 -c "
import urllib.parse
# Encode
encoded = urllib.parse.quote('/etc/passwd')
print('Encoded:', encoded)   # %2Fetc%2Fpasswd

# Double encode (WAF bypass technique)
double = urllib.parse.quote(encoded)
print('Double:', double)    # %252Fetc%252Fpasswd
"

# Hex encode/decode:
echo "Hello" | xxd -p                              # Hex encode: 48656c6c6f0a
echo "48656c6c6f" | xxd -r -p                      # Hex decode: Hello

# Detect encoding in captured traffic:
echo "SGVsbG8gV29ybGQ=" | base64 -d               # Check if it's base64
echo "48656c6c6f" | python3 -c "import sys; print(bytes.fromhex(sys.stdin.read().strip()).decode())"
```

### 3.2 The Critical Security Distinction

```
Most common security mistake: treating encoding as encryption

Example — "stored encoded" passwords (wrong!):
  Password: "SecretPass123"
  Stored as: base64("SecretPass123") = "U2VjcmV0UGFzczEyMw=="
  Security provided: ZERO
  If database is breached: echo "U2VjcmV0UGFzczEyMw==" | base64 -d → SecretPass123
  
Correct approach:
  Password: "SecretPass123"
  Stored as: bcrypt("SecretPass123") = "$2b$12$LKJSD...."
  Security: computationally infeasible to reverse
  If database is breached: hashes must be cracked (expensive)

Example — "encoded" API credentials in source code:
  API_KEY = base64.encode("ak_prod_12345secret")
  Developers think this hides the key in code
  Anyone who reads the code: decode → plaintext key
  Correct: environment variables, secrets management (Vault, AWS Secrets Manager)
```

---

## 4. Symmetric Encryption — AES, DES, 3DES, Blowfish

### 4.1 How Symmetric Encryption Works

Symmetric encryption uses the **same key** for encryption and decryption. The key must be shared between sender and receiver through a secure channel — the "key distribution problem."

```
Symmetric Encryption Flow:

  Alice                              Bob
    │                                 │
    │ Encrypt with shared key K       │
    │ "Hello" + K → "x7Kp2mQ9..."   │
    │                                 │
    │ ─── Ciphertext ───────────────→ │
    │     (safe to send publicly)     │
    │                                 │
    │                 Decrypt with K  │
    │                 "x7Kp2mQ9..." + K → "Hello"
    
Key distribution problem:
  How do Alice and Bob share key K securely?
  If they're communicating for the first time over an insecure channel:
  Sending K over the channel → attacker intercepts K → can decrypt everything
  
Solution: Use asymmetric encryption to exchange the symmetric key
  (this is exactly what TLS does — see Section 10)
```

### 4.2 Block Ciphers vs Stream Ciphers

```
Block Ciphers:
  Process data in fixed-size blocks (64-bit, 128-bit)
  Examples: AES (128-bit blocks), DES (64-bit blocks)
  Must handle data that isn't exactly block-size → padding
  Mode of operation determines security properties
  
Stream Ciphers:
  Process data one bit/byte at a time
  Examples: RC4 (broken), ChaCha20 (modern, secure)
  No padding needed
  More efficient for streaming data
  Crucial: NEVER reuse the same key+nonce combination
           Reuse → XOR ciphertexts → plaintext recovered
```

### 4.3 Block Cipher Modes of Operation

The mode of operation transforms a block cipher into a complete encryption scheme. Different modes have radically different security properties.

```
ECB (Electronic Codebook) — NEVER USE:
  Each block encrypted independently with same key
  Same plaintext block → same ciphertext block
  
  Security failure:
  Block 1: "Hello Wor" → "x7Kp2mQ9"
  Block 2: "Hello Wor" → "x7Kp2mQ9"  (IDENTICAL — reveals pattern)
  
  The Linux Penguin (ECB mode image encryption):
  Encrypt a bitmap image of a penguin with AES-ECB
  The outline of the penguin is still visible in the ciphertext
  Because identical pixel blocks produce identical ciphertext blocks
  ECB is broken for any data with patterns (text, images, structured data)

CBC (Cipher Block Chaining) — Common, requires care:
  Each block XOR'd with previous ciphertext before encryption
  Requires Initialization Vector (IV) for first block
  IV must be random and unique per message
  
  Vulnerabilities:
  - Padding oracle attacks (POODLE, CBC padding oracle)
  - IV reuse → information leakage
  - CBC decryption is parallelisable, encryption is not
  
CTR (Counter Mode) — Recommended:
  Uses block cipher as pseudo-random generator
  Counter value encrypted, XOR'd with plaintext
  Transforms block cipher into stream cipher
  Encryption AND decryption are parallelisable
  Random access within ciphertext possible
  
GCM (Galois/Counter Mode) — Best practice:
  CTR mode + Galois Message Authentication Code (GMAC)
  Provides both confidentiality AND integrity/authentication
  "Authenticated encryption with associated data" (AEAD)
  
  This is what TLS 1.3 uses: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
  
  Critical: GCM nonce must NEVER be reused with the same key
  Nonce reuse in GCM → authentication key revealed → all security lost
```

### 4.4 AES — Advanced Encryption Standard

AES (Rijndael algorithm, selected by NIST 2001) is the gold standard for symmetric encryption. Understanding how it works illuminates why it is secure.

```
AES Specifications:
  Block size: 128 bits (16 bytes) — ALWAYS
  Key sizes: 128, 192, or 256 bits
  Rounds: 10 (AES-128), 12 (AES-192), 14 (AES-256)
  
AES Internal Structure — Substitution-Permutation Network:

State: 4×4 matrix of bytes (128 bits)
┌──┬──┬──┬──┐
│b0│b4│b8│b12│
│b1│b5│b9│b13│
│b2│b6│b10│b14│
│b3│b7│b11│b15│
└──┴──┴──┴──┘

Each round (except last) applies four operations:

1. SubBytes: each byte replaced by substitute from S-box (256-entry lookup table)
   Provides non-linearity (without this, AES would be linear algebra — trivially broken)

2. ShiftRows: row i is shifted i bytes to the left
   Row 0: unchanged
   Row 1: [b1,b5,b9,b13] → [b5,b9,b13,b1]
   Row 2: [b2,b6,b10,b14] → [b10,b14,b2,b6]
   Row 3: [b3,b7,b11,b15] → [b15,b3,b7,b11]
   Provides diffusion across columns

3. MixColumns: each column multiplied by a matrix in GF(2^8)
   Provides diffusion — one input bit affects multiple output bytes

4. AddRoundKey: XOR state with round key (derived from original key via key schedule)

Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns)
Key schedule: original key expanded into 11 (AES-128) or 15 (AES-256) round keys

Security: No known attacks significantly better than brute force against AES itself
          All known vulnerabilities are implementation-level (timing attacks, cache attacks)
```

### 4.5 DES — Data Encryption Standard

DES (IBM/NIST, 1977) was the dominant encryption standard for 20 years. It is now completely broken.

```
DES Specifications:
  Block size: 64 bits (8 bytes)
  Key size: 56 bits (actually 64 bits, 8 are parity bits)
  Rounds: 16 (Feistel network)
  
Why DES is broken:
  56-bit key = 2^56 = 72 quadrillion possible keys
  1998: EFF's "Deep Crack" machine cracked DES in 22 hours for $250,000
  2008: FPGA cluster cracked DES in 6.4 days for $10,000
  2012: Cloud computing: DES crackable in hours for ~$100
  Today: DES cracked in minutes on commodity hardware
  
DES Attacks:
  - Brute force: 2^56 key search (trivial with modern hardware)
  - Differential cryptanalysis: theoretical attacks requiring 2^47 chosen plaintexts
  - Linear cryptanalysis: requires 2^43 known plaintexts
  - Neither more practical than brute force — brute force is already practical
  
Do not use DES for any purpose.
```

### 4.6 3DES (Triple DES)

3DES applies DES three times to extend effective key length.

```
3DES Variants:
  DES-EEE3: Encrypt-Encrypt-Encrypt with 3 different keys (168-bit key, 112-bit security)
  DES-EDE3: Encrypt-Decrypt-Encrypt with 3 different keys (most common, "Triple DES")
  DES-EDE2: Encrypt-Decrypt-Encrypt with 2 different keys (K1=K3, 112-bit key, 80-bit security)

Why 3DES doesn't give 168-bit security:
  Meet-in-the-Middle attack reduces DES-EDE3 to ~112 bits of security
  Still exponentially better than single DES
  
Problems with 3DES:
  - 64-bit block size → "birthday bound" problem
  - After 2^32 blocks (~32 GB), collisions become likely
  - SWEET32 attack (CVE-2016-2183): exploits 64-bit block birthday bound
    to recover plaintext from long-lived TLS sessions using 3DES
  - Only ~112 bits of security (not 168)
  - MUCH slower than AES (3× DES operations per block)
  
NIST deprecated 3DES in 2017 (allowed until 2023, disallowed after)
3DES is still found in: legacy payment systems (PCI-DSS grace period),
old TLS configurations, mainframe systems
```

### 4.7 Blowfish and Twofish

```
Blowfish (Bruce Schneier, 1993):
  Block size: 64 bits (same birthday-bound problem as DES/3DES)
  Key size: 32-448 bits (variable)
  Design: public domain, no patent
  
  Security: No known significant vulnerabilities against Blowfish itself
  Problem: 64-bit block size (SWEET32 applies)
  Use: bcrypt password hashing algorithm uses modified Blowfish (Eksblowfish)
       bcrypt is still recommended for passwords — Blowfish-derived, not raw Blowfish
  
  Do not use raw Blowfish for data encryption today.
  
Twofish (Schneier et al., 1998):
  AES finalist (lost to Rijndael in 2001 selection)
  Block size: 128 bits (no birthday-bound problem)
  Key size: 128, 192, 256 bits
  Public domain, no patent
  Still considered secure — no known practical attacks
  Less deployed than AES (lost the competition)
  Available in: TrueCrypt/VeraCrypt, GPG, some TLS configurations
```

```bash
# Symmetric encryption in practice:

# AES-256-GCM encryption with OpenSSL:
openssl enc -aes-256-gcm \
    -in plaintext.txt \
    -out encrypted.bin \
    -pass pass:"MySecretPassword" \
    -pbkdf2 \
    -iter 100000
# -aes-256-gcm: AES 256-bit in GCM mode (authenticated encryption)
# -pass pass: derive key from password
# -pbkdf2: use PBKDF2 key derivation (not simple MD5)
# -iter 100000: 100,000 iterations of PBKDF2 (makes brute force slower)

# Decryption:
openssl enc -d -aes-256-gcm \
    -in encrypted.bin \
    -out decrypted.txt \
    -pass pass:"MySecretPassword" \
    -pbkdf2 \
    -iter 100000

# AES in Python (cryptography library):
python3 << 'EOF'
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Generate random 256-bit key
key = os.urandom(32)              # 32 bytes = 256 bits

# Generate random 96-bit nonce (12 bytes — recommended for GCM)
nonce = os.urandom(12)

# Create AES-GCM cipher
aesgcm = AESGCM(key)

# Encrypt
plaintext = b"Secret message"
associated_data = b"authenticated but not encrypted metadata"
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
print(f"Ciphertext: {ciphertext.hex()}")
print(f"Length: {len(ciphertext)} bytes (plaintext + 16-byte auth tag)")

# Decrypt (will raise exception if tampered)
try:
    decrypted = aesgcm.decrypt(nonce, ciphertext, associated_data)
    print(f"Decrypted: {decrypted}")
except Exception as e:
    print(f"Authentication failed: {e}")  # Ciphertext was modified
EOF

# Check what cipher a TLS connection uses:
openssl s_client -connect google.com:443 2>/dev/null | grep "Cipher"
# Look for: AES-128-GCM or AES-256-GCM or CHACHA20-POLY1305

# Test if a server still supports broken ciphers:
nmap --script ssl-enum-ciphers -p 443 target.com | grep -E "DES|RC4|NULL|EXPORT"
# Any of these: immediately report — broken ciphers in use
```

> **Key Insight:** AES-256-GCM is the correct answer for symmetric encryption in 2024. The mode matters as much as the algorithm — AES-ECB is broken regardless of key length. GCM's built-in authentication tag (AEAD) means you get confidentiality and integrity in a single primitive. If you see DES, 3DES, RC4, or ECB mode anywhere in a production system, it is a vulnerability.

---

## 5. Asymmetric Encryption — RSA, ECC, Diffie-Hellman

### 5.1 The Key Exchange Problem — Why Asymmetric Cryptography Exists

Symmetric encryption has a fundamental problem: both parties must share the same key before they can communicate securely. How do you share a key securely with someone you've never met, over an insecure channel?

Asymmetric cryptography (public key cryptography) solves this by using mathematically related key pairs:
- **Public key:** can be shared with anyone
- **Private key:** kept secret, never shared

```
Key Pair Relationship:

  Private Key                Public Key
  ───────────               ─────────────
  Secret (never share)      Share freely
  Decrypts what public      Encrypts for private
  key encrypted             key holder
  Signs messages            Verifies signature
  
The magic: public and private keys are mathematically related
but it is computationally infeasible to derive the private key
from the public key (assuming the hard problems hold)

Analogy:
  Public key = padlock (anyone can lock)
  Private key = key to open the padlock
  
  You give your padlock to Alice
  Alice puts message in box, locks with your padlock
  Only you (private key holder) can open the padlock
```

### 5.2 RSA — Rivest-Shamir-Adleman

RSA (1977) is based on the difficulty of factoring large integers.

```
RSA Key Generation:
1. Choose two large prime numbers p and q (each ~1024-2048 bits)
2. Compute n = p × q (the modulus — public)
3. Compute φ(n) = (p-1)(q-1) (Euler's totient — secret)
4. Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
   (public exponent — usually 65537 = 2^16 + 1)
5. Compute d = e^(-1) mod φ(n) (private exponent)

Public key:  (n, e)
Private key: (n, d)  [also need p, q for efficient computation]

RSA Encryption (message M):
  Ciphertext C = M^e mod n

RSA Decryption:
  Message M = C^d mod n

Security: Given n, find p and q (integer factorisation)
  This is computationally hard for large n (2048+ bits)
  
RSA Key Sizes and Security:
  1024-bit: BROKEN (factorable since 2010, do not use)
  2048-bit: Currently secure minimum (recommended for legacy compat)
  3072-bit: Post-2030 recommendation
  4096-bit: High-security applications
```

**RSA Attack History:**

```
RSA-768 factored (2009): 768-bit RSA key factored using 30 years of CPU time
RSA-1024: Not yet factored but academic consensus: should not be used
ROCA vulnerability (CVE-2017-15361):
  Infineon Technologies RSA key generation library flaw
  Generated keys with detectable prime patterns
  Allowed factoring 1024-bit keys in <1 hour, 2048-bit in ~2 weeks
  Affected: YubiKey, TPM chips, smart cards
  1.25 billion keys potentially vulnerable

Bleichenbacher's attack (1998, recurring as ROBOT 2017):
  RSA PKCS#1 v1.5 padding oracle
  If server responds differently to valid vs invalid padding:
  Attacker can recover plaintext of RSA-encrypted messages
  Requires ~1 million queries to server
  Affected F5, Citrix, Cisco, Palo Alto and others in 2017
  ROBOT (Return Of Bleichenbacher's Oracle Threat) - 19 years after original
```

### 5.3 ECC — Elliptic Curve Cryptography

ECC is based on the algebraic structure of elliptic curves over finite fields.

```
Elliptic Curve:
  y² = x³ + ax + b (over a finite field GF(p))
  
  Standard curves (NIST):
  P-256 (secp256r1): 256-bit, 128-bit security
  P-384 (secp384r1): 384-bit, 192-bit security
  P-521 (secp521r1): 521-bit, 260-bit security
  
  Alternative curves (more trusted implementation properties):
  Curve25519: Ed25519 signatures, X25519 key exchange (preferred)
              Designed by Daniel Bernstein, no NIST involvement
              No concerns about NIST/NSA backdoor in curve parameters
              Used in: Signal, TLS 1.3 key exchange, SSH keys, WireGuard

ECC Key Exchange (ECDH — Elliptic Curve Diffie-Hellman):
  1. Alice generates private key a, computes public key A = a×G (G = generator point)
  2. Bob generates private key b, computes public key B = b×G
  3. Alice computes shared secret: S = a×B = a×(b×G) = (ab)×G
  4. Bob computes shared secret: S = b×A = b×(a×G) = (ab)×G
  Both get the same shared secret without ever transmitting it

ECC Signatures (ECDSA — Elliptic Curve Digital Signature Algorithm):
  Sign with private key, verify with public key
  Much shorter signatures than RSA for equivalent security:
  RSA-2048 signature: 256 bytes
  ECDSA-256 signature: 64 bytes

Advantage over RSA:
  256-bit ECC ≈ 3072-bit RSA in security
  Shorter keys = faster computation, less storage, smaller certificates
  TLS 1.3 exclusively uses ECDHE for key exchange (no RSA key exchange)
```

### 5.4 Diffie-Hellman Key Exchange

DH (1976) was the first public key exchange protocol published. It solves key distribution without ever transmitting the key.

```
Classic DH (finite field):

1. Public parameters: prime p, generator g (both public, known to everyone)

2. Alice: chooses secret a, computes A = g^a mod p (sends A to Bob)
3. Bob:   chooses secret b, computes B = g^b mod p (sends B to Alice)

4. Alice: computes S = B^a mod p = (g^b)^a mod p = g^(ab) mod p
5. Bob:   computes S = A^b mod p = (g^a)^b mod p = g^(ab) mod p

Both get the same S = g^(ab) mod p — the shared secret
Attacker sees: p, g, A=g^a mod p, B=g^b mod p
To find S: must solve discrete logarithm problem (find a from g^a mod p)
This is computationally hard for large p

DH Key Sizes:
  1024-bit: deprecated (Logjam attack showed feasibility of precomputation)
  2048-bit: minimum acceptable
  3072-bit: recommended

Ephemeral DH (DHE / ECDHE):
  New a, b generated for each session
  Provides: Perfect Forward Secrecy (PFS)
  If long-term key (private key) is compromised later:
  Past sessions cannot be decrypted (each had unique ephemeral keys)
  
  CRITICAL SECURITY PROPERTY:
  RSA key exchange (static): compromise private key → decrypt ALL past sessions
  ECDHE: compromise private key → can impersonate server, but past sessions safe
  
  TLS 1.3 mandates ECDHE — forward secrecy is no longer optional
```

```bash
# Asymmetric cryptography in practice:

# Generate RSA key pair:
openssl genrsa -out private.pem 4096           # Generate 4096-bit RSA private key
openssl rsa -in private.pem -pubout -out public.pem  # Extract public key

# View key details:
openssl rsa -in private.pem -text -noout | head -20
# Shows: modulus, public exponent (65537), private exponent, primes

# Generate ECC key pair (preferred):
openssl ecparam -name prime256v1 -genkey -noout -out ec_private.pem  # P-256
openssl ec -in ec_private.pem -pubout -out ec_public.pem
# Or use Curve25519 (preferred):
openssl genpkey -algorithm X25519 -out x25519_private.pem
openssl pkey -in x25519_private.pem -pubout -out x25519_public.pem

# RSA encrypt/decrypt:
echo "Secret message" > plaintext.txt
openssl rsautl -encrypt -inkey public.pem -pubin -in plaintext.txt -out encrypted.bin
openssl rsautl -decrypt -inkey private.pem -in encrypted.bin -out decrypted.txt
cat decrypted.txt

# Check a server's public key:
openssl s_client -connect google.com:443 2>/dev/null | \
    openssl x509 -noout -text | grep -E "Public Key Algorithm|Public-Key:"
# Shows: RSA 2048-bit or EC P-256 etc.

# Python - RSA encryption:
python3 << 'EOF'
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Generate 2048-bit RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Encrypt with public key (OAEP padding — correct padding scheme)
message = b"Secret message"
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print(f"Encrypted: {ciphertext[:20].hex()}... ({len(ciphertext)} bytes)")

# Decrypt with private key
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                 algorithm=hashes.SHA256(), label=None)
)
print(f"Decrypted: {plaintext}")
EOF
```

> **Key Insight:** RSA and ECC solve the key distribution problem but are NOT used to encrypt actual data at scale — they are too slow. In practice, asymmetric cryptography is used to securely exchange a symmetric key, which then encrypts the actual data. This hybrid approach (asymmetric for key exchange, symmetric for data encryption) is exactly how TLS works.

---

## 6. Hash Functions — MD5, SHA-1, SHA-256, SHA-3

### 6.1 What Hash Functions Are

A cryptographic hash function takes any input (any size) and produces a fixed-size output (digest/hash) with specific mathematical properties.

```
Hash Function Properties (required for security):

1. Deterministic: Same input → always same output
   hash("Hello") → always produces the same hash

2. Fixed Output Size: Regardless of input length
   hash("a") → 256 bits
   hash(entire_movie.mp4) → 256 bits (same length)

3. One-Way (Preimage Resistance):
   Given H, computationally infeasible to find M where hash(M) = H
   Cannot reverse the hash to get input

4. Second Preimage Resistance:
   Given M1, computationally infeasible to find M2 where hash(M1) = hash(M2)
   Cannot find a different input with the same hash

5. Collision Resistance:
   Computationally infeasible to find ANY M1, M2 where hash(M1) = hash(M2)
   (Note: collisions MUST exist — infinite inputs, finite outputs)
   But finding them should be computationally infeasible

6. Avalanche Effect: Small change → completely different output
   hash("Hello") → "2cf24d..."
   hash("hello") → "b94d27b9..."  (completely different — 1 bit change)
   This prevents any correlation between input and output
```

### 6.2 Hash Algorithms Comparison

```
Algorithm  Output   Status         Best Attack           Security
──────────────────────────────────────────────────────────────────────────────
MD5        128-bit  BROKEN         Collision: 2009       NONE for integrity
                                   (Flame malware used   DO NOT USE
                                   MD5 collision for
                                   code signing bypass)
SHA-1      160-bit  BROKEN         SHAttered (2017):     DO NOT USE
                                   Google/CWI computed   for security
                                   first SHA-1 collision purposes
                                   Cost: ~$100,000 GPU
SHA-224    224-bit  Deprecated     Theoretical only      Acceptable transitional
SHA-256    256-bit  SECURE         No practical attack    128-bit security
                                   known                  USE THIS
SHA-384    384-bit  SECURE         No practical attack    192-bit security
SHA-512    512-bit  SECURE         No practical attack    256-bit security
SHA-3-256  256-bit  SECURE         Different design       128-bit security
                                   from SHA-2 family     Use for diversity
BLAKE2b    512-bit  SECURE         No practical attack    256-bit security
                                                          Faster than SHA-3
BLAKE3     256-bit  SECURE         No practical attack    128-bit security
                                                          Fastest modern hash
```

### 6.3 MD5 — Broken

```
MD5 (Ronald Rivest, 1992):
  Output: 128-bit (32 hex characters)
  
Timeline of MD5's death:
  1993: Den Boer and Bosselaers: theoretical weaknesses found
  1996: Dobbertin: MD5 compression function collisions found (partial break)
  2004: Wang et al.: first full MD5 collisions computed
         Cost: hours on a laptop
  2005: Lenstra et al.: demonstrated MD5-based X.509 certificate collision
         Two different certificates with the same MD5 hash
  2008: CMU/Sotirov: rogue CA certificate using MD5 collision
         Created fraudulent intermediate CA certificate trusted by all browsers
         Full HTTPS impersonation of any website theoretically possible
  2012: Flame malware: used MD5 collision to forge Microsoft code-signing certificate
         Malware appeared to be legitimately signed by Microsoft
         Affected: Iranian nuclear programme (likely)

MD5 in security today:
  NEVER use for: passwords, digital signatures, certificates, any security purpose
  MAY use for: non-security file deduplication, non-security checksums
               (but SHA-256 is equally fast and secure — just use SHA-256)
  Found in: legacy systems, old configurations, some OT firmware update checks
```

### 6.4 SHA-1 — Broken

```
SHA-1 (NIST, 1995):
  Output: 160-bit (40 hex characters)
  
Timeline:
  2005: Xiaoyun Wang: theoretical collision attack (2^69 operations vs 2^80 ideal)
  2007: NIST recommends migration away from SHA-1
  2011: CA/Browser Forum: ban SHA-1 certificates after 2015
  2017: SHAttered attack (Google/CWI Amsterdam):
         First SHA-1 collision computed
         Two different PDF files with IDENTICAL SHA-1 hashes
         Cost: 9 quintillion SHA-1 computations = ~$100,000 in cloud computing
         Same PDF files have different content but same SHA-1 hash
         
  2020: Chosen-prefix collision: find collision given arbitrary prefixes
         More powerful than identical-prefix collision
         Cost reduced to ~$50,000
         
Impact of SHAttered:
  Git uses SHA-1 internally (aware, mitigations added: SHA-256 migration ongoing)
  Any SHA-1-based integrity check can potentially be bypassed
  
SHA-1 in security today:
  NEVER use for: digital signatures, certificates, TLS, code signing
  Legacy OT concern: many industrial firmware update mechanisms use SHA-1
                     for integrity verification — still vulnerable to SHAttered
                     type attacks on controlled devices
```

### 6.5 SHA-256 and SHA-3

```
SHA-256 (NIST, 2001) — Part of SHA-2 family:
  Output: 256-bit (64 hex characters)
  Internal structure: Merkle-Damgård construction with Davies-Meyer compression
  No practical attacks known
  Used in: Bitcoin, TLS, code signing, most modern security applications
  
SHA-3 (Keccak, NIST standardised 2015):
  Different internal structure from SHA-2 (sponge construction)
  Not vulnerable to length extension attacks (SHA-2 is)
  SHA-3-256 output: 256-bit
  Adoption: slower (SHA-2 still dominant)
  Use case: when diversity from SHA-2 is needed (defence against future SHA-2 attacks)
  
Length Extension Attack (SHA-2 weakness, not SHA-3):
  Given H(m) and len(m) but NOT m:
  Attacker can compute H(m || padding || extension) without knowing m
  
  Attack scenario:
  API: sign request with SHA-256(secret_key || request_params)
  Attacker: knows H(secret_key || "user=alice")
            Can compute H(secret_key || "user=alice" || padding || "&admin=true")
            Without knowing secret_key!
            
  Fix: use HMAC instead of raw hash for message authentication
  HMAC is not vulnerable to length extension attacks
```

```bash
# Hash function demonstrations:

# Calculate hashes of same file:
echo "Hello World" > test.txt
md5sum test.txt         # MD5: e59ff97941044f85df5297e1c302d260
sha1sum test.txt        # SHA1: 648a6a6ffffdaa0badb23b8baf90b6168dd16b3a
sha256sum test.txt      # SHA256: d2a84f4b8b650937ec8f73cd8be2c74add5a911ba64df27458ed8229da804a26
sha512sum test.txt      # SHA512: (128 hex chars)
b2sum test.txt          # BLAKE2b (package: b2sum)

# Verify file integrity (download verification):
wget https://example.com/software.tar.gz
wget https://example.com/software.tar.gz.sha256sum
sha256sum -c software.tar.gz.sha256sum
# "software.tar.gz: OK" = file not tampered

# Demonstrate avalanche effect:
python3 << 'EOF'
import hashlib

msg1 = b"Hello World"
msg2 = b"Hello world"  # Only capital W changed

h1 = hashlib.sha256(msg1).hexdigest()
h2 = hashlib.sha256(msg2).hexdigest()

print(f"SHA-256('Hello World'): {h1}")
print(f"SHA-256('Hello world'): {h2}")

# Count differing bits:
b1 = int(h1, 16)
b2 = int(h2, 16)
diff = bin(b1 ^ b2).count('1')
print(f"Differing bits: {diff} out of 256 ({diff/256*100:.1f}%)")
# Approximately 128 bits differ (50%) — avalanche effect
EOF

# Demonstrate MD5 collision (SHAttered file pair):
# Download the two PDF files that have same SHA-1:
# wget https://shattered.io/static/shattered-1.pdf
# wget https://shattered.io/static/shattered-2.pdf
# sha1sum shattered-1.pdf shattered-2.pdf  # IDENTICAL SHA-1
# sha256sum shattered-1.pdf shattered-2.pdf  # DIFFERENT SHA-256

# HMAC (keyed hash, MAC):
python3 -c "
import hmac, hashlib
key = b'secret_key'
message = b'user=alice&action=transfer&amount=1000'
mac = hmac.new(key, message, hashlib.sha256).hexdigest()
print(f'HMAC-SHA256: {mac}')
# Attacker cannot forge this without knowing the key
# Not vulnerable to length extension attacks
"
```

---

## 7. Salt and Pepper — Password Hashing

### 7.1 Why Naive Password Hashing Fails

Simply hashing passwords and storing the hash is insufficient protection. Two attacks defeat it:

```
Attack 1 — Rainbow Tables:
  Precompute hashes of millions of common passwords:
  MD5("password")  = "5f4dcc3b5aa765d61d8327deb882cf99"
  MD5("123456")    = "e10adc3949ba59abbe56e057f20f883e"
  MD5("admin")     = "21232f297a57a5a743894a0e4a801fc3"
  
  Breach database → look up hash in precomputed table → plaintext in milliseconds
  No computation needed — just lookup
  
  Countermeasure: Salt (makes precomputation impossible)

Attack 2 — Dictionary Attack:
  Hash common passwords and compare to stolen hashes
  For each candidate password: compute hash → compare
  GPU can compute billions of SHA-256 hashes per second
  
  Countermeasure: Slow hash functions (bcrypt, scrypt, Argon2)
```

### 7.2 Salt

A salt is a random value unique to each password, added before hashing.

```
WITHOUT SALT:
  User A: password "letmein" → SHA-256 → "b3fba..."
  User B: password "letmein" → SHA-256 → "b3fba..."
  
  Same password → same hash
  Attacker sees: User A and B have same hash → same password
  Crack one → crack both
  Rainbow table works: "b3fba..." → "letmein"

WITH SALT:
  User A: password "letmein" + salt "xK7mP2" → SHA-256 → "a1b2c3..."
  User B: password "letmein" + salt "9qRnL5" → SHA-256 → "z9y8x7..."
  
  Same password → DIFFERENT hashes (different salts)
  Attacker must crack each hash independently
  Rainbow tables are useless (different salt = different table needed per user)
  
  Salt must be:
  - Random (generated with CSPRNG)
  - Unique per password (even same user resetting password gets new salt)
  - Stored alongside the hash (not secret — attacker who gets DB gets salt too)
    But that's OK — salt defeats rainbow tables even when known
  - Long enough: 16+ bytes (128+ bits)

bcrypt (Blowfish-based, 1999):
  Incorporates salt automatically
  Output format: $2b$12$SALT22CHARS.HASH31CHARS
    $2b$ = bcrypt version
    12   = cost factor (2^12 rounds = 4096 iterations)
    next 22 chars = salt (128 bits)
    last 31 chars = hash
  
  Cost factor: controls speed (and therefore brute-force resistance)
  Higher cost = slower hash = more resistant to brute force
  Recommendation: choose cost factor so hashing takes 100-300ms
  Increase cost factor over time as hardware gets faster
  
Argon2 (Password Hashing Competition winner, 2015):
  Three variants:
  Argon2d: data-dependent, resists GPU cracking
  Argon2i: data-independent, resists side-channel attacks
  Argon2id: hybrid, RECOMMENDED for passwords
  
  Parameters: time cost, memory cost, parallelism
  Memory cost: makes hardware attacks (ASIC/GPU) expensive
  Argon2id(time=3, memory=64MB, parallel=4) recommended by OWASP (2024)
```

### 7.3 Pepper

A pepper is an additional secret value added to passwords before hashing, stored separately from the database (in application code, HSM, or configuration).

```
WITH SALT + PEPPER:
  password + salt + pepper → hash
  
  Storage:
  Database: salt + hash (attacker who breaches DB gets these)
  Application/HSM: pepper (attacker who only breaches DB doesn't have this)
  
  Even with: stolen database + knowing salt + knowing algorithm
  Attacker cannot crack without pepper
  Must also breach application server or HSM
  
  Pepper requirements:
  - HIGH entropy (256 bits random)
  - Different from the salt
  - Stored separately from the database (application config, HSM)
  - Never logged or exposed in error messages
  - Rotate with re-hashing (requires all users to re-authenticate)
  
Limitations:
  If attacker compromises BOTH database AND application server: both salt and pepper available
  Pepper is only effective if the attacker has access to ONE but not both
  
Combined: salt + pepper + slow hash (Argon2id or bcrypt) is the current gold standard
```

```bash
# Password hashing in practice:

# bcrypt in Python:
python3 << 'EOF'
import bcrypt
import time

password = b"UserPassword123!"
pepper = b"AppSecretPepper256BitRandom"  # Store in app config, not DB

# Hash (bcrypt handles salt automatically)
peppered = password + pepper
start = time.time()
hashed = bcrypt.hashpw(peppered, bcrypt.gensalt(rounds=12))
elapsed = time.time() - start
print(f"bcrypt hash: {hashed.decode()}")
print(f"Time to hash: {elapsed:.3f}s (should be ~100-300ms)")

# Verify:
is_valid = bcrypt.checkpw(peppered, hashed)
print(f"Password valid: {is_valid}")

# Wrong password:
wrong = b"WrongPassword" + pepper
is_valid = bcrypt.checkpw(wrong, hashed)
print(f"Wrong password valid: {is_valid}")  # False
EOF

# Argon2id in Python:
python3 << 'EOF'
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# OWASP recommended parameters
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)
# time_cost=3: 3 iterations
# memory_cost=65536: 64MB RAM (makes GPU/ASIC attacks expensive)
# parallelism=4: use 4 threads

password = "UserPassword123!"
pepper = "AppSecretPepper"

hash_val = ph.hash(password + pepper)
print(f"Argon2id hash: {hash_val[:50]}...")

# Verify:
try:
    ph.verify(hash_val, password + pepper)
    print("Password valid")
except VerifyMismatchError:
    print("Password invalid")
EOF

# Check what hash algorithm is used in /etc/shadow:
sudo cat /etc/shadow | head -3 | cut -d: -f2 | cut -c1-5
# $6$ = SHA-512 (acceptable for system use)
# $5$ = SHA-256
# $y$ = yescrypt (best, modern Linux default)
# $2b$ = bcrypt
# Blank or no $ = no password (check immediately!)

# Crack example hashes to understand speed difference:
# hashcat -m 0 hash.txt wordlist.txt        # MD5: billions/sec
# hashcat -m 3200 hash.txt wordlist.txt     # bcrypt: thousands/sec
# hashcat -m 1800 hash.txt wordlist.txt     # SHA-512crypt: millions/sec
# Speed difference: MD5 = 1,000,000× faster than bcrypt
# This is exactly why bcrypt for passwords matters
```

> **Key Insight:** Password storage security is not about using "a hash" — it is about using a purpose-built, slow password hashing function (Argon2id or bcrypt) with a random unique salt. SHA-256(password) is not password storage — it is broken password storage. The goal is to make brute forcing so slow that even a database breach yields no crackable passwords within an attacker's operational window.

---

## 8. Digital Signatures

### 8.1 What Digital Signatures Provide

A digital signature provides three guarantees simultaneously:
- **Authentication:** The message came from the claimed sender (they have the private key)
- **Integrity:** The message has not been modified since signing
- **Non-repudiation:** The sender cannot deny having sent it (only they have the private key)

```
Digital Signature Process:

SIGNING (sender with private key):
  Message M → Hash(M) → Sign with Private Key → Signature S
  Send: (M, S)
  
VERIFICATION (receiver with public key):
  Receive: (M, S)
  Compute: Hash(M) → H1
  Decrypt: S with Public Key → H2
  Verify:  H1 == H2?
    YES: signature valid (M not tampered, came from key holder)
    NO:  signature invalid (M modified, or wrong signer)

Why hash first?
  RSA can only sign data ≤ key size (2048 bits)
  Hash reduces any-size message to fixed output (256 bits for SHA-256)
  Sign the hash, not the message
  
  RSA-PSS (Probabilistic Signature Scheme) — correct:
  Uses random salt, provably secure, RECOMMENDED
  
  RSA-PKCS1v15 — legacy:
  Deterministic, older vulnerabilities, still widely used but avoid for new systems
  
  ECDSA (Elliptic Curve Digital Signature Algorithm):
  Based on ECC discrete log problem
  256-bit signature (much shorter than RSA-2048's 256-byte signature)
  Requires cryptographically random k value per signature
  
  Critical ECDSA vulnerability: k reuse
  If same k used twice with different messages:
  Private key can be recovered algebraically
  
  2010: PlayStation 3 used constant k in ECDSA → private key recovered
  2013: Android Bitcoin wallet ECDSA k reuse → keys stolen
```

### 8.2 Code Signing

```
Code Signing: applying digital signatures to software to verify authenticity

Windows Authenticode:
  Developer signs executable with private key (from certificate authority)
  Windows verifies signature before execution (if policy enforced)
  "Published by: Microsoft Corporation" with valid chain → trusted
  Self-signed → warning
  No signature → warning or block
  
  Attack: steal code signing certificate and private key
  Example: Stuxnet used stolen certificates from Realtek and JMicron
           to sign kernel drivers → bypassed Windows driver signing requirement
  
Linux Package Signing:
  Debian/Ubuntu: GPG signatures on packages + repository metadata
  RPM: GPG signatures on packages
  apt: verifies package signatures automatically
  
  Verify GPG signature:
  gpg --verify file.sig file
  
Certificate Transparency (CT):
  All publicly trusted TLS certificates must be logged to CT logs
  Allows monitoring for unexpected certificates for your domains
  Tools: crt.sh, certspotter, Google CT
  
SSH Host Key Verification:
  SSH server presents public key fingerprint
  Client verifies against known_hosts
  First connection: TOFU (Trust On First Use) — user must verify
```

```bash
# Digital signatures in practice:

# Sign a file with private key:
openssl dgst -sha256 -sign private.pem -out signature.bin document.txt

# Verify signature:
openssl dgst -sha256 -verify public.pem -signature signature.bin document.txt
# "Verified OK" = authentic and unmodified

# Sign with GPG:
gpg --gen-key                                    # Generate GPG key pair
gpg --sign --armor document.txt                  # Sign (creates document.txt.asc)
gpg --verify document.txt.asc document.txt       # Verify signature

# Python - sign and verify:
python3 << 'EOF'
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# Generate EC key pair (P-256)
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Sign message
message = b"This document is authentic"
signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
print(f"Signature: {signature.hex()[:40]}... ({len(signature)} bytes)")

# Verify - original message:
try:
    public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    print("Signature VALID")
except InvalidSignature:
    print("Signature INVALID")

# Verify - tampered message:
tampered = b"This document is authentic and has extra admin=true"
try:
    public_key.verify(signature, tampered, ec.ECDSA(hashes.SHA256()))
    print("Tampered signature VALID")  # Should never reach here
except InvalidSignature:
    print("Tampered message: Signature INVALID — tampering detected!")
EOF

# Check certificate signature:
openssl s_client -connect google.com:443 2>/dev/null | \
    openssl x509 -noout -text | grep -A3 "Signature Algorithm"
```

---

## 9. PKI — Public Key Infrastructure

### 9.1 The Problem PKI Solves

Asymmetric cryptography lets us encrypt to anyone with their public key. But how do you know that the public key claiming to be "google.com" actually belongs to Google and not an attacker?

PKI (Public Key Infrastructure) is the system of trust, policies, procedures, and technologies that manages digital certificates, binding public keys to verified identities.

```
The Man-in-the-Middle Problem:

Without PKI:
  Alice wants to connect to "bank.com"
  Attacker intercepts connection:
  Alice ←→ Attacker ←→ Bank
  Attacker sends own public key to Alice, claiming to be Bank
  Alice encrypts with attacker's key
  Attacker decrypts, re-encrypts with bank's real key
  Alice has no way to know she's talking to the attacker
  
With PKI:
  Bank has a certificate signed by a trusted Certificate Authority (CA)
  Certificate contains: Bank's public key + domain name + CA signature
  Alice's browser trusts the CA (comes pre-installed)
  Browser verifies: CA signature is valid → this public key belongs to bank.com
  Attacker cannot forge this — doesn't have CA's private key
```

### 9.2 Certificate Structure (X.509)

```
X.509 Certificate Fields:

Version:             3 (v3 is current)
Serial Number:       Unique identifier assigned by CA
Signature Algorithm: sha256WithRSAEncryption or ecdsa-with-SHA256
Issuer:              CA that signed this certificate
                     CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1
Validity:
  Not Before:        2024-01-01 00:00:00 UTC
  Not After:         2025-01-31 23:59:59 UTC
Subject:             Who this certificate belongs to
                     CN=*.google.com, O=Google LLC, C=US
Subject Public Key:  The actual public key (RSA or EC)
                     RSA 2048-bit or ECC P-256
Extensions:
  Subject Alternative Names (SANs): All domains covered
    DNS:*.google.com
    DNS:google.com
  Key Usage: Digital Signature, Key Encipherment
  Extended Key Usage: TLS Web Server Authentication
  Certificate Policies: https://pki.goog/repository/
  CRL Distribution Points: URL to check if certificate is revoked
  OCSP: URL for real-time revocation checking
  Certificate Transparency: SCT list (proof of CT log inclusion)
Signature: CA's signature over all of the above
```

### 9.3 Certificate Chain of Trust

```
PKI Trust Hierarchy:

Root CA (self-signed, highest trust)
  └── Intermediate CA (signed by Root CA)
        └── End-Entity Certificate (signed by Intermediate CA)
            (the certificate for google.com, for example)

Root CA:
  Stored in OS/browser trust stores (pre-installed)
  ~150 trusted root CAs in major browsers
  Private key extremely protected (offline, HSM, physical vault)
  Very rarely used directly (too valuable to risk)
  
Intermediate CA:
  Signed by root CA, issues end-entity certificates
  Private key stored in HSM (Hardware Security Module)
  If compromised: can be revoked without compromising root
  
End-Entity Certificate:
  Issued to the specific organisation/domain
  Short-lived (1 year max since 2020 for public TLS)
  
Chain validation:
  Browser validates end-entity cert is signed by intermediate CA
  Validates intermediate CA is signed by root CA
  Validates root CA is in trusted store
  Validates none are expired or revoked
  Validates domain name matches (SAN check)
```

### 9.4 Certificate Revocation

```
What if a private key is compromised? Certificate must be revoked.

CRL (Certificate Revocation List):
  List of revoked serial numbers, signed by CA, published periodically
  Browsers download CRL and check if certificate serial number is in it
  Problem: CRL can be large, infrequent updates, check often skipped
  
OCSP (Online Certificate Status Protocol):
  Real-time revocation check — query CA's OCSP responder per certificate
  Faster than CRL, smaller response
  Problem: Privacy (CA knows which sites you visit), performance, failure mode
  
OCSP Stapling:
  Server periodically fetches its own OCSP response from CA
  Includes ("staples") the response in TLS handshake
  Browser gets revocation status without contacting CA
  Best approach: solves privacy and performance
  
Revocation in practice (sadly):
  Browser failure to get CRL/OCSP response → typically ALLOW connection
  "Soft fail" = revocation checking provides minimal real protection
  Exception: Certificate Pinning — browser refuses connection if pin mismatch
  
CAA DNS Records:
  DNS record specifying which CAs may issue certificates for your domain
  example.com CAA 0 issue "letsencrypt.org"
  Prevents misissued certificates from unauthorised CAs
  Check: dig CAA yourdomain.com
```

```bash
# PKI and certificate analysis:

# View a server's full certificate chain:
openssl s_client -connect google.com:443 -showcerts 2>/dev/null | \
    grep -E "BEGIN|END|subject|issuer|Not"

# Check certificate details:
openssl s_client -connect google.com:443 2>/dev/null | \
    openssl x509 -noout -text | grep -E "Subject:|Issuer:|Not After|DNS:"

# Verify certificate chain:
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt certificate.pem

# Check OCSP status:
openssl s_client -connect google.com:443 -status 2>/dev/null | grep -A5 "OCSP"

# Check if certificate is about to expire (monitoring):
openssl s_client -connect target.com:443 2>/dev/null | \
    openssl x509 -noout -enddate | \
    awk -F= '{print $2}' | \
    xargs -I{} date -d "{}" +%s | \
    awk -v now=$(date +%s) '{days=($1-now)/86400; print "Expires in " int(days) " days"}'

# Monitor certificate changes (detect unexpected reissue):
openssl s_client -connect target.com:443 2>/dev/null | \
    openssl x509 -fingerprint -sha256 -noout
# Compare fingerprint over time — unexpected change = possible attack or cert rotation

# Certificate transparency monitoring (your domain):
curl -s "https://crt.sh/?q=yourdomain.com&output=json" | \
    python3 -c "
import json,sys
certs = json.load(sys.stdin)
for c in certs[:10]:
    print(c['not_before'][:10], c['name_value'], c['issuer_name'][:50])
"
# Review for unexpected certificates issued for your domain

# Generate self-signed certificate (for testing/internal use only):
openssl req -x509 -newkey rsa:4096 \
    -keyout private.pem \
    -out certificate.pem \
    -days 365 \
    -subj "/CN=localhost/O=Test/C=US" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

---

## 10. SSL/TLS — How Secure Connections Work

### 10.1 SSL to TLS Evolution

```
Timeline:
  SSL 1.0 (Netscape, 1994): Never released (serious flaws found)
  SSL 2.0 (1995):           Released, flaws found quickly
  SSL 3.0 (1996):           Still broken (POODLE 2014 — CVE-2014-3566)
  TLS 1.0 (1999):           RFC 2246, BEAST vulnerability (CVE-2011-3389)
  TLS 1.1 (2006):           Fixed BEAST, still has issues
  TLS 1.2 (2008):           Current acceptable standard
  TLS 1.3 (2018):           Current best practice, significant redesign

Deprecated (should not be used):
  SSL 2.0, SSL 3.0: COMPLETELY BROKEN, disable everywhere
  TLS 1.0, TLS 1.1: Deprecated by RFC 8996 (2021)
                    Chrome/Firefox removed support 2020
  
  Current standard: TLS 1.2 minimum, TLS 1.3 preferred
```

### 10.2 What TLS Provides

```
TLS provides a secure channel with three properties:

1. Confidentiality: All application data encrypted
   (Before TLS: plaintext visible to any network observer)
   
2. Integrity: Data cannot be modified without detection
   (HMAC or AEAD authentication tags detect any tampering)
   
3. Authentication: Server (and optionally client) identity verified
   (Via certificate chain validation)
   
What TLS does NOT protect:
  - Metadata: IP addresses, TCP ports, timing, volume
  - Server-side application vulnerabilities
  - The DNS lookup that led to the connection
  - Traffic analysis (size and timing patterns)
  - Certificate validity (user must check/browser must validate)

TLS components:
  Record Protocol: Fragments, compresses (deprecated), encrypts, MACs application data
  Handshake Protocol: Negotiates cipher suite, authenticates server, establishes keys
  Alert Protocol: Signals errors and close notifications
  Change Cipher Spec: Signals switch to negotiated cipher (TLS 1.2 only)
```

### 10.3 TLS Cipher Suites

```
TLS 1.2 Cipher Suite naming (verbose):
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

  TLS:         Protocol
  ECDHE:       Key Exchange (Elliptic Curve Diffie-Hellman Ephemeral — forward secrecy)
  RSA:         Authentication (certificate type — RSA cert verifies server identity)
  WITH:        Separator
  AES_256_GCM: Symmetric cipher (AES 256-bit in GCM mode)
  SHA384:      HMAC algorithm for integrity (for PRF function in TLS 1.2)

Components:
  Key Exchange: ECDHE > DHE > RSA (RSA key exchange has no forward secrecy — avoid)
  Auth:         ECDSA > RSA (for certificates)
  Cipher:       AES-GCM > AES-CBC (GCM is authenticated, CBC requires separate MAC)
  PRF/HMAC:     SHA-384 > SHA-256 > MD5/SHA-1 (avoid weak hashes)

TLS 1.3 cipher suites (simplified, only 5 allowed):
  TLS_AES_128_GCM_SHA256         (default, fast)
  TLS_AES_256_GCM_SHA384         (high security)
  TLS_CHACHA20_POLY1305_SHA256   (mobile/embedded — faster without AES-NI)
  TLS_AES_128_CCM_SHA256         (constrained environments)
  TLS_AES_128_CCM_8_SHA256       (very constrained IoT)
  
  Note: TLS 1.3 separates authentication (certificate) from key exchange
        No more RSA key exchange — only ECDHE or DHE
        All TLS 1.3 cipher suites have forward secrecy by default

Weak cipher suites to detect and disable:
  *_NULL_*:    No encryption (plaintext)
  *_EXPORT_*:  40/56-bit keys (FREAK/Logjam attack)
  *_RC4_*:     RC4 stream cipher (broken since 2013)
  *_DES_*:     56-bit DES (trivially cracked)
  *_3DES_*:    112-bit 3DES (SWEET32, slow)
  *_MD5:       MD5 MAC (broken)
  *_SHA:       SHA-1 MAC (weakened)
  *RSA_WITH_*: RSA key exchange (no forward secrecy)
  *_ANON_*:    Anonymous (no authentication — trivial MITM)
```

---

## 11. TLS Handshake — Deep Dive

### 11.1 TLS 1.2 Handshake

```
TLS 1.2 Full Handshake:

Client                                         Server
  │                                               │
  │──── ClientHello ───────────────────────────→  │
  │  Version: TLS 1.2                             │
  │  Random: 32 bytes (includes timestamp)        │
  │  Session ID: (for resumption)                 │
  │  Cipher Suites: [list of supported]           │
  │  Extensions: SNI, ALPN, elliptic curves...    │
  │                                               │
  │ ←── ServerHello ─────────────────────────── │
  │  Version: TLS 1.2                             │
  │  Random: 32 bytes                             │
  │  Session ID: (new or resumed)                 │
  │  Cipher Suite: SELECTED ONE                   │
  │                                               │
  │ ←── Certificate ─────────────────────────── │
  │  Server's X.509 certificate(s)               │
  │  [Full chain: end-entity + intermediates]     │
  │                                               │
  │ ←── ServerKeyExchange (if ECDHE/DHE) ─────  │
  │  DH parameters + server's DH public value    │
  │  Signed with server's private key            │
  │                                               │
  │ ←── ServerHelloDone ─────────────────────── │
  │                                               │
  │ Client validates:                             │
  │   Certificate chain → trusted CA             │
  │   Server hostname matches SAN                │
  │   Not expired, not revoked                   │
  │   ServerKeyExchange signature valid          │
  │                                               │
  │──── ClientKeyExchange ──────────────────────→ │
  │  Client's DH public value                    │
  │                                               │
  │  [Both compute: Pre-Master Secret from DH]   │
  │  [Both derive: Master Secret]                │
  │  [Both derive: 4 session keys from MS]       │
  │    client_write_key, server_write_key        │
  │    client_write_MAC, server_write_MAC        │
  │                                               │
  │──── ChangeCipherSpec ───────────────────────→ │
  │  "I'll now use the negotiated cipher"        │
  │                                               │
  │──── Finished (encrypted) ───────────────────→ │
  │  HMAC of entire handshake transcript         │
  │  Verifies nothing was tampered during setup  │
  │                                               │
  │ ←── ChangeCipherSpec ─────────────────────── │
  │ ←── Finished (encrypted) ─────────────────── │
  │                                               │
  │ ════════ Application Data (encrypted) ═══════ │
  
Total round trips: 2-RTT (2 full round trips before data flows)
This latency matters — TLS 1.3 reduces to 1-RTT
```

### 11.2 TLS 1.3 Handshake

```
TLS 1.3 Handshake — Redesigned for speed and security:

Client                                         Server
  │                                               │
  │──── ClientHello ───────────────────────────→  │
  │  Version: TLS 1.3                             │
  │  Random: 32 bytes                             │
  │  Cipher Suites: [TLS 1.3 only suites]        │
  │  key_share: Client's ECDH public key          │
  │  (Client guesses server's preferred group)    │
  │  supported_versions: [TLS 1.3, TLS 1.2...]   │
  │  pre_shared_key: (for 0-RTT resumption)       │
  │                                               │
  │  [Server can now compute handshake key]       │
  │  [Server begins encrypting immediately]       │
  │                                               │
  │ ←── ServerHello ─────────────────────────── │
  │  Version: TLS 1.3                             │
  │  key_share: Server's ECDH public key          │
  │  (Both now compute shared secret)             │
  │                                               │
  │ ←── {Certificate} ────────────────────────── │ ← Encrypted!
  │ ←── {CertificateVerify} ──────────────────── │ ← Encrypted!
  │  Signature over entire handshake transcript  │
  │ ←── {Finished} ────────────────────────────── │ ← Encrypted!
  │                                               │
  │ Client validates certificate (encrypted)     │
  │                                               │
  │──── {Finished} ─────────────────────────────→ │
  │                                               │
  │ ════════ Application Data (encrypted) ═══════ │
  
Key improvements in TLS 1.3:
  1-RTT: Faster by one full round trip (vs TLS 1.2's 2-RTT)
  0-RTT: Session resumption can send data in the first message
         (Security tradeoff: 0-RTT data not forward secret, replay risk)
  
  No more:
    RSA key exchange (eliminated — only ECDHE/DHE)
    CBC cipher suites (GCM and ChaCha20 only)
    MD5, SHA-1 in MAC (SHA-256 minimum)
    DH with <2048-bit primes
    Export cipher suites
    Session renegotiation (was a security issue in TLS 1.2)
    Compression (CRIME attack)
    
  Certificate and CertificateVerify now encrypted:
    In TLS 1.2, certificate was sent in plaintext → server identity visible to observer
    In TLS 1.3, certificate encrypted → privacy improvement
    
  Encrypted ClientHello (ECH) — draft standard:
    Extends encryption to ClientHello (SNI currently plaintext)
    When standardised: server hostname hidden from observer
```

### 11.3 TLS Attack Landscape

```
BEAST (CVE-2011-3389):
  Target: TLS 1.0 CBC mode
  Method: Chosen-boundary attack against CBC's predictable IV
  Impact: Decrypt HTTPS session cookies
  Fix: Use TLS 1.2+ (fixed IV handling), use RC4 (now broken too), AES-GCM
  
CRIME (CVE-2012-4929):
  Target: TLS compression (DEFLATE)
  Method: Compression oracle — inject guesses, observe size change
  Impact: Recover HTTPS cookies
  Fix: Disable TLS compression (disabled by default in all modern implementations)
  
POODLE (CVE-2014-3566):
  Target: SSL 3.0 CBC mode
  Method: Padding oracle after downgrade to SSL 3.0
  Impact: Decrypt session cookies
  Fix: Disable SSL 3.0 entirely, use TLS 1.2+
  
Heartbleed (CVE-2014-0160):
  Target: OpenSSL heartbeat extension (TLS extension)
  Method: Missing bounds check — request more data than sent
  Impact: Up to 64KB of server memory per request
          Exposed: private keys, session tickets, passwords, other secrets
  Fix: Patch OpenSSL (1.0.1g), reissue all certificates, rotate secrets
  
FREAK (CVE-2015-0204):
  Target: Export cipher suites (forced by 90s US regulations)
  Method: Force server to use RSA-EXPORT (512-bit) → factor in hours
  Impact: Decrypt HTTPS connections to affected servers
  Fix: Disable all EXPORT cipher suites
  
Logjam (CVE-2015-4000):
  Target: DHE-EXPORT (512-bit DH parameters)
  Method: Precompute discrete logarithm table for 512-bit primes
          NSA-scale attack feasible against 1024-bit primes
  Impact: Passive decryption of many HTTPS+VPN connections
  Fix: Minimum 2048-bit DH parameters, use ECDHE instead
  
ROBOT (2017):
  Target: RSA PKCS#1v1.5 padding in TLS
  Method: Bleichenbacher's 1998 oracle attack resurrected
          Server's different error responses for valid vs invalid padding
  Impact: Decrypt RSA-encrypted TLS sessions (if no forward secrecy)
  Affected: F5, Citrix, Cisco, Palo Alto, Radware, many others
  Fix: Constant-time RSA decryption, use ECDHE (no RSA key exchange)
```

```bash
# TLS security testing:

# Test TLS configuration comprehensively:
# testssl.sh (most comprehensive):
bash testssl.sh target.com:443

# Quick checks:
nmap --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-dh-params \
    -p 443 target.com

# Check supported TLS versions:
for version in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
    if openssl s_client -connect target.com:443 -$version 2>/dev/null | \
            grep -q "CONNECTED"; then
        echo "$version: SUPPORTED"
    else
        echo "$version: NOT supported"
    fi
done

# Check certificate details and chain:
openssl s_client -connect target.com:443 -showcerts 2>/dev/null | \
    openssl x509 -noout -text | grep -E "Not After|Signature Algorithm|Public-Key:"

# Decrypt TLS traffic (requires pre-master secret log):
export SSLKEYLOGFILE=/tmp/ssl_keys.log
curl https://target.com/api/data  # Keys logged
# Open in Wireshark: Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log

# Test HSTS:
curl -sI https://target.com | grep -i "strict-transport"
# max-age should be ≥31536000 (1 year)
# includeSubDomains recommended
# preload for browser preload list

# Certificate pinning test:
curl -sI --pinnedpubkey sha256//HASH= https://target.com
# If pinning correct: 200
# If wrong pin: SSL error
```

---

## 12. Cryptographic Randomness

### 12.1 Why Randomness Is Critical

Cryptography requires random numbers for key generation, IVs, salts, nonces, and ephemeral DH values. If these "random" values are predictable, the entire cryptographic system fails regardless of the strength of the algorithm.

```
What breaks when randomness is weak:

Key generation: Predictable private key → attacker knows your key without brute force
AES IV:         Predictable IV → pattern in ciphertext, BEAST-like attacks
ECDSA nonce:    Predictable k → private key recovery (PS3, Android Bitcoin wallet)
Salt:           Predictable salt → precomputed table attacks possible
Session tokens: Predictable tokens → session hijacking without authentication
VPN key:        Predictable key → full traffic decryption (DUHK attack 2017)
```

### 12.2 PRNG vs CSPRNG

```
PRNG (Pseudo-Random Number Generator):
  Deterministic algorithm that produces "random-looking" numbers
  Seeded with initial value
  Given seed: entire sequence is deterministic
  
  Examples: rand() in C, Math.random() in JavaScript
  Use for: simulation, games, non-security randomness
  NEVER use for: cryptographic keys, tokens, passwords, security
  
  Attack: if attacker knows seed (e.g., current timestamp), they can
          predict all "random" numbers → broken crypto

CSPRNG (Cryptographically Secure PRNG):
  Designed to be computationally infeasible to predict next output
  Even with knowledge of all previous output
  Forward secrecy: learning current state doesn't reveal past output
  Backward secrecy: predicting future output is infeasible
  
  Examples:
  Linux: /dev/urandom (modern Linux: uses CSPRNG, safe for all uses)
  Linux: /dev/random (legacy: blocks until entropy; /dev/urandom is preferred)
  Windows: CryptGenRandom, BCryptGenRandom
  OpenSSL: RAND_bytes()
  Python: os.urandom(), secrets module
  
/dev/random vs /dev/urandom (Linux):
  Myth: /dev/urandom is weaker than /dev/random
  Truth: Both use same CSPRNG kernel; /dev/random blocks unnecessarily
  Modern Linux (kernel 5.6+): both behave identically
  ALWAYS use: /dev/urandom or the secrets module
  NEVER block applications waiting for /dev/random
```

### 12.3 Entropy

```
Entropy in cryptography: measure of unpredictability (bits)

High entropy: 256-bit key from CSPRNG (truly unpredictable, 2^256 possibilities)
Low entropy:  256-bit key from timestamp (only milliseconds in a day)

Entropy sources (Linux kernel entropy pool):
  Hardware: CPU timing jitter, thermal noise, hardware RNG (RDRAND)
  Devices: Disk I/O timing, network packet arrival timing
  User: Keyboard/mouse timing
  Early boot: Low entropy problem (all sources above unavailable)
  
The "entropy starvation" problem:
  Embedded systems, VMs, and containers often lack entropy at boot
  
  Impact: If CSPRNG generates keys before sufficient entropy is collected:
          Keys may be predictable
          
  Real attack (2012): Heninger et al. analysed millions of RSA public keys
                      Found many shared factors (same primes in different keys)
                      Root cause: entropy-starved key generation at first boot
                      Multiple different devices generated the same "random" primes
                      
  Solution:
  Hardware RNG: Intel RDRAND instruction (hardware true RNG)
  virtio-rng: Feed entropy to VMs from host
  haveged: Software entropy daemon
  rng-tools: Hardware RNG interface daemon
```

```bash
# Cryptographic randomness in practice:

# Generate secure random values:
openssl rand -hex 32                       # 32 bytes = 256-bit random key (hex)
openssl rand -base64 32                    # 32 bytes as base64
openssl rand -out keyfile.bin 32           # Write 32 random bytes to file

# Python — ALWAYS use secrets module for cryptographic randomness:
python3 << 'EOF'
import secrets, os

# Secure token for session IDs, CSRF tokens, etc:
token = secrets.token_hex(32)              # 64-char hex string (256 bits)
print(f"Secure token: {token}")

# Secure random bytes for key material:
key = secrets.token_bytes(32)              # 32 random bytes
print(f"Key (hex): {key.hex()}")

# os.urandom() is equivalent and always cryptographically secure:
key2 = os.urandom(32)
print(f"os.urandom key: {key2.hex()}")

# WRONG: Do not use random module for security:
import random
insecure = random.randbytes(32)
# This is NOT cryptographically secure — don't use for keys/tokens/salts
# random.randbytes looks secure but can be predicted if seed is known
EOF

# Check entropy on Linux:
cat /proc/sys/kernel/random/entropy_avail    # Current entropy bits available
cat /proc/sys/kernel/random/pool_size        # Entropy pool size

# Check hardware RNG availability:
cat /sys/devices/virtual/misc/hw_random/rng_available
ls /dev/hwrng                                # Hardware RNG device

# Install entropy daemon for servers/VMs:
sudo apt install haveged
sudo systemctl start haveged
cat /proc/sys/kernel/random/entropy_avail    # Should be much higher now

# Test PRNG quality (diehard/NIST tests):
openssl rand 1000000 > /tmp/random.bin
ent /tmp/random.bin                          # Entropy test (install: apt install ent)
# Entropy: should be close to 8.00 bits/byte
# Chi-square: should be within expected range
# Serial correlation: should be close to 0.00
```

> **Key Insight:** Weak randomness is the silent killer of cryptographic systems. AES-256 with a predictable key provides no security. ECDSA with a repeated nonce loses the private key. Session tokens generated with timestamp seeds are trivially predictable. Always use CSPRNG (/dev/urandom, os.urandom(), secrets module) and never use general-purpose PRNGs (rand(), random.random()) for any security purpose.

---

## 13. Steganography

### 13.1 What Steganography Is

Steganography (Greek: "hidden writing") is the practice of concealing a message within another, non-secret, file or communication. Unlike cryptography, which makes content unreadable, steganography hides the existence of the message itself.

```
Steganography vs Cryptography:

Cryptography:
  "Hello World" → encrypted → "x7Kp2mQ9..." (obviously encrypted)
  Attacker knows: a secret message exists, cannot read it
  
Steganography:
  "Hello World" hidden inside a photo of a cat
  Attacker sees: a photo of a cat
  Attacker doesn't know: a secret message exists
  
Combined (crypto + stego):
  Encrypt "Hello World" → encrypt it → hide encrypted data in cat photo
  Even if stego is detected: encrypted content cannot be read
  This is what sophisticated threat actors and C2 channels use
```

### 13.2 Steganography Techniques

```
Image Steganography — LSB (Least Significant Bit):
  
  Each pixel in a 24-bit RGB image has: R(8 bits) G(8 bits) B(8 bits)
  Changing the least significant bit changes colour by 1/256 — visually imperceptible
  
  Original pixel: R=11010110, G=10010100, B=11100010
  Modified pixel: R=11010111, G=10010100, B=11100011
  (Changed LSB of R and B to embed 2 bits of hidden data)
  
  Capacity: 3 bits per pixel (one per RGB channel)
  24-bit 1920×1080 image: 1920×1080×3 = 6.2 million bits = ~750KB of hidden data
  
  Detection: Statistical analysis (chi-square test detects LSB pattern anomalies)
  Steganalysis tools: StegExpose, StegoSuite

Audio Steganography:
  Hide data in audio file LSBs (imperceptible to human hearing)
  Phase modification: hide in phase of audio signal
  Echo hiding: encode data in echo parameters

Network Steganography:
  ICMP payload: hide data in ping packet payload
  TCP timestamp: encode data in TCP timestamp option
  DNS: hide data in subdomain labels or response padding
  HTTP headers: hide in custom headers or timing
  
  This is particularly relevant for C2 (command and control):
  Malware uses network steganography to blend C2 traffic with legitimate traffic
```

### 13.3 Steganography in Security

```
Offensive uses:
  Data exfiltration: hide stolen data in images uploaded to social media
  C2 communication: hide commands in public social media posts/images
  Malware delivery: embed malware in documents, images
  
  Real examples:
  Turla APT (2019): hid C2 commands in comments on Britney Spears' Instagram posts
  Duqu malware: used custom steganography to exfiltrate data
  Multiple APT groups: use image steganography for C2 communications
  
Defensive considerations:
  DLP systems must inspect image content, not just file type
  Network monitoring must analyse payload patterns, not just protocols
  Outbound traffic should be analysed for steganographic channels
```

```bash
# Steganography in practice:

# steghide — hide data in JPEG/BMP/WAV/AU:
sudo apt install steghide

# Hide a file in an image:
steghide embed \
    -cf photo.jpg \              # Cover file (the innocent-looking carrier)
    -sf secret.txt \             # Secret file to hide
    -p "stegopassword"           # Passphrase (encrypts the hidden data)

# Extract hidden data:
steghide extract \
    -sf photo.jpg \              # Stego file
    -p "stegopassword"           # Passphrase
# Extracts secret.txt if passphrase correct

# stegseek — fast steghide password cracker:
stegseek photo.jpg /usr/share/wordlists/rockyou.txt

# zsteg — detect LSB steganography in PNG/BMP:
sudo gem install zsteg
zsteg suspicious_image.png       # Detect hidden data
zsteg -a suspicious_image.png    # Try all methods

# binwalk — find embedded files in any binary:
binwalk suspicious_file.jpg      # Shows embedded files
binwalk -e suspicious_file.jpg   # Extract embedded files

# exiftool — check metadata (stego sometimes in EXIF):
exiftool photo.jpg | grep -v "^$"  # All metadata
exiftool -all= clean_photo.jpg     # Strip ALL metadata

# Detect LSB steganography with statistical analysis:
python3 << 'EOF'
from PIL import Image
import numpy as np

def detect_lsb_stego(filename):
    img = Image.open(filename)
    pixels = np.array(img)
    
    # Get all LSBs
    lsbs = pixels & 1  # Extract LSB of each channel
    
    # Calculate expected vs actual distribution
    # In a natural image, LSBs should be ~50% 0, ~50% 1
    # LSB steganography makes it exactly 50% (or different pattern)
    ratio = lsbs.mean()
    print(f"LSB distribution: {ratio:.4f} (natural: ~0.5, suspicious: exactly 0.5)")
    
    # Chi-square test
    n = lsbs.size
    observed_0 = np.sum(lsbs == 0)
    observed_1 = np.sum(lsbs == 1)
    expected = n / 2
    chi_sq = ((observed_0 - expected)**2 + (observed_1 - expected)**2) / expected
    print(f"Chi-square: {chi_sq:.2f} (low value suggests steganography)")

detect_lsb_stego("photo.jpg")
EOF
```

> **Key Insight:** Steganography's power is deniability — the carrier file appears innocent. Sophisticated APT groups use steganography for C2 because the traffic blends with normal image/media traffic. Defence requires content inspection (not just metadata), statistical analysis of image entropy, and anomaly detection on upload/download patterns. In incident response, always check media files for embedded content.

---

## 14. Cryptography in OT/ICS Environments

### 14.1 The Cryptography Gap in OT

```
State of cryptography in OT/ICS (2024):

No cryptography at all:
  Modbus TCP: no authentication, no integrity, no confidentiality
  DNP3 (baseline): no cryptography (SAv5 adds authentication)
  PROFIBUS: no cryptography
  BACnet: no cryptography in baseline
  
Why no cryptography:
  1. Designed in 1970s-1980s before network security was a concern
  2. CPU constraints: embedded PLCs lack processing power for crypto
  3. Latency constraints: crypto processing adds microseconds-milliseconds
     unacceptable for hard real-time control loops
  4. Legacy infrastructure: millions of deployed devices cannot be updated
  5. Vendor lock-in: vendors slow to implement standard crypto
  
Real consequence:
  Any device on the OT network segment can:
  - Read all sensor values (passive Modbus scan)
  - Write to any register/coil (change setpoints, open/close valves)
  - Replay captured commands (repeat a previous command)
  - Inject false commands (fabricate Modbus function codes)
  With no authentication required
```

### 14.2 Where Cryptography Exists in OT

```
IEC 62351 — Security for IEC 61850 and IEC 60870-5-104:
  62351-3: TLS for MMS, ICCP
  62351-4: Authentication for ICCP
  62351-5: Authentication for DNP3 and IEC 60870-5-101/104
  62351-6: GOOSE and Sampled Values authentication (AES-GMAC)
  62351-8: Role-based access control
  
  Adoption: low — implementation is complex, vendor support varies
  
OPC-UA Security:
  OPC-UA has built-in security: authentication, signing, encryption
  MessageSecurityMode: None, Sign, SignAndEncrypt
  Sign: Integrity protection (HMAC)
  SignAndEncrypt: Integrity + Confidentiality (AES-256-CBC)
  Certificates: X.509 certificates for server/client authentication
  
  This is the correct model for new OT deployments
  OPC-UA adoption growing — replacing older proprietary protocols
  
WirelessHART / ISA100.11a:
  AES-128 encryption for wireless industrial sensors
  CCM (Counter with CBC-MAC) mode — authenticated encryption
  Key management: join keys, session keys
  
DNP3 Secure Authentication v5 (SAv5):
  HMAC-based challenge-response authentication
  Prevents command injection for DNP3
  Adoption: some power utilities (NERC CIP drives adoption)
  
IEC 61850 GOOSE Security (IEC 62351-6):
  GOOSE messages authenticated with AES-GMAC
  Prevents forged protection relay commands
  Deployment: rare — latency constraints challenged
```

### 14.3 TLS in OT Environments

```
TLS deployment challenges in OT:

Certificate management:
  OT devices have long lifespans (10-20 years)
  Annual TLS certificate renewal cycles require:
    - Update process that doesn't interrupt operation
    - Certificate lifecycle management tooling
    - Operator training
  Many OT environments have no process for this
  
TLS versions on legacy OT:
  Windows CE, Windows XP embedded: support TLS 1.0 only (deprecated)
  Cannot be upgraded without replacing hardware
  Solution: TLS termination proxy (modern TLS toward IT, legacy toward OT device)
  
Self-signed certificates in OT:
  OT environments often cannot access internet PKI
  Internal CA or self-signed certificates used
  Risk: No validation possible without PKI
  
TLS for OT communication:
  OPC-UA → TLS 1.2/1.3 for secure machine-to-machine
  Remote access → TLS VPN or TLS-based remote access (not Telnet!)
  Historian → TLS for HTTPS data access from IT
  
Certificate pinning in OT:
  OT systems can pin specific certificates
  Prevents MITM even with compromised CA
  Requires careful management for certificate rotation
```

```bash
# Cryptography assessment in OT networks:

# Check if OT protocols are running without encryption:
sudo tcpdump -i eth0 -nn 'port 502 or port 20000 or port 2404 or port 44818' | \
    head -20
# If you see traffic: those protocols running in cleartext

# Check if OPC-UA is using TLS:
# Port 4840 = OPC-UA (unencrypted baseline)
# Port 4843 = OPC-UA with TLS
nmap -sV -p 4840,4843 192.168.1.0/24 2>/dev/null

# Test TLS on industrial historian or HMI:
openssl s_client -connect historian-server:443 2>/dev/null | \
    grep -E "Protocol|Cipher|Verify"
# Look for TLS 1.0/1.1 (deprecated) or weak cipher suites

# Check IEC 62351 GOOSE authentication (wireshark):
# Filter: goose
# Check if Security Level > 0 in GOOSE PDU
# Security Level 0 = no authentication (vulnerable)

# Audit OPC-UA security mode:
# Using open62541 or other OPC-UA client:
# python-opcua:
python3 << 'EOF'
try:
    from opcua import Client
    client = Client("opc.tcp://192.168.1.100:4840")
    client.connect()
    # If connected without security: no encryption or authentication
    security_mode = client.get_attribute(1, "SecurityMode")
    print(f"Security Mode: {security_mode}")
    # 1 = None (no security!)
    # 2 = Sign
    # 3 = SignAndEncrypt (correct)
    client.disconnect()
except Exception as e:
    print(f"Connection result: {e}")
EOF
```

---

## 15. Module Summary

| Concept | Core Mechanism | Attack Relevance | Key Defence | OT/ICS Note |
|---------|---------------|-----------------|-------------|-------------|
| **Encoding** | Format conversion (Base64, URL, Hex) | WAF bypass via encoding, credential exposure in Basic Auth | Decode all input before validation; never confuse with encryption | OT firmware strings often Base64-encoded in memory dumps |
| **Symmetric Encryption** | Same key encrypts and decrypts | Brute force key, weak cipher (DES/3DES), ECB mode patterns | AES-256-GCM; never ECB; unique random IV per message | AES-128-CCM in WirelessHART; OT devices often lack AES-NI |
| **AES** | SPN, 10-14 rounds, 128-bit blocks | Side-channel (timing, cache); implementation attacks only | AES-256-GCM standard; hardware AES-NI; protect key material | AES-128 in WirelessHART; AES-256 for historian data at rest |
| **DES/3DES** | 56-bit/112-bit Feistel; BROKEN | DES: brute force in minutes; 3DES: SWEET32 birthday attack | Eliminate; replace with AES-256 | Legacy payment systems in OT; force replacement schedule |
| **RSA** | Integer factorisation; public/private keys | PKCS1v15 padding oracle (ROBOT 2017); short keys (ROCA) | RSA-2048 minimum; RSA-PSS padding; prefer ECDH | TLS certificates for OT historian, OPC-UA servers |
| **ECC** | Elliptic curve discrete log; ECDHE | Weak curve parameters (NIST distrust); ECDSA k reuse | Curve25519/P-256; always random k in ECDSA | OPC-UA certificates; preferred over RSA for constrained devices |
| **Diffie-Hellman** | g^ab mod p shared secret without transmitting | Logjam (512-bit precomputed); discrete log for weak params | ECDHE; 2048-bit minimum DH; forward secrecy | ECDHE in OPC-UA TLS; enables forward secrecy for OT sessions |
| **MD5** | 128-bit Merkle-Damgård; BROKEN | Collision (2009); forged CA cert (Flame 2012) | SHA-256 minimum; MD5 acceptable only for non-security deduplication | Legacy OT firmware checksums use MD5; identify and flag |
| **SHA-1** | 160-bit; BROKEN | SHAttered collision (2017, $100K); chosen-prefix 2020 | SHA-256 minimum | OT firmware updates still using SHA-1; critical finding |
| **SHA-256/SHA-3** | 256-bit; SECURE | No practical attack known | SHA-256 standard; SHA-3 for diversity | Use for firmware integrity verification in OT |
| **Salt** | Random per-password value; defeats rainbow tables | Without salt: precomputed table attack | 16+ byte CSPRNG salt; unique per password; store with hash | Hash-based authentication tokens in OT systems |
| **Pepper** | Secret application-level addition to password | Requires app server compromise in addition to DB breach | 256-bit CSPRNG; store in HSM or config separate from DB | HMI application authentication secrets |
| **bcrypt/Argon2id** | Intentionally slow; work factor | GPU cracking; requires work to crack even with hash | Argon2id (time=3, mem=64MB); bcrypt (rounds≥12) | SCADA operator passwords; HMI authentication |
| **Digital Signatures** | Hash + asymmetric sign; auth + integrity + non-repudiation | Key theft; PS3/Android k reuse; PKCS1v15 forgery | ECDSA with random k; Ed25519; RSA-PSS | IEC 62351 signing of GOOSE messages; OTA firmware signing |
| **PKI** | Certificate chains; CA trust anchor | Rogue CA (MD5 collision 2008); misissued certs | CAA DNS records; CT monitoring; short-lived certs | OPC-UA PKI; internal CA for OT certificates |
| **TLS** | Asymmetric key exchange → symmetric data encryption | Heartbleed, BEAST, POODLE, FREAK, Logjam, ROBOT | TLS 1.3 minimum; ECDHE only; AEAD ciphers; HSTS | TLS for OT historian, remote access, OPC-UA; never Telnet |
| **TLS Handshake** | ClientHello/ServerHello → key exchange → application data | Downgrade attack; session hijack; MITM (no cert validation) | Certificate pinning; HSTS; validate full chain; TLS 1.3 | OT remote access must validate server certificates |
| **Cryptographic Randomness** | CSPRNG; entropy sources; unpredictable output | Predictable seed (DUHK 2017); entropy starvation; ECDSA k | /dev/urandom; secrets module; hardware RNG; haveged for VMs | First-boot key generation in OT devices; entropy starvation risk |
| **Steganography** | Hidden data in carrier files | Data exfiltration; C2 in social media images (Turla APT) | Content inspection; outbound media analysis; StegExpose | ICMP tunnel C2 in OT networks; detect with payload analysis |

---

> **Next Module:** [Stage 2.3 — Identity and Access Management](./stage-2.3-iam.md)  
> **Previous Module:** [Stage 2.1 — Core Security Concepts](./stage-2.1-core-concepts.md)  
> **Stage Index:** [Stage 2 README](./README.md)  
> **Series Index:** [Full Roadmap](../../README.md)

---

*This document is part of the Cybersecurity × OT/ICS Security Full Roadmap series. All techniques are presented for educational purposes, authorised security research, and defensive security practice. Always obtain proper authorisation before testing any system.*