# Module 2.3 — Kimlik Doğrulama ve Erişim Yönetimi (IAM)
### Bytewall Academy | Cybersecurity × OT/ICS Security Roadmap

---

## Table of Contents

1. [Why This Module Matters](#1-why-this-module-matters)
2. [Foundations: Identity, Authentication, Authorization](#2-foundations-identity-authentication-authorization)
3. [Password Policies](#3-password-policies)
4. [Multi-Factor Authentication (MFA)](#4-multi-factor-authentication-mfa)
5. [Biometric Authentication](#5-biometric-authentication)
6. [Token-Based Authentication](#6-token-based-authentication)
7. [OAuth 2.0](#7-oauth-20)
8. [OpenID Connect (OIDC)](#8-openid-connect-oidc)
9. [SAML](#9-saml)
10. [Kerberos](#10-kerberos)
11. [NTLM](#11-ntlm)
12. [Single Sign-On (SSO)](#12-single-sign-on-sso)
13. [Privileged Access Management (PAM)](#13-privileged-access-management-pam)
14. [The Missing Layer: Directory Services & Identity Federation Architecture](#14-the-missing-layer-directory-services--identity-federation-architecture)
15. [OT/ICS-Wide Identity Considerations](#15-otics-wide-identity-considerations)
16. [Module Summary Table](#16-module-summary-table)
17. [Navigation](#17-navigation)

---

## 1. Why This Module Matters

Identity is the new perimeter. Firewalls fail, network segmentation fails, but the single most consistent root cause across breach reports for the last decade is **compromised credentials and broken access logic**.

Concrete evidence, not theory:

- **Colonial Pipeline (May 2021)** — the attacker entered through a single compromised VPN account that had **no MFA enabled** and was tied to a password reused from another breach. The result: 5,500 miles of pipeline shut down, fuel shortages across the U.S. East Coast, and a $4.4M ransom payment. This is the canonical IT-to-OT pivot case study and it starts entirely in the IAM layer.
- **Uber (2022)** — an attacker bought a contractor's stolen credentials, defeated MFA via **MFA fatigue** (repeated push-notification spam until the victim approved one), and walked into Uber's internal Slack, AWS console, and source code repos.
- **Microsoft Exchange "Golden SAML" style attacks** and the **SolarWinds/Sunburst campaign (2020)** — attackers forged SAML tokens after compromising an ADFS signing certificate, granting themselves authentication into any federated service, including Microsoft 365, without ever touching a password.
- **Kerberoasting and Pass-the-Hash** are present in the overwhelming majority of post-exploitation phases in enterprise ransomware intrusions documented in Mandiant's M-Trends and CrowdStrike's Global Threat Reports, year after year.
- **NotPetya (2017)** spread laterally inside Maersk and Merck largely via **NTLM relay and stolen domain admin credentials**, causing over $10 billion in global damage — making it, to date, one of the most expensive uses of broken authentication in history.

Career relevance: IAM is the single domain where **identity architects, red teamers, blue teamers, auditors, and OT security engineers** all need the same foundational knowledge, just applied differently. A penetration tester without deep Kerberos/NTLM knowledge cannot operate in a Windows domain. A SOC analyst without OAuth/SAML knowledge cannot triage a cloud account-takeover. An OT engineer without PAM knowledge cannot defend a Safety Instrumented System from an insider or a compromised vendor laptop.

> **Retain this:** Every major breach you will study in this entire roadmap touches IAM at least once — either as the initial access vector or as the mechanism of lateral movement. Master this module and you understand the connective tissue of nearly all intrusions.

---

## 2. Foundations: Identity, Authentication, Authorization

Before any protocol, three words must be permanently distinct in your mind:

| Term | Question it answers | Example |
|---|---|---|
| **Identity** | Who/what are you claiming to be? | `jdoe@corp.local` |
| **Authentication (AuthN)** | Can you prove that claim? | Password + OTP code |
| **Authorization (AuthZ)** | What are you allowed to do once proven? | "Can read Finance share, cannot write to Domain Admins" |

```
   IDENTITY            AUTHENTICATION            AUTHORIZATION
  "I am jdoe"    -->   "Prove it: password +  -->  "OK, you may
                          OTP code"                  access /finance,
                                                      read-only"
```

Most breaches occur not because authentication failed cryptographically, but because the **authorization model was flat, over-permissioned, or never reviewed** after authentication succeeded. Keep this distinction precise — it will resurface in every section below.

A fourth, frequently omitted, concept:

- **Accounting / Auditing (AAA's third "A")** — every authentication and authorization decision must be logged immutably. Without this, forensic reconstruction of an incident is impossible. This is your bridge to Module 2.x on logging and SIEM, and it is non-negotiable in OT environments where safety and liability are at stake.

---

## 3. Password Policies

### 3.1 First Principles

A password is a **shared secret**. Its security rests entirely on two properties: **entropy** (how hard it is to guess/brute-force) and **secrecy** (whether it has been disclosed, reused, or stored insecurely). Everything else — length rules, rotation rules, complexity rules — is an attempt to engineer those two properties at scale across a population of humans who are bad at generating randomness.

### 3.2 How Passwords Are Actually Attacked

```
┌─────────────────┬──────────────────────────────────────────┐
│ Attack Class     │ Mechanism                                │
├─────────────────┼──────────────────────────────────────────┤
│ Online brute     │ Repeated login attempts against a live   │
│ force            │ service (slow, noisy, rate-limited)       │
│ Offline crack    │ Attacker has the hash (e.g. from a dump) │
│                   │ and brute-forces/dictionary-attacks it    │
│                   │ with zero rate limit, using GPUs          │
│ Credential        │ Reusing leaked username:password pairs    │
│ stuffing          │ from unrelated breaches (Have I Been      │
│                   │ Pwned-class data) against your service    │
│ Password spraying │ Trying ONE common password against MANY  │
│                   │ accounts to stay under lockout thresholds │
└─────────────────┴──────────────────────────────────────────┘
```

**Password spraying** is the technique behind numerous nation-state intrusions (APT28/Fancy Bear has used it extensively against Microsoft 365 tenants). It defeats naive "5 failed attempts = lockout" policies because each *individual account* only sees one or two attempts.

### 3.3 Offline Cracking in Practice

If an attacker dumps `/etc/shadow` on Linux or the NTDS.dit database on a Windows Domain Controller, they own the hashes. Speed depends entirely on hash algorithm:

```bash
# Hashcat benchmark example — illustrates why algorithm choice matters enormously
hashcat -b -m 1000   # -b = benchmark mode, -m 1000 = NTLM hash type
hashcat -b -m 1800   # -m 1800 = sha512crypt (Linux shadow, modern)
```

NTLM (MD4-based, unsalted) can be brute-forced at **tens of billions of hashes/second** on modern GPUs. `bcrypt`/`argon2`-hashed passwords can be brute-forced at only **thousands per second** because they are deliberately slow (memory-hard / CPU-hard by design). This single fact is why modern password storage MUST use bcrypt, scrypt, or Argon2 — never MD5, SHA-1, or unsalted SHA-256.

```bash
# Dictionary + rule-based attack against a captured NTLM hash list
hashcat -m 1000 -a 0 ntlm_hashes.txt rockyou.txt -r rules/best64.rule
# -m 1000  : hash mode = NTLM
# -a 0     : attack mode = straight dictionary
# -r ...   : apply mangling rules (case, leetspeak, append digits) to each
#            dictionary word, multiplying effective coverage
```

### 3.4 What Modern Policy Actually Should Say

NIST SP 800-63B (the de facto modern standard) explicitly **reversed** decades of bad advice:

| Old (bad) guidance | Modern (NIST 800-63B) guidance |
|---|---|
| Force rotation every 90 days | Rotate only on evidence of compromise |
| Require special chars/mixed case | Require **length** (≥8, recommend 15+) over complexity |
| Block password managers | Encourage them |
| No reuse check | **Screen against known-breached password lists** |

```bash
# Example: checking a password against the Pwned Passwords k-anonymity API
# (never send the full password — only a SHA-1 prefix, preserving privacy)
PW_HASH=$(echo -n "P@ssw0rd123" | sha1sum | cut -d' ' -f1 | tr 'a-z' 'A-Z')
PREFIX=${PW_HASH:0:5}
SUFFIX=${PW_HASH:5}
curl -s "https://api.pwnedpasswords.com/range/$PREFIX" | grep -i "$SUFFIX"
# If a match is returned, the password has appeared in a known breach corpus
```

### 3.5 Defensive Controls

- Enforce **length minimums**, not arbitrary complexity.
- Enforce **breach-list screening** at creation/change time.
- Enforce **account lockout / adaptive throttling** tuned to defeat spraying (e.g., lock per-IP and per-account velocity, not just per-account count).
- Store with **Argon2id** (preferred), bcrypt, or scrypt — with per-user random salts and a server-side secret pepper where feasible.
- Never log raw passwords, even in debug/error paths — this is a recurring real-world finding (Facebook, 2019: hundreds of millions of plaintext passwords found in internal logs).

### 3.6 Forensic Evidence

Failed login storms in `Security.evtx` (Event ID **4625** on Windows), `/var/log/auth.log` on Linux, and authentication gateway logs are your primary spray/brute-force indicators. Look for **one source IP/user-agent hitting many distinct usernames** with low per-account attempt counts — that signature is spraying, not brute force.

### 3.7 OT/ICS Perspective

Many PLC/HMI/engineering workstation accounts ship with **vendor-default credentials** (e.g., historically documented defaults for Siemens, Schneider, Rockwell HMIs) that are never rotated because operations teams fear downtime from a lockout. Shodan-indexed ICS devices with default creds remain discoverable to this day. **Never apply IT lockout policies blindly to OT** — a locked-out HMI account during a process upset can be more dangerous than the credential risk itself; compensate instead with strict network segmentation and PAM session brokering (Section 13).

> **Retain this:** Password strength is irrelevant if the storage hash is weak, and policy is irrelevant if it ignores the realistic attack — spraying, not brute force, is what breaches you.

---

## 4. Multi-Factor Authentication (MFA)

### 4.1 First Principles

MFA requires proof from **two or more independent factor categories**:

```
1) Something you KNOW   — password, PIN
2) Something you HAVE   — phone, hardware token, smart card
3) Something you ARE    — fingerprint, face, iris
4) Somewhere you ARE    — geolocation/network context (increasingly used as a signal)
```

Two passwords is not MFA. A password + a security question is not MFA (both are "something you know"). This distinction is tested constantly in compliance audits and interviews — know it cold.

### 4.2 MFA Mechanisms, Ranked by Resistance to Modern Attacks

```
WEAKEST ─────────────────────────────────────────────► STRONGEST
SMS OTP   Email OTP   TOTP App   Push Notification   FIDO2/WebAuthn (hardware)
```

- **SMS OTP** — vulnerable to **SIM swapping** (social-engineering a carrier to port a victim's number) and **SS7 protocol interception**. Numerous celebrity/crypto-wallet account takeovers (e.g., widely documented Twitter/X account hijacks, 2019–2021) trace back to SIM swap attacks defeating SMS MFA.
- **TOTP (Time-based One-Time Password, RFC 6238)** — a shared secret seed plus the current time window generates a 6-digit code. Stronger than SMS (no carrier dependency) but the **seed can be phished** via real-time relay (adversary-in-the-middle).
- **Push notification MFA** — vulnerable to **MFA fatigue / push bombing**: an attacker with a valid password spams push approvals until the victim taps "approve" out of annoyance or confusion. This is exactly the technique used in the **Uber 2022** and several **Lapsus$ group** intrusions.
- **FIDO2/WebAuthn hardware keys (YubiKey, etc.)** — cryptographically bind the authentication to the **specific origin domain**, making them phishing-resistant. Even if a user is tricked onto `evil-microsoft-login.com`, the hardware key will refuse to sign the challenge because the origin doesn't match.

### 4.3 Attack Tooling You Must Know

- **Evilginx2** — a reverse-proxy phishing framework that sits between victim and real login page, harvesting session cookies in real time, which defeats TOTP and push MFA (it doesn't need the password — it steals the post-auth session token).
- **Modlishka** — similar adversary-in-the-middle (AiTM) phishing proxy.

```bash
# Conceptual illustration of why AiTM defeats OTP/push MFA (NOT an executable exploit):
# Victim -> evil proxy (looks identical to real site) -> real site
# Victim enters password + OTP on the FAKE page
# Proxy relays both to the REAL site in real time
# Proxy captures the resulting authenticated SESSION COOKIE
# Attacker replays that cookie — MFA was satisfied, but for the ATTACKER's session
```

This is precisely why **FIDO2/WebAuthn** is the recommended end-state: it cryptographically verifies the origin, so the proxy relay breaks.

### 4.4 Defensive Controls

- Mandate **FIDO2/WebAuthn or certificate-based smart cards** for privileged and remote-access accounts.
- Disable **SMS MFA** for any account with elevated privilege.
- Implement **number-matching push MFA** (Microsoft Authenticator's "enter the number shown on screen" mode) to blunt fatigue attacks — it doesn't fully solve AiTM, but it eliminates blind-tap approval.
- **Rate-limit and alert on repeated push prompts** to the same user within a short window — a strong fatigue-attack indicator.
- Conditional Access / risk-based policies: block or challenge logins from impossible-travel locations, new devices, or anomalous ASN ranges.

### 4.5 Forensic Evidence

Azure AD/Entra ID Sign-in logs show `MFA Satisfied` vs. `MFA Denied` counts per session and per user — a burst of denied/cancelled push attempts followed by one approval within seconds is the fatigue-attack signature. AiTM compromises leave a tell-tale anomaly: **the authenticating IP differs from the IP later using the resulting session token**.

### 4.6 OT/ICS Perspective

Air-gapped or "logically isolated" OT networks frequently have **zero MFA** on engineering workstations because vendors historically didn't support it and operators view it as a usability tax during emergency response. The compensating architecture (Section 13) is to put MFA at the **jump-server/PAM boundary** between IT and OT rather than inside the OT network itself — this preserves emergency operability inside the OT zone while still gating the crossing point.

> **Retain this:** MFA defeats password theft, not session theft. If you don't also defend against AiTM phishing and push fatigue, your "MFA-protected" account is still one click away from compromise.

---

## 5. Biometric Authentication

### 5.1 First Principles

Biometrics authenticate based on a **measured physical or behavioral trait** — fingerprint ridges, iris patterns, facial geometry, gait, typing cadence. Critically: **a biometric is an identifier, not a secret**. Your fingerprint is on every glass you touch; your face is in thousands of photos. This single fact reframes the entire threat model — biometrics are strong against *remote credential theft* but weak against *physical spoofing and irrevocability*.

### 5.2 How Matching Works Internally

```
ENROLLMENT:  raw biometric --> feature extraction --> template (NOT the raw image)
                                                       --> stored, ideally on-device
                                                           in a Secure Enclave/TPM

VERIFICATION: live capture --> feature extraction --> compare against stored
                                                        template --> match score
                                                        --> accept if score > threshold
```

Two error rates define system quality:
- **FAR (False Accept Rate)** — probability an impostor is wrongly accepted.
- **FRR (False Reject Rate)** — probability a legitimate user is wrongly rejected.
These trade off against each other via the match threshold — this is the same precision/recall tradeoff you'll see in any classifier, and it is exploitable: an attacker tunes spoof quality to land just inside the FAR tolerance.

### 5.3 Documented Attacks

- **Chaos Computer Club (2017)** demonstrated bypassing Samsung Galaxy S8 iris recognition using a printed photo of the iris plus a contact lens to add curvature/reflection.
- **Fingerprint spoofing** via lifted latent prints reconstructed in silicone or wood glue — demonstrated repeatedly against capacitive sensors lacking liveness detection.
- **Presentation attacks against face recognition** using photos, masks, or deepfake video injected into the camera feed — this is why modern systems require **liveness detection** (blink, depth-sensing via structured light/ToF, challenge-response).

### 5.4 Defensive Controls

- Use sensors with **liveness/anti-spoofing detection** (depth sensing, blood-flow/pulse detection, infrared).
- Store templates **on-device in a hardware-backed secure enclave**, never as raw biometric data on a central server — a centralized biometric database is a catastrophic, **unrevocable** breach if compromised (you can reset a password; you cannot reset your fingerprint).
- Always pair biometrics with a **second independent factor** for high-value actions — biometric-as-sole-factor is convenience-tier security, not assurance-tier.
- Apply **template encryption and integrity binding** to the specific device hardware to prevent template extraction-and-replay.

### 5.5 Forensic Evidence

Biometric authentication events typically log only **match/no-match plus the device's secure enclave attestation** — raw biometric data should never appear in logs (and if it does, that itself is a serious compliance and security failure to flag). Repeated low-confidence "near-miss" match attempts in short succession are a spoof-attempt indicator.

### 5.6 OT/ICS Perspective

Biometric access control is increasingly used for **physical access to control rooms and safety-critical cabinets**, not network login. The forensic implication for OT incident response: tie physical badge/biometric access logs to the SCADA/HMI session logs — a documented technique in insider-threat investigations is correlating "who was physically present" against "what commands were issued" during the incident window.

> **Retain this:** Biometrics authenticate identity, not secrecy — design every biometric system assuming the trait itself will eventually be duplicated, and ensure liveness detection plus a second factor carry the real security weight.

---

## 6. Token-Based Authentication

### 6.1 First Principles

A **token** is a piece of data, issued after successful authentication, that the client presents on subsequent requests **instead of re-sending credentials**. This is the foundational shift away from sessions stored server-side per request, toward bearer-based, often stateless, authentication — and it underlies OAuth, OIDC, JWTs, and API security broadly.

### 6.2 Stateful vs. Stateless Tokens

```
STATEFUL (Session ID)               STATELESS (JWT)
─────────────────────               ────────────────
Server stores session in DB         Server signs a self-contained token
Client holds only an opaque ID      Client holds the full claims, signed
Revocation: delete server record    Revocation: HARD (must blacklist or
                                     use short expiry + refresh)
Scales poorly across many servers   Scales horizontally with ease
```

### 6.3 Anatomy of a JWT (JSON Web Token)

```
header.payload.signature

eyJhbGciOiJIUzI1NiJ9 . eyJzdWIiOiJqZG9lIiwicm9sZSI6ImFkbWluIn0 . sX...signature

Decoded header:   {"alg": "HS256", "typ": "JWT"}
Decoded payload:  {"sub": "jdoe", "role": "admin", "exp": 1735689600}
```

### 6.4 The Critical Vulnerability Class: `alg=none` and Algorithm Confusion

```bash
# Demonstrating the classic JWT "alg:none" bypass concept (CVE-class issue,
# affected numerous poorly-implemented JWT libraries circa 2015-2017)
echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0       # forged header
echo -n '{"sub":"admin","role":"admin"}' | base64 -w0   # forged payload
# Result: header.payload. (empty signature)
# A vulnerable verifier that trusts the client-supplied 'alg' field will
# accept this with ZERO valid signature, granting admin claims outright.
```

A related class: **RS256-to-HS256 algorithm confusion**, where an attacker takes a server's known-public RSA key and resigns a token using HS256 with that public key string *as the HMAC secret* — if the verifier doesn't strictly pin the expected algorithm, it will accept the forged HMAC signature.

### 6.5 Defensive Controls

- **Pin the expected algorithm server-side** — never trust the `alg` header from the token itself.
- Keep token lifetimes **short** (minutes, not days) and pair with refresh tokens that ARE revocable server-side.
- Store sensitive tokens in **httpOnly, Secure, SameSite cookies** — never in `localStorage`, which is trivially exfiltrated by any XSS.
- Implement **token binding** (tying a token to a TLS channel or device fingerprint) for high-assurance use cases.

```bash
# Inspecting a JWT quickly without trusting any tooling that auto-verifies
TOKEN="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqZG9lIn0.xxx"
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null   # decode header
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null   # decode payload
```

### 6.6 Forensic Evidence

Look for tokens with **unexpectedly long lifetimes**, tokens issued with `alg` values outside your expected set, and replay of the same token from **multiple distinct IP/geolocation pairs** in a short window — the latter is a strong session/token theft indicator.

### 6.7 OT/ICS Perspective

Modern OT cloud-connectivity platforms (vendor remote-monitoring portals, digital twin platforms) increasingly issue API tokens to field gateways. A leaked, long-lived, unscoped token to a cloud telemetry API can become a pivot point into the vendor's broader tenant — treat every OT-to-cloud integration token with the same scrutiny as a privileged credential, and scope tokens to the **minimum API surface** the device actually needs.

> **Retain this:** A stolen valid token is functionally equivalent to a stolen password — but often invisible to password-rotation policies. Short lifetimes and strict algorithm pinning are what make tokens safe.

---

## 7. OAuth 2.0

### 7.1 First Principles — OAuth Is Authorization, Not Authentication

This is the single most common misconception in the industry: **OAuth 2.0 was designed to delegate authorization (access to resources), not to prove identity.** "Login with Google" *feels* like authentication, but raw OAuth alone doesn't standardize *who* the user is — that gap is exactly what OpenID Connect (Section 8) was built to close.

### 7.2 The Four Roles

```
┌──────────────┐      ┌──────────────────┐
│   Resource    │      │  Authorization    │
│   Owner       │      │  Server            │
│  (the user)   │      │ (e.g. accounts.    │
└──────┬───────┘      │  google.com)       │
       │               └────────┬──────────┘
       │ grants consent          │ issues token
       ▼                         ▼
┌──────────────┐      ┌──────────────────┐
│   Client      │◄────►│  Resource         │
│ (3rd-party app)│      │  Server            │
│               │      │ (e.g. Google Drive │
│               │      │  API)              │
└──────────────┘      └──────────────────┘
```

### 7.3 The Authorization Code Flow (the only flow you should use for web apps)

```
1. Client redirects user to Authorization Server:
   GET https://auth.example.com/authorize?
       response_type=code
       &client_id=abc123
       &redirect_uri=https://app.example.com/callback
       &scope=read:profile
       &state=xyz789RANDOM      # CSRF protection — MUST be unguessable
       &code_challenge=BASE64URL(SHA256(code_verifier))   # PKCE
       &code_challenge_method=S256

2. User authenticates + consents at Authorization Server.

3. Authorization Server redirects back:
   GET https://app.example.com/callback?code=AUTH_CODE&state=xyz789RANDOM

4. Client exchanges code for token (server-to-server, NOT browser-visible):
   POST https://auth.example.com/token
       grant_type=authorization_code
       &code=AUTH_CODE
       &redirect_uri=https://app.example.com/callback
       &client_id=abc123
       &client_secret=SECRET
       &code_verifier=ORIGINAL_RANDOM_STRING   # PKCE proof

5. Authorization Server returns:
   { "access_token": "...", "refresh_token": "...", "expires_in": 3600 }
```

### 7.4 PKCE — Why It Exists

**PKCE (Proof Key for Code Exchange, RFC 7636)** was introduced because the authorization code, transmitted via browser redirect, can be intercepted (malicious app on the same mobile device registering the same custom URI scheme, or a referrer leak). PKCE binds the code exchange to a secret (`code_verifier`) only the legitimate client holds, so an intercepted *code* alone is useless without it. **PKCE is now mandatory best practice for all client types**, not just public/mobile clients.

### 7.5 Documented Real-World OAuth Vulnerabilities

- **Open Redirect via `redirect_uri`** — if the authorization server doesn't strictly validate the redirect URI against an exact allow-list, an attacker can register `https://app.example.com.attacker.com/callback` or exploit a loose wildcard match, redirecting the authorization code straight to themselves.
- **CVE-2022-31093 (Keycloak)** and various other IdP-specific OAuth/OIDC redirect validation flaws over the years have allowed token/code theft via crafted redirect URIs.
- **`state` parameter omission** — enables CSRF login attacks where an attacker tricks a victim into completing an OAuth flow that links the *attacker's* third-party account to the *victim's* session.

```bash
# Conceptual detection: searching IdP logs for authorization requests
# with redirect_uri values OUTSIDE the registered allow-list
grep "redirect_uri=" auth_server.log | grep -v "app.example.com/callback"
```

### 7.6 Defensive Controls

- **Exact-match allow-listing of redirect URIs** — never substring or wildcard match.
- **Always require and validate `state`** to prevent CSRF.
- **Always use PKCE**, even for confidential (server-side) clients.
- Use the **least-privilege `scope`** requested — never request broader scopes than the integration needs.
- Treat `client_secret` as a credential: rotate it, never commit it to source control (a chronic real-world finding in public GitHub repos via automated secret-scanning).

### 7.7 Forensic Evidence

Authorization-server logs should show the full redirect_uri, scope, and client_id per grant. An anomaly to hunt: a token issued with a **scope broader than the client's registered/expected scope set**, or a sudden spike in token requests from a single client_id across many distinct user accounts (credential-stuffing-style abuse of a third-party OAuth app).

### 7.8 OT/ICS Perspective

OAuth increasingly governs access between **OT vendor cloud platforms and enterprise SSO** (e.g., a turbine vendor's remote diagnostics portal federating into the customer's IdP). The risk: an over-broad `scope` granted to a vendor integration can become a standing, often-forgotten bridge between corporate identity and OT vendor cloud infrastructure. Audit OAuth app consent grants in your tenant **specifically for OT-vendor applications** on a recurring schedule — these are rarely reviewed after initial setup.

> **Retain this:** OAuth tells you what a token can *do*; it never by itself tells you *who* the user *is*. Confusing authorization with authentication is the root cause of an entire category of "Login with X" vulnerabilities.

---

## 8. OpenID Connect (OIDC)

### 8.1 First Principles

OIDC is a thin **identity layer built on top of OAuth 2.0**. It adds one critical artifact OAuth never defined: the **ID Token**, a signed JWT that asserts *who the user is*, alongside the OAuth access token that governs *what the client may do*.

```
OAuth 2.0 alone:           access_token   →  "you may call this API"
OAuth 2.0 + OIDC:          access_token   →  "you may call this API"
                           id_token (JWT) →  "this user is jdoe@corp.com,
                                              authenticated at time T,
                                              by issuer https://idp.corp.com"
```

### 8.2 ID Token Structure (Decoded)

```json
{
  "iss": "https://idp.corp.com",
  "sub": "9f8e7d6c-...",
  "aud": "client-app-id",
  "exp": 1735693200,
  "iat": 1735689600,
  "nonce": "n-0S6_WzA2Mj",
  "email": "jdoe@corp.com",
  "email_verified": true
}
```

Critical fields a defender must validate (and that vulnerable implementations historically skipped):
- `iss` — is this issuer the one you trust?
- `aud` — was this token actually issued *for your client*, not stolen from a different client of the same IdP?
- `exp`/`iat` — is it within validity window?
- `nonce` — matches the one your client generated, preventing replay of a stale ID token.

### 8.3 Documented Vulnerability Pattern: Missing `aud` Validation

If a relying party fails to check `aud`, an attacker who legitimately obtained an ID token for **a different, less-trusted client application** of the *same* IdP can replay that token against the higher-trust application — because the IdP's signature is valid, just not meant for this audience. This exact class of bug has appeared repeatedly across OIDC library implementations and is a standard finding in IAM security assessments.

### 8.4 Discovery and JWKS — How Trust Is Established at Scale

```bash
# OIDC discovery document — published at a well-known URL, tells clients
# everything they need: token endpoint, issuer, supported scopes, and
# crucially, the JWKS URI for signature verification keys
curl -s https://idp.corp.com/.well-known/openid-configuration | jq .

# Example relevant fields returned:
# {
#   "issuer": "https://idp.corp.com",
#   "authorization_endpoint": "https://idp.corp.com/authorize",
#   "token_endpoint": "https://idp.corp.com/token",
#   "jwks_uri": "https://idp.corp.com/.well-known/jwks.json"
# }

# Fetching the actual public signing keys to verify ID token signatures
curl -s https://idp.corp.com/.well-known/jwks.json | jq .
```

### 8.5 Defensive Controls

- Validate **every** claim — `iss`, `aud`, `exp`, `nonce`, signature — never trust just signature validity alone.
- Rotate signing keys regularly and always fetch them live from `jwks_uri`, never hardcode a key.
- Use the `nonce` parameter on every authorization request to prevent ID token replay.
- Restrict which IdPs/issuers are trusted via an explicit allow-list — never accept "any valid JWT from anywhere."

### 8.6 Forensic Evidence

ID token validation failures (bad `aud`, expired `exp`, signature mismatch) should be logged and alerted distinctly from generic auth failures — a spike in `aud` mismatches across many requests suggests active token replay/confusion attack attempts against your relying party.

### 8.7 OT/ICS Perspective

OIDC underlies most modern **cloud-based ICS/SCADA HMI access portals** (vendors increasingly offer browser-based HMI access federated through OIDC). Validate that these portals enforce strict `aud` and `iss` checks — a misconfigured OT vendor portal accepting tokens broadly scoped to "any corporate user" rather than the specific OT-access group is a documented category of finding in OT security assessments.

> **Retain this:** OIDC's ID token answers "who," OAuth's access token answers "what" — verifying only the token signature without checking `iss`/`aud`/`nonce` is equivalent to checking a passport's hologram but never reading the name on it.

---

## 9. SAML

### 9.1 First Principles

**SAML (Security Assertion Markup Language)** is an XML-based standard for exchanging authentication and authorization assertions between an **Identity Provider (IdP)** and a **Service Provider (SP)**. It predates OAuth/OIDC and remains dominant in large enterprise SSO (Okta, Active Directory Federation Services / ADFS, PingFederate) because of its maturity and strong enterprise tooling support.

### 9.2 The SP-Initiated Flow

```
 User           Service Provider (SP)        Identity Provider (IdP)
  │                     │                            │
  │── access app ──────►│                             │
  │                     │── AuthnRequest (redirect) ─►│
  │◄─────────── redirected to IdP login ──────────────┤
  │── credentials ─────────────────────────────────────►│
  │                     │     IdP authenticates user   │
  │◄──── SAML Response (signed XML Assertion) ──────────┤
  │── POST assertion ──►│                             │
  │                     │  SP validates signature,     │
  │                     │  trusts assertion, logs in   │
```

### 9.3 Anatomy of a SAML Assertion (Simplified)

```xml
<saml:Assertion ID="_a1b2c3" IssueInstant="2026-06-28T10:00:00Z">
  <saml:Issuer>https://idp.corp.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID>jdoe@corp.com</saml:NameID>
  </saml:Subject>
  <saml:Conditions NotBefore="..." NotOnOrAfter="...">
    <saml:AudienceRestriction>
      <saml:Audience>https://app.example.com</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <ds:Signature>...</ds:Signature> <!-- XML digital signature -->
</saml:Assertion>
```

### 9.4 Golden SAML — The Most Important Attack in This Section

**Golden SAML** is to SAML what Golden Ticket (Section 10) is to Kerberos. If an attacker compromises the **IdP's private signing key/certificate** (e.g., the ADFS token-signing certificate), they can **forge arbitrary SAML assertions offline**, impersonating *any user, with any attributes, for any service provider*, without ever touching the real IdP, leaving no IdP-side authentication log.

This is exactly what investigators concluded happened in the **SolarWinds/Sunburst breach (2020)**: APT29 (Cozy Bear) extracted ADFS signing material from compromised environments and minted forged SAML tokens to access Microsoft 365 and other federated cloud services as any user they chose — entirely bypassing MFA, because MFA had already been satisfied "upstream" in the forged assertion's trust chain.

```bash
# Conceptual structure of a Golden SAML forgery (illustrative, not exploit code):
# 1. Attacker extracts the IdP's private signing certificate (e.g. from
#    AD FS server's certificate store or DKM container in AD)
# 2. Attacker crafts an arbitrary SAML assertion XML naming any user/claims
# 3. Attacker signs that XML with the stolen private key
# 4. Attacker submits the forged, validly-signed assertion directly to the SP
# 5. SP validates signature against the IdP's known public cert --> SUCCEEDS
#    because the signature IS cryptographically valid, just illegitimately produced
```

### 9.5 XML-Specific Attack Classes

- **XML Signature Wrapping (XSW)** — exploiting parsers that validate the signature against one part of the XML document tree but then *process* a different, attacker-modified part, effectively smuggling forged claims past a technically-valid signature.
- **XXE (XML External Entity) injection** — if the SP's XML parser resolves external entities, an attacker can exfiltrate local files or trigger SSRF via a crafted assertion.

### 9.6 Defensive Controls

- **Protect the IdP signing key like a root CA private key** — hardware security module (HSM) storage, strict access control, key rotation, and dedicated monitoring of the certificate store/DKM container.
- Always validate `AudienceRestriction`, `NotBefore`/`NotOnOrAfter`, and the assertion's `Issuer` — never accept an otherwise-valid-signature assertion outside its intended audience or time window.
- Use **schema-validating, hardened XML parsers** that disable external entity resolution by default.
- Monitor for **IdP signing certificate export/access events** (e.g., Windows Event ID 4662 against the ADFS DKM container) as a critical, rare, high-fidelity alert.

### 9.7 Forensic Evidence

The chilling property of Golden SAML is that **forged assertions generate no corresponding authentication event at the real IdP** — your hunting target shifts to the **Service Provider's** logs: an assertion accepted with no matching upstream IdP sign-in event is the core indicator. Also monitor for anomalous `NotOnOrAfter` windows far outside policy norms, suggesting a hand-crafted (not naturally issued) assertion.

### 9.8 OT/ICS Perspective

Large industrial operators frequently federate **OT vendor support portals and engineering-cloud platforms** through the same corporate ADFS/SAML IdP used for everything else. A Golden SAML compromise at the corporate IdP therefore can directly cascade into OT-adjacent vendor platforms — this is a strong architectural argument for a **separate, isolated IdP trust boundary** for anything touching OT vendor federation, rather than a single flat corporate-wide IdP trust.

> **Retain this:** A valid cryptographic signature proves the assertion was signed by the holder of that key — it proves nothing about whether that signing event was legitimate. Protecting the signing key is more important than any single control downstream of it.

---

## 10. Kerberos

### 10.1 First Principles

Kerberos is a **ticket-based authentication protocol** built on **symmetric cryptography** and a trusted third party (the Key Distribution Center, KDC). Its core innovation: a user proves their identity *once* and receives a ticket usable to access multiple services *without re-sending their password*, and *without the service itself ever learning the password*.

### 10.2 The Three Heads of Kerberos (named for Cerberus, the three-headed guard dog)

```
   Client            KDC: Authentication       KDC: Ticket Granting
                      Server (AS)                Service (TGS)
     │                     │                          │
     │── AS-REQ (user) ───►│                           │
     │◄── AS-REP (TGT) ────┤                           │
     │                     │                           │
     │── TGS-REQ (TGT, target service) ───────────────►│
     │◄── TGS-REP (Service Ticket) ─────────────────────┤
     │                                                  │
     │── AP-REQ (Service Ticket) ──► Target Service     │
     │◄── AP-REP (mutual auth) ─────                    │
```

- **AS-REQ/AS-REP** — client requests a **Ticket Granting Ticket (TGT)**, encrypted with a key derived from the user's password hash (for the krbtgt-related secret) — this is the *initial* authentication.
- **TGT** — proves "this user authenticated successfully" without needing to re-prove the password for every subsequent request, typically valid ~10 hours by default in AD environments.
- **TGS-REQ/TGS-REP** — client presents the TGT to request a **Service Ticket** for a specific resource (e.g., a file server), encrypted with that *service's* own secret key, derived from the service account's password hash.
- **AP-REQ** — client presents the Service Ticket directly to the target service, which decrypts it with its own key and grants access — the service never talks to the KDC directly per request and never sees the user's password.

### 10.3 Golden Ticket Attack

If an attacker compromises the **krbtgt account's password hash** (the domain-wide secret used to encrypt all TGTs), they can forge a TGT for **any user, including non-existent users, with any group membership, with any lifetime** — entirely offline, without contacting a Domain Controller at forgery time. This is **complete and unrecoverable domain authentication compromise** unless the krbtgt password is reset (twice, due to password-history-based ticket validity).

```
# Conceptual flow (Mimikatz-style tooling, real technique, name only — not
# operational exploit code):
1. Attacker achieves Domain Admin (or DCSync rights) once.
2. Attacker extracts the krbtgt account's NTLM hash via DCSync
   (replicating AD secrets through legitimate replication APIs, abused).
3. Attacker forges a TGT offline using that hash for arbitrary identity/groups.
4. Forged TGT is accepted by any DC indefinitely, until krbtgt is rotated.
```

### 10.4 Silver Ticket Attack

Similar concept, but scoped to a **single service** — the attacker only needs that *service account's* password hash (not krbtgt), and forges a Service Ticket directly, bypassing the TGS step entirely. Narrower blast radius than Golden Ticket, but harder to detect because **it never touches the KDC at all** — TGS-REQ/TGS-REP events simply never occur.

### 10.5 Kerberoasting

```
Any authenticated domain user can request a Service Ticket for ANY
service principal in the domain — that's by design, not a bug.

Attacker requests Service Tickets for accounts with SPNs set
(commonly service accounts running databases, web apps, etc.)
   │
   ▼
Service Ticket is encrypted with the SERVICE ACCOUNT's password hash
   │
   ▼
Attacker takes that ticket OFFLINE and brute-forces it with hashcat —
no further domain interaction needed, no lockout risk, no further alerts
```

```bash
# Hashcat mode for Kerberos 5 TGS-REP etype 23 (RC4) — the classic
# Kerberoasting crack target, because RC4-encrypted tickets are crackable
# at high speed if the service account's password is weak
hashcat -m 13100 -a 0 kerberoast_hashes.txt rockyou.txt
# -m 13100 : Kerberos 5 TGS-REP etype 23
# -a 0     : dictionary attack mode
```

This is precisely why **service account password strength** matters disproportionately — these accounts are frequently set once at deployment, never rotated, and often massively over-privileged.

### 10.6 Pass-the-Ticket

Stealing a valid TGT or Service Ticket directly from memory (e.g., via Mimikatz's `sekurlsa::tickets`) and **injecting it into a different session/host** to impersonate the victim without ever knowing their password — the ticket itself is the credential.

### 10.7 Defensive Controls

- **Rotate the krbtgt password twice**, on a recurring schedule and immediately after any suspected Domain Admin compromise (rotating only once leaves the *previous* password's tickets valid through password history).
- Enforce **long, random passwords on service accounts** (25+ characters) specifically to defeat Kerberoasting — or migrate to **Group Managed Service Accounts (gMSA)**, whose passwords are automatically rotated and never human-known.
- Monitor for **abnormal TGS-REQ volume** from a single account in a short window (Event ID 4769 with ticket encryption type RC4 specifically is a strong Kerberoasting signal — AES-encrypted tickets are far more crack-resistant, so legacy RC4 use is itself a red flag).
- Restrict and monitor **DCSync rights** (`Replicating Directory Changes` / `Replicating Directory Changes All`) — only Domain Controllers and explicitly authorized accounts should ever hold these.
- Enable **Protected Users group** and **Credential Guard** to prevent ticket/credential extraction from memory on modern Windows.

### 10.8 Forensic Evidence

- **Event ID 4768** (TGT requested), **4769** (Service Ticket requested), **4770** (Service Ticket renewed) on Domain Controllers.
- Golden Ticket indicator: a TGT with a **lifetime far exceeding domain policy**, or referencing a **user that no longer exists / was deleted**.
- Kerberoasting indicator: a single account generating **many 4769 events with RC4 encryption (etype 0x17)** across many different SPNs in a short period.

### 10.9 OT/ICS Perspective

OT environments running Windows-based SCADA/HMI servers joined to a corporate Active Directory domain inherit **every one of these Kerberos risks directly**. A Kerberoasted service account tied to a SCADA application server can grant an attacker a foothold that bridges IT compromise straight into OT supervisory control — this is a documented lateral-movement pattern in ICS incident response case studies (e.g., patterns described in ICS-CERT/CISA advisories following ransomware intrusions into hybrid IT/OT Windows domains). Where feasible, OT-tier Windows servers should join a **separate, isolated forest/domain** rather than the corporate forest, specifically to contain Kerberos-based lateral movement.

> **Retain this:** Kerberos tickets, not passwords, are the actual currency of post-compromise lateral movement in Windows domains — defending the krbtgt secret and service account hygiene matters more than any single password policy.

---

## 11. NTLM

### 11.1 First Principles

**NTLM (NT LAN Manager)** is Microsoft's legacy challenge-response authentication protocol, predating Kerberos in Windows environments and still present today for backward compatibility, workgroup (non-domain) authentication, and certain legacy application support.

### 11.2 The Challenge-Response Flow

```
Client                              Server
  │── NEGOTIATE_MESSAGE ────────────►│
  │◄── CHALLENGE_MESSAGE (nonce) ────┤
  │── AUTHENTICATE_MESSAGE ─────────►│
  │   (response = HMAC of nonce      │
  │    using NTLM hash of password)  │
  │                                  │  Server validates response
  │                                  │  against its own copy of the
  │                                  │  NTLM hash (or relays to a DC)
```

Crucially, the **NTLM hash itself (MD4 of the password, no salt)** is the long-term secret — and because it's used directly in the HMAC computation, **possessing the hash is functionally equivalent to possessing the password** for authentication purposes. You never need to crack it.

### 11.3 Pass-the-Hash

```bash
# Conceptual technique only — Pass-the-Hash means authenticating using a
# captured NTLM hash directly, with NO password cracking required:
#
# 1. Attacker dumps LSASS memory or SAM/NTDS.dit, obtains NTLM hash
# 2. Attacker uses that raw hash directly in an NTLM authentication exchange
#    (e.g., via tools like Impacket's psexec.py / wmiexec.py using -hashes)
python3 wmiexec.py -hashes :NTLM_HASH_HERE administrator@10.0.0.5
# -hashes <LM:NTLM>  : supplies the captured hash directly, bypassing
#                       any need to ever know or crack the plaintext password
```

This is one of the single most consequential techniques in Windows lateral movement, because **local administrator password reuse across many machines** (extremely common in unmanaged enterprise fleets) turns ONE compromised endpoint into domain-wide reach.

### 11.4 NTLM Relay

```
Attacker positions as a man-in-the-middle (e.g. via LLMNR/NBT-NS spoofing
with Responder, or a malicious SMB/HTTP server):

 Victim Client          Attacker (relay)          Target Server
     │── auth attempt ───────►│                          │
     │                        │── relays the SAME ──────►│
     │                        │   challenge-response      │
     │                        │   to a DIFFERENT server   │
     │                        │◄── target authenticates ──┤
     │                        │    the relayed session AS │
     │                        │    the victim, NO hash     │
     │                        │    cracking needed          │
```

This is the mechanism behind tools like **Responder** (LLMNR/NBT-NS/MDNS poisoning to harvest or relay NTLM auth attempts) and **ntlmrelayx** (Impacket) — and it was a primary lateral-movement vector during **NotPetya (2017)**, where stolen credentials and NTLM-based authentication allowed the worm to self-propagate across Maersk's and Merck's networks at devastating speed, in part because **SMB signing was not enforced** on many internal hosts, allowing relay attacks to succeed.

### 11.5 Why NTLM Is Fundamentally Weaker Than Kerberos

| Property | NTLM | Kerberos |
|---|---|---|
| Mutual authentication | No (client can't verify server) | Yes |
| Relay resistance | Weak (no built-in channel binding by default) | Strong (ticket bound to specific service) |
| Hash reuse across machines | Catastrophic if local admin reused | Per-service ticket secrets |
| Delegation model | Crude / risky | Constrained delegation supported |

### 11.6 Defensive Controls

- **Disable NTLM entirely where possible**; at minimum, enforce **NTLMv2** only (never LM or NTLMv1) via Group Policy.
- **Enforce SMB Signing** domain-wide — this is the single most impactful control against NTLM relay, as it cryptographically binds each SMB message and breaks naive relay.
- **Enforce LDAP signing and channel binding** to prevent LDAP relay (a related, equally damaging relay target).
- Eliminate **local administrator password reuse** across endpoints — use **LAPS (Local Administrator Password Solution)** to randomize and rotate local admin passwords per-machine automatically.
- Disable **LLMNR and NBT-NS** broadcast name resolution where not operationally required, removing Responder's primary poisoning surface.

### 11.7 Forensic Evidence

- **Event ID 4624** (logon) with **Logon Type 3 (network)** and **Authentication Package: NTLM** at unexpected volume or from unexpected source hosts.
- A single source host authenticating as **many distinct user accounts** in rapid succession — strong Pass-the-Hash/credential-spray indicator.
- Unusual LLMNR/NBT-NS broadcast traffic spikes on the wire — Responder activity signature, visible in network capture/IDS.

### 11.8 OT/ICS Perspective

Many legacy OT Windows systems (Windows XP/7-era HMI software still in production due to vendor certification lock-in) **cannot be upgraded away from NTLM** and often cannot even support SMB signing without breaking vendor-certified application compatibility. This is a textbook case of **accepting a known protocol weakness and compensating architecturally**: isolate these legacy NTLM-dependent hosts on a dedicated, tightly firewalled VLAN with no direct reachability from general IT, and route any necessary IT-to-OT administrative access exclusively through a PAM jump host (Section 13) rather than direct NTLM-authenticated access.

> **Retain this:** NTLM's design flaw isn't weak cryptography per se — it's the absence of mutual authentication and channel binding, which is precisely what makes relay attacks possible. SMB/LDAP signing is the cheapest, highest-impact mitigation in any Windows environment still running NTLM.

---

## 12. Single Sign-On (SSO)

### 12.1 First Principles

SSO lets a user authenticate **once** to a central Identity Provider and gain access to **multiple independent applications** without re-authenticating to each. Every protocol covered so far — SAML, OIDC, Kerberos — is a *mechanism* by which SSO is technically implemented; SSO itself is the **architectural pattern**, not a protocol.

### 12.2 The Security Trade-off, Stated Plainly

```
            BENEFIT                          RISK
   ───────────────────────         ──────────────────────────
   Fewer passwords to manage        ONE compromised IdP account
   Centralized MFA enforcement      = access to EVERY connected
   Centralized audit trail          application simultaneously
   Faster offboarding (one          ("keys to the kingdom" problem)
   disable = all access revoked)
```

This is not a reason to avoid SSO — fragmented, non-SSO environments are *empirically worse* (more password reuse, inconsistent MFA, slower offboarding leaving orphaned accounts). It is a reason to **invest disproportionately in protecting the IdP itself**.

### 12.3 Architecture Pattern

```
                         ┌─────────────────┐
                         │  Identity        │
              ┌──────────│  Provider (IdP)  │──────────┐
              │          │  Okta/Azure AD/  │           │
              │          │  ADFS/Ping       │           │
              ▼          └─────────────────┘           ▼
      ┌──────────────┐                         ┌──────────────┐
      │  App A (SAML) │                         │  App B (OIDC) │
      └──────────────┘                         └──────────────┘
```

### 12.4 Real-World Failure: Cloud Identity Provider Compromise

The **Okta breach (2022, via a third-party support engineer's compromised laptop)** and the **Okta source-code-repo breach (2023, customer support system compromised, session tokens for some customers exposed)** are the canonical illustrations of the SSO concentration risk: when the IdP vendor itself is compromised, the blast radius extends to **every downstream customer organization simultaneously**.

### 12.5 Defensive Controls

- Treat the IdP as your **single highest-value asset** — disproportionate monitoring, phishing-resistant MFA mandatory for all IdP admins, and a dedicated incident response runbook specifically for IdP compromise scenarios.
- Implement **conditional access policies** (device compliance, geolocation, risk scoring) at the IdP layer, since this is now the single enforcement point for *everything*.
- Maintain a **documented emergency break-glass account** outside normal SSO flow, with offline-stored credentials, for the scenario where the IdP itself is unavailable or compromised.
- Regularly **audit connected application consent grants** at the IdP — orphaned, over-scoped, or unused application integrations are a common, overlooked attack surface.

### 12.6 Forensic Evidence

IdP admin-action logs (role/policy changes, new application registrations, signing certificate access) are your highest-priority log source in the entire identity stack — any anomaly here has organization-wide blast radius and should carry the highest alerting priority in your SIEM.

### 12.7 OT/ICS Perspective

Extending corporate SSO into OT-adjacent systems (engineering workstation logins, vendor support portals) is increasingly common for usability — but it directly imports the "one IdP compromise = total access" risk into the OT domain. The architectural answer used by mature OT security programs: a **separate, dedicated OT-tier IdP** (or at minimum a separate trust realm/forest) federated *narrowly and explicitly* to corporate SSO only for specific, audited use cases — never a flat, fully-trusted extension of the corporate IdP into OT.

> **Retain this:** SSO doesn't eliminate identity risk — it concentrates it. Concentration is good only if you invest proportionally in protecting the single point you've created.

---

## 13. Privileged Access Management (PAM)

### 13.1 First Principles

PAM is the discipline and toolset for controlling, monitoring, and auditing access by **accounts with elevated privilege** — Domain Admins, root, database admins, network device admins, OT engineering accounts. The core insight: **privileged accounts are disproportionately responsible for breach severity**, even though they're a small minority of total accounts. Nearly every major breach's *impact* (not necessarily initial access) traces to privileged credential abuse.

### 13.2 Core PAM Capabilities

```
┌────────────────────────────────────────────────────────────────┐
│ 1. VAULTING        Privileged credentials stored encrypted,     │
│                     never known by the human user directly       │
│ 2. JUST-IN-TIME     Privilege granted temporarily, for a          │
│    ACCESS (JIT)     specific task, then automatically revoked     │
│ 3. SESSION          All privileged sessions proxied through a    │
│    BROKERING        jump host, recorded, and monitorable live    │
│ 4. CREDENTIAL       Privileged passwords auto-rotated after       │
│    ROTATION         every checkout/use, so a stolen credential    │
│                     is valid for only one session                │
│ 5. LEAST            Privilege scoped to the minimum necessary     │
│    PRIVILEGE        task, time window, and target system          │
└────────────────────────────────────────────────────────────────┘
```

### 13.3 The Standing Privilege Problem

```
TRADITIONAL MODEL:                    PAM/JIT MODEL:
Admin account is ALWAYS               Admin requests elevation for
privileged, 24/7, whether              a specific task --> approved
in use or not                          (manually or policy-based) -->
                                        privilege granted for a defined
ATTACK SURFACE: large,                 window (e.g. 1 hour) --> auto-
constant, always exploitable           revoked
                                       ATTACK SURFACE: small, time-
                                        boxed, requires active task
```

Standing privileged access is precisely what attackers seek post-initial-access: in nearly every domain-wide ransomware case, the time between initial foothold and Domain Admin acquisition is the critical window — and PAM's purpose is to make that acquisition either impossible (no standing privileged credentials to steal) or immediately detectable (every privileged session is recorded and alertable).

### 13.4 Architecture: The Privileged Access Workstation (PAW) + Jump Host Model

```
Administrator's          Privileged Access      Target Privileged
regular workstation      Workstation (PAW) /     System (DC, SCADA
(email, browsing,        Jump Host                server, etc.)
general use)              (hardened, no            
                          internet/email,
     │                    MFA-gated,
     │  NO DIRECT          session-recorded)
     │  PRIVILEGED              │
     │  ACCESS ─────X           │
                                  │── brokered, recorded,
                                     time-boxed session ──►
```

The principle: **the workstation used for everyday email/browsing must never be the same workstation used for privileged administrative access** — this single architectural separation defeats the single most common ransomware escalation pattern (phishing on the daily-use workstation leading directly to credential theft of an admin session active on the same machine).

### 13.5 PAM Tooling Landscape

CyberArk, BeyondTrust, Delinea (formerly Thycotic), HashiCorp Vault (secrets management, often complementary to full PAM suites), and native cloud equivalents (AWS IAM Roles + Session Manager, Azure PIM — Privileged Identity Management) all implement variations of the above capabilities. **Azure PIM** is a particularly instructive cloud-native example of JIT: roles like Global Administrator can be configured as **eligible** rather than **active**, requiring explicit, time-boxed, justification-logged activation per use.

```bash
# Example: Azure PIM CLI-style role activation request (illustrative)
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests" \
  --body '{
    "action": "selfActivate",
    "principalId": "<user-object-id>",
    "roleDefinitionId": "<role-id>",
    "directoryScopeId": "/",
    "justification": "Investigating ticket INC1234",
    "scheduleInfo": { "expiration": { "duration": "PT1H" } }
  }'
# duration": "PT1H"  -- ISO 8601 duration: this elevation expires
#                       automatically after exactly 1 hour
```

### 13.6 Detecting PAM Bypass / Misuse

- **Direct authentication to privileged accounts outside the PAM checkout workflow** (i.e., a Domain Admin login event with no corresponding PAM vault checkout record) is one of the highest-fidelity indicators of either a PAM gap or active credential theft.
- **Session recording gaps** (a privileged session with no corresponding video/keystroke log, due to misconfiguration or tampering) should themselves trigger an alert — an attacker disabling session recording before activity is a documented technique in mature intrusions.

### 13.7 Defensive Controls

- Eliminate all **standing/permanent privileged group memberships** where JIT is feasible.
- Enforce **PAW separation** — privileged sessions only from hardened, isolated jump hosts.
- **Auto-rotate** every privileged credential after each checkout, regardless of whether misuse is suspected.
- **Record and retain** all privileged sessions, with tamper-evident storage (write-once or hashed/chained logs) and a defined retention period meeting your compliance/forensic requirements.
- Apply PAM principles to **service accounts and API keys**, not just human admins — non-human privileged identities are an increasingly dominant share of real-world privilege in modern environments and are routinely under-governed.

### 13.8 Forensic Evidence

Cross-reference PAM vault checkout/checkin logs against actual authentication events on target systems — any privileged authentication **without** a matching, time-adjacent vault checkout is your single most actionable PAM-layer detection rule, and should be a standing, always-on correlation rule in your SIEM.

### 13.9 OT/ICS Perspective — This Is the Most Important Subsection in the Module for This Specialization

PAM is arguably **the single highest-leverage control for IT/OT boundary security**, because it directly addresses the Colonial Pipeline pattern: a remote, standing credential with no MFA, no session recording, no time-boxing, bridging directly into OT-adjacent infrastructure.

```
RECOMMENDED OT PAM ARCHITECTURE:

   IT Network                  DMZ / PAM Layer              OT Network
  ┌──────────┐               ┌─────────────────┐          ┌───────────┐
  │ Vendor/   │               │  PAM Jump Host /  │          │  HMI /     │
  │ Engineer  │──MFA-gated──►│  Privileged       │──brokered│  SCADA /   │
  │ remote    │  request      │  Session Broker   │ recorded │  PLC       │
  │ access    │               │  (time-boxed,      │ session  │  engineer  │
  └──────────┘               │   credential        │─────────►│  station   │
                              │   vaulted, never     │          └───────────┘
                              │   known to user)      │
                              └─────────────────┘
```

Key OT-specific PAM design points:
- **Vendor remote access** (the Colonial Pipeline-class scenario) must *never* terminate directly inside the OT network — it must terminate at a PAM-brokered jump host in a DMZ, with the OT-side credential never disclosed to the vendor, fully time-boxed to the maintenance window, and fully session-recorded.
- **Standing OT vendor VPN accounts**, active 24/7/365 "just in case," are a documented recurring finding in ICS security assessments and represent exactly the standing-privilege risk PAM/JIT is designed to eliminate.
- Session recording in OT must be configured to **never interfere with real-time control-system performance or safety system response times** — PAM brokering should be architected at the engineering-access layer (HMI/workstation access), never inline with control-loop communication (PLC-to-PLC, controller-to-I/O), where latency or a broker outage could itself create a safety hazard. Know this distinction precisely: PAM governs **who can open an engineering session**, not the deterministic control traffic underneath it.
- Maintain **documented break-glass procedures** for emergency OT access scenarios where the PAM layer itself is unavailable (e.g., during a wide-scale IT outage) — OT operability must never be hostage to an IT identity system outage, but break-glass use must be logged and reviewed after every use without exception.

> **Retain this:** Colonial Pipeline was not a sophisticated attack — it was one standing, MFA-less, unrotated VPN credential. PAM exists specifically to make that scenario architecturally impossible, and in OT environments, it is the single highest-return control you can implement at the IT/OT boundary.

---

## 14. The Missing Layer: Directory Services & Identity Federation Architecture

This subtopic is not in the original outline but is essential — every protocol above (Kerberos, NTLM, SAML, OIDC) ultimately reads from a **directory**: Active Directory, LDAP, Azure AD/Entra ID, or a cloud-native identity store. Understanding *where identity actually lives* is the connective layer the rest of this module assumes.

### 14.1 LDAP — The Underlying Data Layer

Active Directory is, at its data layer, an **LDAP (Lightweight Directory Access Protocol)** directory. Every user, group, computer, and policy object is an LDAP entry with a Distinguished Name (DN):

```
CN=John Doe,OU=Finance,DC=corp,DC=local
```

```bash
# Querying AD via LDAP from Linux — common in both legitimate admin work
# and attacker reconnaissance (this is exactly how tools like BloodHound
# pull their raw data)
ldapsearch -x -H ldap://dc01.corp.local \
  -D "CN=jdoe,OU=Finance,DC=corp,DC=local" -w 'password' \
  -b "DC=corp,DC=local" "(objectClass=user)" memberOf
# -x : simple authentication
# -H : target LDAP server
# -D : bind DN (the authenticating account)
# -b : search base (where in the directory tree to start)
```

**LDAP injection** and **unauthenticated/anonymous LDAP bind misconfigurations** remain a recurring finding category — anonymous bind allowing full directory enumeration is a critical, frequently overlooked exposure in legacy environments.

### 14.2 BloodHound — Why Directory Enumeration Matters Offensively and Defensively

BloodHound maps AD trust and permission relationships as a graph, revealing **non-obvious attack paths** (e.g., User A is in Group B, which has GenericAll rights over Group C, which is a member of Domain Admins) that no flat permission list would surface. Defensively, **running BloodHound against your own environment** is now considered standard practice — you cannot defend an attack path you don't know exists.

### 14.3 Trust Relationships and Their Risk

```
Forest A  ◄──── two-way trust ────►  Forest B

If Forest B is compromised, and the trust is improperly scoped
(not using SID filtering / selective authentication), an attacker
can potentially traverse INTO Forest A using forged or stolen
credentials/tickets that cross the trust boundary.
```

> **Retain this:** Every authentication protocol in this module is a *consumer* of a directory service — securing the directory itself (LDAP hardening, trust scoping, anonymous bind elimination) is a prerequisite for every other control in this module to mean anything.

---

## 15. OT/ICS-Wide Identity Considerations

Consolidating the cross-cutting OT themes from every section above into explicit, standalone guidance:

1. **Identity systems in OT must never become a single point of operational failure.** A control-room operator must always be able to act during a safety event, even if the corporate identity stack is down. Design break-glass paths deliberately, not as an afterthought.
2. **Vendor remote access is the dominant real-world OT initial-access vector** (Colonial Pipeline being the most-cited example) — PAM-brokered, time-boxed, MFA-gated, never-standing access is the highest-leverage single investment in this entire module for OT environments.
3. **Legacy protocol support (NTLM, weak Kerberos encryption types) often cannot be removed from OT due to vendor certification constraints** — the correct response is network-layer and PAM-layer compensating control, not pretending the legacy protocol isn't there.
4. **Separate identity trust boundaries between IT and OT** (separate AD forest/domain, separate IdP realm) contain the blast radius of an IT-side identity compromise from automatically becoming an OT-side compromise — this single architectural decision determined the difference in outcome between organizations that contained Colonial-Pipeline-style intrusions to IT and those where it reached OT.
5. **Physical and digital identity correlation matters in OT** — badge/biometric access logs to a control room should be correlated with HMI/SCADA session logs during incident investigation; insider-threat and safety-incident investigations in industrial settings rely on this correlation routinely.

---

## 16. Module Summary Table

| Concept | Core Function | Primary Offensive Technique | Primary Defensive Control | OT/ICS Note |
|---|---|---|---|---|
| Password Policies | Shared-secret proof of identity | Spraying, offline cracking | Length over complexity, breach-list screening, Argon2id storage | Avoid blind lockout policies on safety-critical HMI accounts |
| MFA | Second independent proof factor | Push fatigue, AiTM phishing, SIM swap | FIDO2/WebAuthn, number-matching push | Enforce MFA at IT/OT jump-host boundary, not inside OT itself |
| Biometrics | Trait-based identity proof | Spoofing/presentation attacks | Liveness detection, on-device template storage, second factor | Used for physical control-room access; correlate with session logs |
| Token-Based Auth | Bearer credential post-login | `alg:none`/algorithm confusion, token theft | Algorithm pinning, short lifetimes, httpOnly cookies | Scope and monitor OT-to-cloud telemetry tokens tightly |
| OAuth 2.0 | Delegated authorization | Redirect URI manipulation, CSRF (missing `state`) | Exact redirect allow-listing, PKCE, least-privilege scope | Audit vendor OAuth app consent grants regularly |
| OpenID Connect | Identity layer atop OAuth | Missing `aud`/`iss` validation, ID token replay | Validate all claims, use `nonce`, pin trusted issuers | Validate cloud HMI portal token audience scoping |
| SAML | XML-based federated assertions | Golden SAML, XML Signature Wrapping | HSM-protect signing keys, validate audience/time window | Isolate OT-vendor federation from core corporate IdP trust |
| Kerberos | Ticket-based domain authentication | Golden/Silver Ticket, Kerberoasting, Pass-the-Ticket | krbtgt rotation, gMSA, monitor 4769/RC4 etype | Separate forest/domain for OT Windows servers |
| NTLM | Legacy challenge-response auth | Pass-the-Hash, NTLM Relay | SMB/LDAP signing, disable LLMNR/NBT-NS, LAPS | Compensate via network isolation for legacy OT hosts |
| SSO | Single authentication, multiple apps | IdP vendor compromise, consent grant abuse | Disproportionate IdP hardening, conditional access, break-glass account | Dedicated OT-tier IdP, narrowly federated |
| PAM | Controls/monitors privileged access | Standing credential theft, direct-to-privileged login | JIT access, session recording, credential rotation, PAW separation | Brokered, time-boxed vendor remote access; never inline with control traffic |
| Directory Services (LDAP/AD) | Underlying identity data store | LDAP injection, anonymous bind enumeration, BloodHound mapping | Disable anonymous bind, SID filtering on trusts, self-audit with BloodHound | Prerequisite hardening for every other OT identity control |

---

## 17. Navigation

⬅ Previous: [Module 2.2 — Network Security Fundamentals](#)
➡ Next: [Module 2.4 — Endpoint Security and Hardening](#)

---

*Bytewall Academy — Cybersecurity × OT/ICS Security Roadmap. This module is part of a continuously maintained open reference series. Contributions, corrections, and CVE updates are welcome via pull request.*