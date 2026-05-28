<div align="center">

# 🛡️ Bytewall Academy

### A Complete Cybersecurity & OT/ICS Security Roadmap
#### From Zero to Professional — Structured, Deep, Uncompromising

[![Stages](https://img.shields.io/badge/Stages-18-blue?style=flat-square)](.)
[![Focus](https://img.shields.io/badge/Specialisation-OT%2FICS%20Security-red?style=flat-square)](./STAGE-12_OT-SCADA-ICS)
[![Language](https://img.shields.io/badge/Language-English-green?style=flat-square)](.)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](./LEGAL.md)

</div>

---

## What This Is

This is not a cheat sheet collection. It is not a list of tools with one-line descriptions. It is not another "learn hacking in 30 days" resource.

This repository is a structured, long-form learning roadmap built around one goal: producing a security professional who understands **why** things work, not just **how** to run them. Every module is written to take a concept from its foundations to its real-world security implications — with the attack perspective, the defence perspective, and the forensic perspective covered in the same place.

The primary specialisation target is **OT/ICS Security** — the intersection of cybersecurity and operational technology (industrial control systems, SCADA, power grids, building automation, critical infrastructure). This is one of the rarest and most in-demand profiles in the global security industry. The roadmap builds toward it systematically, ensuring that by Stage 12, the concepts are not abstract — they are grounded in everything that came before.

---

## Roadmap Structure

| Stage | Title | Status |
|-------|-------|--------|
| [STAGE-00](./STAGE-00_Foundations) | **Foundations** — Hardware, OS, Windows, Linux, Programming | 🟡 In Progress |
| [STAGE-01](./STAGE-01_Network-Fundamentals) | **Network Fundamentals** — OSI, TCP/IP, Protocols, Analysis | ⬜ Upcoming |
| [STAGE-02](./STAGE-02_CyberSecurity-Fundamentals) | **Cybersecurity Core** — CIA, Cryptography, IAM, Frameworks | ⬜ Upcoming |
| [STAGE-03](./STAGE-03_Offense-and-Defense) | **Attack Methods & Defence** — Malware, Social Engineering, Web Attacks | ⬜ Upcoming |
| [STAGE-04](./STAGE-04_Penetration-Testing) | **Penetration Testing** — Methodology, OSINT, Exploitation, Reporting | ⬜ Upcoming |
| [STAGE-05](./STAGE-05_Network-Security) | **Network Security** — Firewall, IDS/IPS, VPN, Segmentation | ⬜ Upcoming |
| [STAGE-06](./STAGE-06_Web-Application-Security) | **Web Application Security** — OWASP Top 10, Burp Suite, Secure Dev | ⬜ Upcoming |
| [STAGE-07](./STAGE-07_Active-Directory) | **Active Directory Security** — Kerberos, BloodHound, AD Attacks | ⬜ Upcoming |
| [STAGE-08](./STAGE-08_Cloud-Security) | **Cloud Security** — AWS, Azure, GCP, Kubernetes | ⬜ Upcoming |
| [STAGE-09](./STAGE-09_Incident-Response-Forensics) | **IR & Digital Forensics** — Memory, Disk, Malware Analysis, SIEM | ⬜ Upcoming |
| [STAGE-10](./STAGE-10_SOC) | **SOC Operations** — Threat Hunting, CTI, SOAR | ⬜ Upcoming |
| [STAGE-11](./STAGE-11_Hardening) | **System Hardening** — Windows, Linux, Network Devices | ⬜ Upcoming |
| [STAGE-12](./STAGE-12_OT-SCADA-ICS) | **OT/SCADA/ICS Security** ⭐ — Protocols, Architecture, Real-World Cases | ⬜ Upcoming |
| [STAGE-13](./STAGE-13_Red-Team) | **Red Team Operations** — C2, Adversary Simulation, Physical | ⬜ Upcoming |
| [STAGE-14](./STAGE-14_Blue-Team-Advanced) | **Advanced Blue Team** — Threat Modelling, Deception, Architecture | ⬜ Upcoming |
| [STAGE-15](./STAGE-15_Development-Automation) | **Development & Automation** — Python, Bash, PowerShell, Tool Dev | ⬜ Upcoming |
| [STAGE-16](./STAGE-16_Advanced-Topics) | **Advanced Topics** — Reverse Engineering, Exploit Dev, Mobile, IoT | ⬜ Upcoming |
| [STAGE-17](./STAGE-17_Career-Certifications) | **Career & Certifications** — OSCP, GICSP, CISSP, Job Strategy | ⬜ Upcoming |
| [STAGE-18](./STAGE-18_Platforms-Resources) | **Platforms & Resources** — TryHackMe, HTB, CTF, Communities | ⬜ Upcoming |

> ⭐ **Stage 12 is the primary specialisation target.** OT/ICS security sits at the intersection of cybersecurity and physical engineering — covering power grids, industrial control systems, SCADA, building automation, and critical infrastructure. Every stage before it builds the foundation that makes Stage 12 not just understandable but immediately applicable.

---

## What Makes This Different

**Depth over breadth.**
Most resources explain what a buffer overflow is. This roadmap explains what a buffer overflow is, why the stack is laid out the way it is, how NX/DEP changed the attack surface, why ROP chains exist as a direct response, and how a modern EDR detects the technique at the system call level. Then it gives you exercises to see it yourself.

**Attack and defence in the same place.**
Understanding an attack technique and understanding how to detect and prevent it are not separate subjects. They are the same subject viewed from different angles. Every module covers both.

**OT/ICS as a first-class citizen.**
Industrial security is not an afterthought appended to a general security course. It is the destination this roadmap is built toward. The electrical and physical systems perspective is woven into modules from Stage 00 onward — because the most dangerous vulnerabilities in OT environments are at exactly the intersection of physical and digital knowledge.

**No shortcuts.**
If a concept requires understanding three other concepts first, those three concepts are explained first. If a topic is complex, it gets the space it needs. Nothing is oversimplified to the point of being misleading.

---

## Who This Is For

This roadmap is built for someone who:
- Is entering cybersecurity from a technical background (programming, electrical, networking, IT)
- Wants to understand systems deeply, not just use tools
- Has a long-term goal in offensive security, defensive security, OT/ICS security, or incident response
- Is willing to invest real time — not looking for a weekend crash course

It is particularly relevant for people with backgrounds in **electrical engineering, industrial automation, or building/facility systems** who want to move into security — because that background is one of the rarest and most valuable combinations in the OT/ICS security field.

---

## How to Use This Repository

**Start at Stage 00.** Even if you have experience — the first stage is worth reading because the security perspective applied to hardware and OS fundamentals is not what most introductory resources cover.

**Do the exercises.** Each module has a hands-on section. Reading without doing produces familiarity, not skill. The exercises are designed to make abstract concepts concrete before you move forward.

**Follow the sequence.** The stages build on each other. Stage 04 (Penetration Testing) assumes you understand Stage 01 (Networking) and Stage 02 (Security Core). Jumping ahead creates gaps that quietly limit your ceiling.

**Build a lab.** You need a virtualisation environment. VirtualBox or VMware, a Kali Linux VM, a Windows VM, and a Linux server VM is enough to complete 80% of the exercises in the roadmap.

```
Minimum Lab Setup:
├── Kali Linux VM    → Attack platform, primary security toolset
├── Windows 10/11 VM → Windows exercise target
└── Ubuntu Server VM → Linux exercise target
```

---

## Current Progress

```
STAGE-00_Foundations
├── ✅ 01_hardware-fundamentals.md       (77 KB)
├── ✅ 02_os-fundamentals.md             (62 KB)
├── ✅ 03_windows-fundamentals.md        (80 KB)
├── ⬜ 04_linux-fundamentals.md
└── ⬜ 05_programming-fundamentals.md
```

---

## Certifications This Roadmap Prepares For

| Certification | Stage Alignment | Priority |
|---|---|---|
| **CompTIA Security+** | Stages 00-03 | Entry level |
| **eJPT** | Stages 00-04 | First practical cert |
| **OSCP** | Stages 00-04, 07, 13 | Industry gold standard |
| **GICSP** ⭐ | Stages 00-12 | OT/ICS specialisation |
| **CISSP** | All stages | Senior management |
| **ISA/IEC 62443** | Stage 12 | OT security standard |

> ⭐ **GICSP (GIAC Global Industrial Cyber Security Professional)** is the primary certification target for this roadmap. It is the most recognised OT/ICS security credential globally and is referenced in hiring requirements for critical infrastructure security roles.

---

## Legal & Ethics

All techniques, tools, and methods documented in this repository are presented strictly for **educational purposes, authorised security research, and defensive security practice**.

- Never test techniques on systems you do not own or have explicit written permission to test
- Always operate within the bounds of applicable laws in your jurisdiction
- CTF environments, personal lab VMs, and purpose-built vulnerable targets (HackTheBox, TryHackMe, VulnHub) are the appropriate practice environments

See [LEGAL.md](./LEGAL.md) for full terms.

---

## Roadmap File

See [ROADMAP.md](./ROADMAP.md) for the detailed topic-by-topic breakdown of every module across all 18 stages.

---

<div align="center">

*Built methodically. Written to last.*

**github.com/RENCBERAKMAN/bytewall-academy**

</div>