# STAGE 00 — Foundations
### Bytewall Academy | Cybersecurity × OT/ICS Security Roadmap

> *"You cannot hack what you do not understand. You cannot defend what you cannot see."*

---

Before you touch a single exploit, write a single line of Python, or open Burp Suite for the first time — this stage exists. Not as a formality. Not as filler. As the **non-negotiable foundation** that separates people who follow tutorials from people who actually understand what they are doing.

Every attack technique you will ever learn is built on top of these concepts. Every detection rule you will ever write assumes you understand what normal looks like at the system level. Every vulnerability you will ever exploit is a deviation from how these fundamentals are supposed to work.

Skip this stage and you will spend the rest of your career googling commands without understanding why they work. Complete it properly and everything that comes after will make sense on a deeper level.

---

## What This Stage Covers

| # | Module | Core Concepts |
|---|--------|---------------|
| [01](./01_hardware-fundamentals.md) | **Hardware Fundamentals** | CPU rings & privilege levels, RAM attacks, firmware security, BIOS/UEFI, physical attack surface |
| [02](./02_os-fundamentals.md) | **Operating System Fundamentals** | Kernel architecture, user vs kernel mode, processes & threads, file systems, memory management, system calls |
| [03](./03_windows-fundamentals.md) | **Windows Fundamentals** | Registry, services, UAC, Defender/AMSI, PowerShell, Event Log forensics, persistence mechanisms |
| [04](./04_linux-fundamentals.md) | **Linux Fundamentals** | File permissions, SUID/SGID, bash scripting, log system, SSH hardening, privilege escalation basics |
| [05](./05_programming-fundamentals.md) | **Programming Fundamentals** | Variables, loops, functions, file I/O, string operations, basic algorithms — security-oriented approach |

---

## Why These Five Modules First

**Hardware** is where every digital system physically lives. Cold boot attacks, firmware implants, DMA attacks, power analysis — these are real techniques used by real adversaries. Your electrical and infrastructure background makes this module more relevant than it is for most people entering this field.

**Operating Systems** are the battlefield. Every piece of malware runs as a process. Every privilege escalation crosses a kernel boundary. Every forensic investigation reads OS structures. There is no shortcut around this.

**Windows** is the dominant enterprise OS. Active Directory, NTLM, Kerberos, PowerShell, Event Logs — the majority of penetration tests and incident response investigations happen inside Windows environments. Understanding it deeply is not optional.

**Linux** is where servers live, where security tools run, and where a significant portion of OT/ICS infrastructure operates. It is also the OS you will use most as a security professional. The command line is your primary interface for everything.

**Programming** is what separates security professionals from security tool users. You do not need to be a software engineer. You need to be able to read code, write scripts, automate tasks, and eventually understand how vulnerabilities manifest at the code level.

---

## How to Use This Stage

Each module is structured the same way:

1. **Why it matters** — the security relevance, not just the theory
2. **Core concepts** — explained from first principles, with depth
3. **Security perspective** — how each concept connects to real attacks and defences
4. **Hands-on exercises** — do not skip these, reading is not enough
5. **Further reading** — for when you want to go deeper

**Recommended approach:**
- One module per week minimum
- Complete every hands-on exercise before moving to the next module
- Build a lab environment (a VM is enough for Stages 00-04)
- Take notes in your own words — if you cannot explain it simply, you do not understand it yet

---

## Lab Setup Recommendation

You do not need expensive hardware. A single machine with virtualisation is enough:

```
Host Machine (your laptop/desktop)
├── Kali Linux VM          → Your attack platform and primary work environment
├── Windows 10/11 VM       → Target for Windows exercises and tool testing
└── Ubuntu Server VM       → Target for Linux exercises
```

Recommended tools: **VirtualBox** (free) or **VMware Workstation Player** (free for personal use).

---

## Series Navigation

```
STAGE 00 — Foundations          ← You are here
STAGE 01 — Network Fundamentals
STAGE 02 — Cybersecurity Core
STAGE 03 — Attack Methods & Defence
STAGE 04 — Penetration Testing
STAGE 05 — Network Security
STAGE 06 — Web Application Security
STAGE 07 — Active Directory Security
STAGE 08 — Cloud Security
STAGE 09 — Incident Response & Forensics
STAGE 10 — SOC Operations
STAGE 11 — System Hardening
STAGE 12 — OT/SCADA/ICS Security      ← Primary specialisation target
STAGE 13 — Red Team Operations
STAGE 14 — Advanced Blue Team
STAGE 15 — Development & Automation
STAGE 16 — Advanced Topics
STAGE 17 — Certifications & Career
```

---

## A Note on This Roadmap

This is not a collection of cheat sheets. Every module is written to take someone with zero background in a topic and build genuine understanding — not surface-level familiarity.

The OT/ICS security field (Stage 12) is the specialisation target of this roadmap. It sits at the intersection of cybersecurity and physical engineering — one of the rarest and most in-demand profiles in the industry globally. Every stage before it builds the foundation that makes Stage 12 comprehensible and actionable.

Start here. Go deep. Do not rush.

---

*Bytewall Academy — Cybersecurity × OT/ICS Security Full Roadmap*  
*github.com/RENCBERAKMAN/bytewall-academy*