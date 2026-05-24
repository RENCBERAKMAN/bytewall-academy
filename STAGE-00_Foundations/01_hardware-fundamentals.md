# Stage 0.1 — Hardware Fundamentals
### The Cybersecurity Professional's Deep Dive into Computer Hardware

> **Roadmap Position:** Stage 0 → Module 1 of 5  
> **Prerequisite:** None — this is where everything begins  
> **Next Module:** 0.2 — Operating System Fundamentals  
> **Estimated Study Time:** 2–3 days of focused study + hands-on practice  

---

## Why Hardware Knowledge Is Non-Negotiable in Cybersecurity

Most cybersecurity courses rush past hardware. They hand you Kali Linux and say "start hacking." That is a critical mistake — and it is exactly the kind of shortcut that produces mediocre analysts who can run tools but cannot think.

Here is the reality: **every single attack, every defense, every piece of malware, every exploit ultimately executes on hardware.** When a ransomware binary encrypts files, the CPU is executing its instructions. When a keylogger captures keystrokes, it is reading from memory-mapped I/O registers. When Spectre/Meltdown shook the entire security industry in 2018, the vulnerability was not in software — it was in how CPUs were designed to execute code faster. When an attacker physically compromises a server, the game is over regardless of how good your software security is.

For you specifically — someone at the intersection of **electrical engineering and cybersecurity** — hardware knowledge is your unfair competitive advantage. Understanding OT/SCADA systems, ICS attacks, smart grid security, PLC exploitation: all of it is grounded in hardware. While other analysts are puzzled by why a Modbus packet behaves oddly, you will understand it at the signal level.

Do not rush this. Build the foundation correctly.

---

## Table of Contents

1. [The CPU — The Brain That Attackers Target](#1-the-cpu)
2. [RAM — The Battlefield of Live Forensics and Attacks](#2-ram)
3. [ROM — Persistent Storage and Firmware Threats](#3-rom)
4. [GPU — The Unlikely Security Tool and Attack Surface](#4-gpu)
5. [The Motherboard — The Nervous System of the Machine](#5-the-motherboard)
6. [Storage: HDD, SSD, NVMe — Where Evidence Lives and Dies](#6-storage-hdd-ssd-nvme)
7. [BIOS / UEFI — The Pre-Boot Attack Surface](#7-bios--uefi)
8. [Power Supply Unit — The Overlooked Attack Vector](#8-power-supply-unit)
9. [Physical Security — The Layer That Software Cannot Patch](#9-physical-security)
10. [Hardware Security: The Full Picture](#10-hardware-security-the-full-picture)
11. [Hands-On Lab Exercises](#11-hands-on-lab-exercises)
12. [Key Takeaways and Security Mindset](#12-key-takeaways-and-security-mindset)

---

## 1. The CPU

### 1.1 What Is a CPU?

The **Central Processing Unit (CPU)** is the primary component responsible for executing instructions. Every program you run — including every piece of malware — is ultimately a set of instructions that the CPU fetches, decodes, and executes.

Think of the CPU as an extraordinarily fast interpreter. It reads a list of instructions from memory, translates each instruction into micro-operations, and carries them out billions of times per second.

### 1.2 How the CPU Works — The Fetch-Decode-Execute Cycle

Understanding this cycle is not optional. It is the foundation of exploit development, reverse engineering, and understanding how malware operates.

```
┌─────────────────────────────────────────────────────────┐
│                  FETCH-DECODE-EXECUTE CYCLE              │
│                                                         │
│  [Memory] ──FETCH──► [Instruction Register]             │
│                              │                          │
│                           DECODE                        │
│                              │                          │
│                              ▼                          │
│                    [Control Unit]                       │
│                              │                          │
│                           EXECUTE                       │
│                              │                          │
│                              ▼                          │
│                    [ALU / Registers]                    │
│                              │                          │
│                         WRITE BACK                      │
│                              │                          │
│                              ▼                          │
│                    [Memory / Registers]                 │
└─────────────────────────────────────────────────────────┘
```

**Step-by-step breakdown:**

**1. Fetch:** The CPU reads the next instruction from the memory address pointed to by the **Program Counter (PC)** register, also called the **Instruction Pointer (IP/RIP)** in x86-64 architecture. This register is critically important in exploit development — controlling where the CPU fetches its next instruction is the goal of almost every code execution exploit.

**2. Decode:** The **Control Unit** interprets the binary instruction, determining what operation is required (add, move, compare, jump, etc.) and what operands are needed.

**3. Execute:** The **Arithmetic Logic Unit (ALU)** performs the actual computation — mathematical operations, logical comparisons, bit shifts. For memory operations, the **Memory Management Unit (MMU)** is involved.

**4. Write Back:** Results are stored back into registers or main memory.

### 1.3 CPU Architecture: x86-64

For cybersecurity work, you will primarily encounter **x86-64 (AMD64)** architecture. Understanding this architecture is mandatory for exploit development and reverse engineering.

**Key registers you must know:**

| Register | Size | Purpose | Security Relevance |
|----------|------|---------|-------------------|
| RAX | 64-bit | Accumulator / Return value | System call return values, function return values |
| RBX | 64-bit | Base register | Preserved across function calls |
| RCX | 64-bit | Counter / 4th argument | Loop counters, system call 4th arg |
| RDX | 64-bit | Data / 3rd argument | File descriptors, 3rd syscall arg |
| RSI | 64-bit | Source / 2nd argument | Buffer addresses in read/write syscalls |
| RDI | 64-bit | Destination / 1st argument | File descriptors, 1st syscall arg |
| RSP | 64-bit | **Stack Pointer** | **Critical for exploit development — points to top of stack** |
| RBP | 64-bit | **Base Pointer** | **Stack frame base — key in buffer overflow analysis** |
| RIP | 64-bit | **Instruction Pointer** | **Controls execution flow — the holy grail of exploitation** |
| RFLAGS | 64-bit | Status flags | Zero Flag (ZF), Carry Flag (CF), Sign Flag (SF) — affect conditional jumps |

> **Security Perspective:** When you analyze a buffer overflow exploit, the attacker is trying to overwrite the saved return address on the stack — which, when the function returns, gets loaded into RIP. Controlling RIP means controlling what code executes next. This is why "control of the instruction pointer" is synonymous with "arbitrary code execution."

**Privilege Rings — The CPU's Built-in Security Model:**

```
┌──────────────────────────────────────────┐
│              Ring 0 — Kernel             │ ← OS kernel, drivers
│   ┌──────────────────────────────────┐   │
│   │         Ring 1 & 2              │   │ ← Rarely used today
│   │   ┌──────────────────────────┐  │   │
│   │   │      Ring 3 — User       │  │   │ ← All user applications
│   │   │   (Unprivileged Mode)    │  │   │
│   │   └──────────────────────────┘  │   │
│   └──────────────────────────────────┘   │
└──────────────────────────────────────────┘
```

This ring architecture is the hardware enforcement of privilege separation. When an exploit achieves a **privilege escalation from Ring 3 to Ring 0**, the attacker has complete control over the system. This is not a software concept — it is enforced by the CPU itself. Kernel exploits attempt to break this boundary.

Additionally, modern CPUs operate in two fundamental modes:
- **User Mode (Ring 3):** Limited access. Cannot directly access hardware. Must request OS services via system calls.
- **Kernel Mode (Ring 0):** Unrestricted access. Direct hardware access. All OS kernel code runs here.

### 1.4 CPU Caches — Performance Feature, Security Vulnerability

Modern CPUs use a hierarchy of caches to reduce memory access latency:

```
CPU Core
├── L1 Cache (fastest, ~32–64KB per core, ~1ns latency)
├── L2 Cache (~256KB–1MB per core, ~5ns latency)
└── L3 Cache (shared, ~4–32MB, ~15–40ns latency)
    └── Main Memory / RAM (~8–16GB, ~60–100ns latency)
```

**Why this matters for security — Cache-Timing Side-Channel Attacks:**

The difference in access time between a cache hit (~1ns) and a cache miss (~100ns) is measurable. An attacker can use this timing difference to infer what data is in the cache — and therefore what data has been recently accessed by another process. This is the basis of:

- **Flush+Reload:** Attacker flushes a cache line, waits, then measures how long it takes to reload. If it's fast, the victim process accessed that address.
- **Prime+Probe:** Attacker fills the cache with known data, lets the victim run, then measures which cache lines were evicted by the victim's accesses.
- **Spectre (CVE-2017-5753):** Exploits speculative execution to read memory that the attacker should not have access to, then uses cache timing to exfiltrate the data.
- **Meltdown (CVE-2017-5754):** Allows user-space processes to read kernel memory by exploiting out-of-order execution and cache effects.

> **Spectre and Meltdown — Historical Significance:**  
> Disclosed in January 2018, these vulnerabilities affected virtually every modern CPU (Intel, AMD, ARM). They demonstrated that **performance optimizations in CPU hardware design could create fundamental security vulnerabilities**. The patches required changes to operating system kernels, hypervisors, and web browsers — and caused measurable performance degradation (5–30% in some workloads). This moment changed how the security community thinks about hardware trust. Previously, software ran on hardware assumed to be a "trusted foundation." Spectre/Meltdown proved that assumption was wrong.

### 1.5 CPU Security Features to Know

**Hardware-enforced security mechanisms built into modern CPUs:**

| Feature | What It Does | Security Benefit |
|---------|-------------|-----------------|
| **NX/XD Bit** (No-Execute / Execute Disable) | Marks memory pages as non-executable | Prevents shellcode injection in data segments |
| **SMEP** (Supervisor Mode Execution Prevention) | Prevents kernel from executing user-space pages | Blocks kernel exploits that point execution to user memory |
| **SMAP** (Supervisor Mode Access Prevention) | Prevents kernel from accessing user-space data | Forces explicit kernel-user data transfer |
| **CET** (Control-flow Enforcement Technology) | Shadow stack + indirect branch tracking | Defeats ROP/JOP attacks |
| **Intel TXT / AMD SVM** | Trusted execution environments | Measured boot, isolated execution |
| **SGX** (Software Guard Extensions) | Encrypted memory enclaves | Protects sensitive code even from privileged attackers |

> **Attacker's Perspective:** When you read about exploit mitigations being bypassed, you are reading about attackers finding clever ways around these hardware features. SMEP bypass, for example, requires either finding a way to execute code in kernel memory directly (not user memory), or manipulating CPU control registers (CR4) to temporarily disable SMEP. This is why privilege escalation exploits in 2024 are far more complex than in 2005.

---

## 2. RAM

### 2.1 What Is RAM?

**Random Access Memory (RAM)** is volatile, high-speed storage that holds the currently running operating system, applications, and their data. "Volatile" means all data is lost when power is removed. A 16GB RAM module stores 16 billion bytes of information that completely disappears the moment the computer shuts down.

For a security professional, RAM is arguably the **most important forensic artifact** in incident response. Malware increasingly lives entirely in memory — never touching the disk — precisely because it knows that most security tools focus on files.

### 2.2 How RAM Works

RAM is composed of billions of capacitors and transistors. Each capacitor represents one bit — charged represents 1, uncharged represents 0. Because capacitors drain over time, **DRAM (Dynamic RAM)** must be refreshed thousands of times per second, which is why it requires continuous power.

**Memory Addressing:**

Every byte in RAM has a unique address. Modern 64-bit systems use a **virtual address space** — each process believes it has access to the entire 64-bit address space (theoretically 16 exabytes, though current implementations use 48-bit addressing = 256 TB). The CPU's **MMU (Memory Management Unit)** translates virtual addresses to physical addresses using **page tables**.

```
Process Virtual Address Space (simplified):
┌──────────────────────┐  High Address (0xFFFFFFFFFFFFFFFF)
│    Kernel Space      │  ← Only accessible in Ring 0
├──────────────────────┤  
│       Stack          │  ← Grows downward; local variables, return addresses
│          ↓           │
│    (free space)      │
│          ↑           │
│        Heap          │  ← Grows upward; dynamically allocated memory (malloc)
├──────────────────────┤
│    BSS Segment       │  ← Uninitialized global/static variables
├──────────────────────┤
│    Data Segment      │  ← Initialized global/static variables
├──────────────────────┤
│    Text Segment      │  ← Executable code (marked NX/non-writable ideally)
└──────────────────────┘  Low Address (0x0000000000000000)
```

> **Security Critical:** This memory layout is the foundation of nearly every exploit class. Buffer overflows target the **stack**, heap exploits target the **heap**, and format string vulnerabilities can read/write anywhere. You will spend hundreds of hours working with this layout in later stages. Understand it now.

### 2.3 RAM Types and Specifications

| Type | Full Name | Characteristics |
|------|-----------|----------------|
| **DDR4** | Double Data Rate 4 | Most common today; 2133–3600 MHz |
| **DDR5** | Double Data Rate 5 | Latest gen; 4800–8000+ MHz; improved security features |
| **ECC RAM** | Error-Correcting Code | Detects and corrects single-bit errors; used in servers |
| **LPDDR** | Low Power DDR | Mobile devices; lower voltage, higher efficiency |

**ECC RAM and Security:** Single-bit errors in RAM occur naturally due to cosmic ray bombardment (seriously — this is real). In regular RAM, these errors can cause system crashes or **data corruption**. In a server handling financial transactions or cryptographic operations, a single flipped bit could be catastrophic. ECC RAM detects and corrects these errors automatically. For security-critical server infrastructure, ECC RAM is not optional — it is a fundamental reliability requirement.

### 2.4 RAM as a Security Battlefield

#### 2.4.1 Memory Forensics

When a system is compromised, the attacker's malware **lives in RAM**. The malware processes, network connections, decrypted strings, encryption keys, and even passwords can all be found in a memory dump. This is why **live forensics** (capturing RAM from a running system before shutdown) is a critical incident response skill.

Key tools: **Volatility 3**, **Rekall** (deprecated but historically important), **WinPmem** (for Windows RAM acquisition), **LiME** (Linux Memory Extractor).

What you can find in a RAM dump:
- Running processes (including hidden/injected ones)
- Network connections and their state
- Registry hives loaded in memory
- Decrypted versions of encrypted files (ransomware may leave keys briefly)
- Browser history, passwords in memory
- Malware code that never touched disk (fileless malware)
- Cryptographic keys in use

#### 2.4.2 RAM-Based Attack Techniques

**Fileless Malware:** Malware that executes entirely in RAM, never writing to disk. It typically hijacks a legitimate process (e.g., PowerShell) and injects malicious code into its memory space. Traditional antivirus (which scans files on disk) is largely blind to it.

**Process Injection Techniques:**
- **DLL Injection:** Forces a target process to load a malicious DLL into its address space
- **Process Hollowing:** Creates a legitimate process in suspended state, empties its memory, replaces it with malicious code, resumes execution
- **Reflective DLL Injection:** DLL loads itself directly from memory without touching the filesystem
- **Thread Execution Hijacking:** Suspends a thread, modifies its context to point to shellcode, resumes it

**Heap Spraying:** An attacker fills the heap with copies of shellcode (often preceded by a long NOP sled) to increase the probability that a controlled jump will land in executable shellcode. Classic technique used in browser exploitation.

#### 2.4.3 Cold Boot Attack — When "Volatile" Is Not Fast Enough

> **This is one of the most fascinating hardware attacks in existence.**

RAM retains data for seconds to minutes after power is removed, especially when cooled. The data fades exponentially with time and temperature. By **spraying RAM modules with compressed air (or liquid nitrogen)**, an attacker can slow the data decay dramatically — sometimes preserving data for hours.

**The attack:**
1. Gain brief physical access to a running (or recently powered off) computer
2. Optionally, cool the RAM modules with compressed air spray (inverted can)
3. Remove the RAM sticks (modern DDR can sometimes be hot-swapped)
4. Boot from a USB drive designed to dump RAM contents
5. Recover the data — including disk encryption keys (e.g., BitLocker, FileVault, LUKS)

**Real-world significance:** This attack, demonstrated by researchers at Princeton University in 2008, showed that **full-disk encryption does not protect against a physically present attacker** if the system is running or recently suspended. The encryption key is in RAM. This fundamentally changed how we think about encryption vs. physical access.

**Countermeasures:** Enable BitLocker's pre-boot PIN, disable Sleep mode (use Hibernate instead, which flushes RAM to disk and powers off), configure firmware to prevent boot from external media, enable Intel TXT/AMD SEV for encrypted memory.

#### 2.4.4 Rowhammer Attack — Flipping Bits Without Physical Access

**Rowhammer** (discovered 2014) is a hardware vulnerability in DRAM. By repeatedly accessing (hammering) rows of memory, an attacker can cause bit flips in adjacent rows — **changing memory values without ever having write permission to those memory locations**.

This has been used to:
- Escalate privileges (flip a bit in a page table to gain write access to privileged memory)
- Break out of virtual machines
- Attack JavaScript engines to gain code execution in browsers
- Attack Android phones remotely via JavaScript

The implication is profound: **even if software is perfectly written with no bugs, hardware-level vulnerabilities can still create exploitable conditions**. This is why hardware security research is increasingly important.

---

## 3. ROM

### 3.1 What Is ROM?

**Read-Only Memory (ROM)** is non-volatile memory that retains its contents without power. In classical computing, "read-only" meant the data was permanently fixed at manufacturing. In modern systems, the term has evolved to encompass various types of persistent, low-level storage that is not directly user-accessible during normal operation.

**Types of ROM in the modern context:**

| Type | Full Name | Characteristics |
|------|-----------|----------------|
| **Mask ROM** | Factory-programmed ROM | Truly read-only; written at semiconductor fab; used in microcontrollers, game cartridges |
| **PROM** | Programmable ROM | Written once by the user with a PROM burner |
| **EPROM** | Erasable PROM | Erased by UV light exposure through a quartz window; reprogrammable |
| **EEPROM** | Electrically Erasable PROM | Can be erased/written electrically, byte by byte; used for BIOS/UEFI storage |
| **Flash Memory** | Flash EEPROM | Block-erased EEPROM; used in SSDs, USB drives, firmware chips; fast and dense |
| **eFuse** | Electronic Fuse | One-time programmable bits in a CPU; used for device configuration, secure boot keys |

### 3.2 ROM in the Security Context

**Firmware Storage:** The BIOS/UEFI firmware (covered in section 7) is stored in a flash chip on the motherboard — this is a form of ROM. The firmware initializes all hardware before the operating system loads. If this chip is compromised, an attacker has persistence that survives OS reinstallation, and even hard drive replacement.

**Microcontroller ROM:** In OT/ICS environments, PLCs (Programmable Logic Controllers) contain ROM that stores the device's operating firmware. Attacks on this firmware — like Stuxnet's modification of Siemens PLC code — represent some of the most sophisticated attacks ever documented. Understanding ROM in embedded systems is critical for ICS security.

**Secure Boot and ROM-stored Keys:** Modern systems use hardware security chips (TPM, Secure Enclave) that contain root-of-trust keys in write-protected ROM. These keys are used to verify that the boot chain has not been tampered with. If the ROM itself is compromised, the entire root of trust collapses.

**Hardware Security Module (HSM) ROM:** HSMs store cryptographic keys in tamper-evident hardware. Attempts to read the ROM physically trigger key erasure. Understanding ROM in HSMs is critical for cryptographic infrastructure security.

---

## 4. GPU

### 4.1 What Is a GPU?

The **Graphics Processing Unit (GPU)** was originally designed to accelerate rendering of 3D graphics. Where a CPU has 8–64 powerful general-purpose cores, a GPU has thousands of smaller, simpler cores optimized for parallel computation. A modern NVIDIA RTX 4090 contains **16,384 CUDA cores**.

This massive parallelism makes GPUs extraordinarily powerful for any computation that can be broken into independent parallel tasks.

### 4.2 GPU Architecture: Why Parallelism Matters

```
CPU Architecture:              GPU Architecture:
┌──────────────────┐          ┌──────────────────────────────────────┐
│  Core 1 (big)    │          │  SM1  SM2  SM3  SM4  SM5  SM6  ...  │
│  Core 2 (big)    │          │  [128 tiny cores per SM × 128 SMs]  │
│  Core 3 (big)    │          │  = 16,384 total CUDA cores           │
│  Core 4 (big)    │          │                                      │
│  (optimized for  │          │  (optimized for thousands of         │
│   sequential     │          │   parallel simple computations)      │
│   complex tasks) │          │                                      │
└──────────────────┘          └──────────────────────────────────────┘
```

**For cybersecurity, GPU parallelism directly translates to password cracking speed.** Consider the task of trying all possible 8-character passwords with lowercase letters (26^8 = ~208 billion combinations). A CPU might try 1–10 million hashes per second. A GPU might try 10–100 **billion** hashes per second — a difference of four to five orders of magnitude.

### 4.3 GPU in Offensive Security — Password Cracking

**Hashcat** is the de-facto GPU-accelerated password cracking tool. It supports hundreds of hash types and uses the GPU to perform massively parallel hash computation.

**Benchmark comparison** (MD5, rough estimates):

| Hardware | MD5 Speed |
|----------|-----------|
| CPU (single-thread) | ~50 MH/s |
| CPU (8 cores) | ~400 MH/s |
| RTX 3090 | ~68,000 MH/s (68 GH/s) |
| 8× RTX 3090 rig | ~544,000 MH/s |

**Attack modes in Hashcat:**

- **Brute-force (Mask Attack):** Try all combinations in a defined character set and length. `?l?l?l?l?l?l?l?l` = all 8-char lowercase. Infeasible for long complex passwords; devastating for short ones.
- **Dictionary Attack:** Try all words in a wordlist (e.g., RockYou.txt with 14 million real passwords).
- **Rule-based Attack:** Apply mutation rules to dictionary words (`password` → `P@$$w0rd`, `passw0rd!`, etc.). This is where cracking becomes an art form.
- **Combinator Attack:** Combine two wordlists (`john` + `2023` = `john2023`).
- **PRINCE Attack:** Probabilistic ordering of elements based on Markov chains of real password patterns.

> **Mindset Shift:** Many people think that hashing passwords makes them "safe." Hashing prevents the storage of plaintext, but it does not prevent offline cracking if the hash is leaked. When a database is breached and password hashes are stolen, an attacker takes the hash file home and runs Hashcat for days or weeks. If the passwords were weak (under 10 characters, common words, predictable patterns), they will be cracked. This is why password hashing algorithms matter: **bcrypt, scrypt, Argon2** are designed to be slow and memory-intensive, making GPU cracking far less effective. **MD5 and SHA-1 for password storage are unacceptable by any modern standard.**

### 4.4 GPU in Defensive Security — AI/ML

GPUs power machine learning, and ML is increasingly used in:
- Behavioral anomaly detection in SIEM systems
- Network traffic classification
- Malware classification via neural networks
- Natural language processing for phishing detection
- Large language model-based security assistants

### 4.5 GPU Attack Surface

**GPU-Based Malware:** Mining malware (cryptojackers) hijacks GPU resources to mine cryptocurrency, often undetected because security tools focus on CPU usage.

**GPU Memory Attacks:** Research has demonstrated that GPU memory is not cleared between processes, potentially allowing one process to read residual data left by another. Unlike CPU memory with sophisticated isolation, GPU memory isolation is historically weaker.

**VRAM Scraping:** Since GPUs process rendered frames that may contain sensitive information (passwords typed in browser, document contents), VRAM has been a target for data exfiltration research.

---

## 5. The Motherboard

### 5.1 What Is the Motherboard?

The **motherboard (mainboard)** is the primary printed circuit board (PCB) that interconnects all components of the computer. It is the physical and electrical backbone of the system.

### 5.2 Critical Motherboard Components

```
┌─────────────────────────────────────────────────────────────────┐
│                         MOTHERBOARD                             │
│                                                                 │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐                       │
│  │ RAM  │  │ RAM  │  │ RAM  │  │ RAM  │  ← DIMM Slots          │
│  └──────┘  └──────┘  └──────┘  └──────┘                       │
│                                                                 │
│  ┌──────────────┐     ┌─────────────────────────┐             │
│  │     CPU      │─────│       PCH/Chipset        │             │
│  │   + Socket   │     │   (Platform Controller   │             │
│  └──────────────┘     │         Hub)             │             │
│                       └─────────────────────────┘             │
│                                    │                            │
│  ┌─────────┐  ┌─────────┐  ┌──────────┐  ┌───────────┐       │
│  │ PCIe x16│  │ PCIe x4 │  │  M.2     │  │  SATA     │       │
│  │  (GPU)  │  │ (NVMe)  │  │  Slot    │  │  Ports    │       │
│  └─────────┘  └─────────┘  └──────────┘  └───────────┘       │
│                                                                 │
│  ┌──────────┐  ┌────────┐  ┌──────────┐  ┌──────────────┐    │
│  │  BIOS/   │  │  TPM   │  │  Power   │  │   I/O Panel  │    │
│  │  UEFI    │  │  Chip  │  │ Connectors│  │ (USB, LAN,   │    │
│  │  Chip    │  │        │  │          │  │  Audio, etc) │    │
│  └──────────┘  └────────┘  └──────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### 5.3 The Chipset (PCH — Platform Controller Hub)

The chipset manages communication between the CPU and all other components. It handles I/O operations: USB controllers, SATA controllers, PCIe lanes for non-GPU devices, audio, and network interfaces.

**Security Relevance:** The chipset runs its own firmware. Intel's **Management Engine (ME)** and AMD's **Platform Security Processor (PSP)** are embedded subsystems within the chipset that operate independently of the main CPU, at a privilege level below the operating system — sometimes called **Ring -2** or **Ring -3**.

**Intel Management Engine — A Controversial Security Topic:**

The Intel ME is a separate processor embedded in the PCH that runs its own operating system (MINIX 3) and has:
- Access to system memory, bypassing the CPU
- Access to the network interface, independent of the main OS
- The ability to remotely control the system (Intel AMT — Active Management Technology)
- Persistent operation even when the main system is powered off (as long as PSU is connected)

**Vulnerabilities:** CVE-2017-5689 (Intel AMT critical auth bypass) allowed unauthenticated remote access to systems with Intel AMT enabled. An attacker on the same network could take complete control of the machine regardless of the operating system state. **This vulnerability affected millions of business laptops and desktops.**

The ME cannot be fully disabled through normal means, which has led to significant controversy in the security community about whether it represents an intentional backdoor. Some security-focused distributions attempt to neutralize it through projects like **me_cleaner**.

### 5.4 TPM — Trusted Platform Module

The **TPM** is a dedicated security chip on the motherboard (or increasingly integrated into the CPU) that performs cryptographic operations in hardware.

**TPM capabilities:**
- **Secure key storage:** Keys generated inside the TPM never leave the chip in unencrypted form
- **Measured Boot:** The TPM records cryptographic measurements of each boot component (firmware → bootloader → kernel), creating a tamper-evident chain
- **Remote Attestation:** A remote server can verify that your system has not been tampered with by requesting a signed report of boot measurements from the TPM
- **Platform Binding:** Keys and secrets can be "sealed" to a specific system state — they can only be decrypted if the system boots in exactly the measured configuration

**BitLocker and TPM:** Windows BitLocker uses the TPM to store the Volume Master Key. The TPM will only release the key if the boot measurements match what was recorded when BitLocker was configured. If the bootloader is modified (e.g., by a bootkit), the measurements change, and the TPM refuses to release the key — **the disk remains encrypted and inaccessible.**

> **Attack:** TPM 2.0 was found vulnerable to a bus-sniffing attack (2023). On systems where the TPM is a discrete chip communicating with the CPU over an LPC or SPI bus, the key transfer between TPM and CPU can be captured with a logic analyzer. This is precisely the kind of hardware-level attack that requires physical access and specialized equipment — but it has been demonstrated successfully against Microsoft Surface Pro devices. The solution is to use a TPM BitLocker configuration with a pre-boot PIN, so the raw key transmission is not sufficient without the PIN.

### 5.5 PCIe — The High-Speed Interconnect and DMA Attack Surface

**PCIe (Peripheral Component Interconnect Express)** is the primary high-speed interface connecting GPUs, NVMe SSDs, and other expansion cards to the motherboard.

**PCIe DMA (Direct Memory Access):** PCIe devices can read and write system RAM directly, without going through the CPU. This is how GPUs load textures, how network cards receive packets, and how NVMe SSDs transfer data — all faster than if every operation had to go through the CPU.

**The Security Implication — DMA Attacks:**

Any PCIe device has the potential to read and write arbitrary system memory. This means:
- A malicious GPU or network card could read passwords from memory
- A malicious Thunderbolt/USB4 device (which exposes PCIe) could take complete control of a system

**Real-world attack:** The **PCILeech** tool uses a $200 FPGA connected via PCIe/M.2 to read physical memory of a running system. It can extract BitLocker keys, inject code into the kernel, and maintain persistence — all while the operating system is completely unaware, because the OS is not consulted for DMA operations.

**IOMMU — The Defense:** An **IOMMU (Input-Output Memory Management Unit)** (Intel VT-d, AMD-Vi) provides the same protection for DMA that the MMU provides for CPU memory access — it restricts which memory regions each device can access. When properly configured, even a malicious PCIe device cannot read arbitrary memory. However, IOMMU must be enabled in UEFI, properly configured by the OS, and not disabled by device drivers.

---

## 6. Storage: HDD, SSD, NVMe

### 6.1 Hard Disk Drive (HDD)

A **Hard Disk Drive** stores data on magnetic platters that spin at 5,400–15,000 RPM. A read/write head moves across the platter surface to access data. This mechanical nature creates:

**Advantages:** High capacity at low cost, data recoverable even after deletion (forensics), no write wear issues.

**Disadvantages:** Slow (mechanical seek time of 5–15ms vs. microseconds for SSD), failure-prone (moving parts), audible operation, vulnerable to physical shock.

**HDD Forensics — Why Deleted Data Is Not Gone:**

When a file is "deleted" on a traditional filesystem, the operating system simply marks the space as available. The actual magnetic patterns on the disk remain until overwritten by new data. This is the foundation of **file carving** — recovering files by their structure (magic bytes, headers, footers) from disk images, regardless of filesystem metadata.

**Slack Space:** Even when a file occupies a disk cluster, it may not use the entire cluster. The remaining space (slack space) may contain remnants of previously stored data. Forensic tools extract slack space artifacts that can reveal previously stored file fragments.

**HDD Firmware Attacks:** The **Equation Group** (believed to be NSA-linked) was discovered in 2015 to have malware capable of **reprogramming HDD firmware** — the embedded software running on the drive's controller board. This malware survived complete OS reinstallation, drive formatting, and even low-level wipes. The infected firmware could create a hidden partition outside the normal disk geometry, invisible to the OS. This represents perhaps the most sophisticated persistence mechanism ever documented. Affected firmware included drives from every major manufacturer.

### 6.2 Solid State Drive (SSD)

SSDs use **NAND flash memory** — the same technology as USB drives, but faster and higher capacity. There are no moving parts; data is stored as electrical charges in floating-gate transistors.

**SSD Forensics — The Complications:**

**TRIM:** When the OS deletes a file on an SSD, it sends a TRIM command to the SSD controller. The controller marks those flash cells for erasure and may erase them during idle time. This makes file recovery from SSDs much harder than from HDDs — deleted data may be permanently gone within minutes to hours.

**Wear Leveling:** SSD controllers continuously move data around the flash cells to distribute wear evenly (flash cells have a limited write endurance of ~1,000–100,000 program/erase cycles). This means the **logical address of data (what the OS sees) is completely different from its physical location on the NAND chips**. This complicates forensic analysis enormously — the SSD controller is continuously managing a translation layer (FTL — Flash Translation Layer) that maps logical addresses to physical cells.

**Over-provisioning:** SSDs maintain a pool of spare cells (typically 7–28%) that are hidden from the OS. These cells are used during wear leveling and garbage collection and are **not accessible through normal read commands** — they exist in the SSD controller's private space. Forensic tools that connect directly to the NAND chips (bypassing the controller) can access this over-provisioned area and may recover data that was thought to be erased.

**SSD Encryption:** Many SSDs advertise hardware-based encryption (Self-Encrypting Drives / SED). Research has revealed that many of these implementations are **critically flawed** — the encryption key is often derived trivially from the password, the key is not protected at rest, or the encryption is bypassed entirely. A 2018 study found that a significant fraction of popular SSDs claiming encryption were trivially bypassable. **Do not rely on SED encryption alone. Use software-layer encryption (BitLocker, LUKS) on top.**

### 6.3 NVMe (Non-Volatile Memory Express)

**NVMe** is a communication protocol designed specifically for flash storage, using PCIe lanes directly. NVMe SSDs connect to the motherboard via M.2 slots or PCIe slots, bypassing the SATA controller entirely.

**Performance comparison:**

| Storage Type | Interface | Sequential Read | Latency |
|-------------|-----------|-----------------|---------|
| HDD | SATA | ~150 MB/s | 5–15ms |
| SATA SSD | SATA | ~550 MB/s | ~0.05ms |
| NVMe SSD (Gen 3) | PCIe 3.0 | ~3,500 MB/s | ~0.02ms |
| NVMe SSD (Gen 5) | PCIe 5.0 | ~14,000 MB/s | ~0.01ms |

**Security Relevance of NVMe:** Because NVMe drives use PCIe and DMA, all the DMA attack considerations from section 5.5 apply. Additionally, NVMe supports a **Sanitize** command that securely erases the entire drive — far more reliable than software-level secure erase for HDDs. When decommissioning equipment, the NVMe Sanitize command (via `nvme` CLI tools) should be used rather than repeated overwrites (which SSDs may not execute as expected due to wear leveling).

### 6.4 Secure Data Destruction — The Full Picture

When disposing of storage media in a security context:

**For HDDs:**
- Software overwrite with DoD 5220.22-M standard (7 passes) or Gutmann method (35 passes) — effective for magnetic media
- Physical destruction: degaussing (strong magnetic field) followed by shredding
- For classified material: NSA-certified shredders producing small particle sizes

**For SSDs/NVMe:**
- ATA Secure Erase or NVMe Sanitize commands — the controller erases all NAND cells including over-provisioned space
- **Overwrite tools designed for HDDs do NOT work reliably on SSDs** due to wear leveling
- Physical destruction is the only guaranteed method for highly sensitive data
- For drives with hardware encryption (if trustworthy), simply destroying the key renders data irrecoverable

---

## 7. BIOS / UEFI

### 7.1 What Is BIOS?

**BIOS (Basic Input/Output System)** is the original pre-OS firmware that initializes hardware and launches the operating system. Stored in a flash chip on the motherboard, BIOS runs the first microseconds after power is applied — before the CPU even knows what operating system it will run.

**BIOS Sequence:**
1. CPU starts at a fixed memory address (typically `0xFFFFFFF0` — 16 bytes from top of 32-bit address space)
2. BIOS code is memory-mapped to this address from the flash chip
3. BIOS performs **POST (Power-On Self Test):** tests and initializes CPU, RAM, keyboard, storage
4. BIOS reads the **MBR (Master Boot Record)** from the first sector of the boot drive
5. MBR loads the bootloader, which loads the operating system

**Legacy BIOS Limitations:**
- 16-bit real mode operation (designed for Intel 8086 processors, 1981)
- Maximum boot disk size: 2.2TB (MBR partition table limitation)
- No support for Secure Boot
- No driver model — hardware must be manually initialized
- No GUI interface (text only)

### 7.2 UEFI — The Modern Replacement

**UEFI (Unified Extensible Firmware Interface)** replaces the legacy BIOS with a far more sophisticated pre-boot environment. UEFI is essentially a miniature operating system that runs before your main OS.

**UEFI Architecture:**

```
┌──────────────────────────────────────────────────────────────┐
│                      UEFI FIRMWARE                           │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐ │
│  │  SEC Phase   │  │   PEI Phase  │  │    DXE Phase      │ │
│  │  (Security)  │  │  (Pre-EFI    │  │  (Driver          │ │
│  │              │  │   Init)      │  │   Execution Env)  │ │
│  └──────────────┘  └──────────────┘  └───────────────────┘ │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              BDS Phase (Boot Device Selection)        │   │
│  │    → Secure Boot verification                        │   │
│  │    → Boot manager                                    │   │
│  │    → Shell access                                    │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌─────────────────────────┐  ┌────────────────────────┐   │
│  │   NVRAM (EFI Variables) │  │    EFI System Partition │   │
│  │   Stored on flash chip  │  │    (ESP) on disk        │   │
│  │   Secure Boot keys etc. │  │    Bootloaders here     │   │
│  └─────────────────────────┘  └────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

**UEFI Advantages Over Legacy BIOS:**
- 32-bit and 64-bit operation
- Support for disks larger than 2.2TB (GPT partition table — supports up to 9.4 ZB theoretically)
- **Secure Boot support**
- Network boot capabilities
- GUI interface possible
- Module-based driver architecture
- EFI Shell: a command-line environment with scripting capability

### 7.3 Secure Boot — How It Works

**Secure Boot** is a UEFI feature that ensures only digitally signed, trusted software can execute during the boot process.

**The trust chain:**

```
UEFI Firmware
    │
    ├── Reads Platform Key (PK) from UEFI NVRAM
    │   (Root of trust — owned by motherboard manufacturer)
    │
    ├── Verifies Key Enrollment Key (KEK)
    │   (Trusted parties who can update Secure Boot databases)
    │
    ├── Checks Signature Database (db)
    │   (Whitelist of trusted bootloader signatures — e.g., Microsoft's certificate)
    │
    ├── Checks Forbidden Signature Database (dbx)
    │   (Blacklist of revoked signatures — known-bad bootloaders)
    │
    └── Verifies bootloader signature against db
            │
            ├── PASS → Bootloader executes → loads kernel → loads drivers
            └── FAIL → Boot halted, error displayed
```

**What Secure Boot Protects Against:**
- **Bootkits:** Malware that infects the bootloader to load before the OS and its security tools
- **Boot-level rootkits:** Malicious code that controls the boot process to hide its presence
- **Unauthorized OS installation:** Without your signing key, unsigned boot media won't run

**What Secure Boot Does NOT Protect Against:**
- Malware that runs after the OS loads (everything in the Windows attack surface)
- An attacker who can enroll their own keys (physical access to UEFI setup)
- Vulnerabilities in signed bootloaders (e.g., BootHole/GRUB2 vulnerability CVE-2020-10713 — a buffer overflow in GRUB2 that allowed bypass of Secure Boot on millions of signed systems)

**The BootHole Incident (2020):** A buffer overflow in GRUB2's configuration file parsing allowed an attacker to execute arbitrary code during boot, even with Secure Boot enabled. GRUB2's bootloader was legitimately signed by Microsoft. The fix required updating the UEFI dbx (forbidden signatures database) to blacklist all affected GRUB2 versions — a massive coordinated update affecting virtually every Linux system using Secure Boot. This demonstrates that a signed binary can still contain exploitable vulnerabilities.

### 7.4 UEFI Firmware Security — The Pre-OS Attack Surface

**UEFI is one of the most persistent and dangerous attack surfaces in existence.** Malware in UEFI:
- Loads before the operating system
- Is invisible to OS-level security tools (antivirus, EDR)
- Survives OS reinstallation
- Survives hard drive replacement
- In many cases, survives firmware update (if not re-flashed completely)
- Only removable by reflashing the BIOS chip or replacing the motherboard

**Notable UEFI Malware:**

| Malware | Year | Attacker | Notes |
|---------|------|----------|-------|
| **LoJax** | 2018 | APT28 (Fancy Bear / Russia) | First UEFI rootkit used in a real attack campaign |
| **MosaicRegressor** | 2020 | Chinese APT | UEFI implant found on NGO systems |
| **ESPecter** | 2021 | Unknown | Persisted in EFI System Partition's Windows Boot Manager |
| **CosmicStrand** | 2022 | Chinese APT | UEFI rootkit targeting specific motherboard models |
| **BlackLotus** | 2023 | Unknown | **First in-the-wild UEFI bootkit to bypass Secure Boot on Windows 11** |

**BlackLotus deserves special attention.** In 2023, ESET researchers discovered BlackLotus — a UEFI bootkit that:
- Bypassed Secure Boot on fully patched Windows 11 systems
- Exploited CVE-2022-21894 (Baton Drop) — a flaw in the Windows Boot Manager that had been patched but not added to the Secure Boot revocation list
- Deployed a kernel driver and a user-mode component
- Disabled Defender, HVCI, and BitLocker
- Was **commercially available on underground forums for ~$5,000**

This means sophisticated UEFI attacks are not exclusively nation-state tools — they are increasingly accessible to cybercriminal groups.

**UEFI Security Recommendations:**
- Enable Secure Boot (do not disable it)
- Set a UEFI administrator password
- Disable boot from USB/external media in UEFI (prevent cold boot attacks and unauthorized boot)
- Keep UEFI firmware updated (manufacturers release security patches)
- Enable Intel Boot Guard or AMD Platform Secure Boot (hardware verification of UEFI itself)
- Monitor for UEFI threats with tools that include UEFI scanning (e.g., ESET, Kaspersky, certain EDR products)

---

## 8. Power Supply Unit

### 8.1 What Is a PSU?

The **Power Supply Unit (PSU)** converts AC mains power (120V/240V) to the DC voltages required by computer components:
- **+12V:** Powers CPU (via voltage regulator), PCIe devices (GPU), and drives
- **+5V:** USB ports, older SATA devices, logic circuits
- **+3.3V:** RAM, modern logic circuits, storage
- **-12V:** Certain legacy components, serial ports
- **+5VSB (Standby):** Powers USB even when system is "off," powers Wake-on-LAN, powers the PCH for remote management

**ATX Power Connector Standards:**

The standardized ATX connector pinout means that any ATX PSU should work with any ATX motherboard. However, this standardization also has security implications.

### 8.2 Power Quality and Hardware Security

**Power Glitching — A Hardware Attack Technique:**

Power glitching introduces deliberate voltage spikes or drops to cause a processor to execute instructions incorrectly or skip instructions entirely. This technique has been used to:

- Bypass secure boot verification on embedded devices
- Bypass PIN verification on encrypted storage
- Cause CPUs to skip authentication checks
- Extract secrets from microcontrollers by causing a fault during secure operations

Power glitching is a **hardware hacking technique** used in embedded systems security research, smartcard attacks, and IoT device hacking. In OT security, PLC security assessments sometimes include power fault injection as an attack vector.

**Voltage Regulator Modules (VRM) and CPU Stability:**

The CPU requires an extremely stable and precise voltage. The VRM on the motherboard converts the +12V rail to the CPU's required core voltage (typically 1.0–1.4V for modern processors). If the VRM quality is poor or fails, the CPU may exhibit random computational errors — which could theoretically be exploited if an attacker can induce VRM instability.

**Uninterruptible Power Supply (UPS) — Defense:**

For servers and critical infrastructure (directly relevant to OT/SCADA):
- UPS provides battery backup, preventing unclean shutdowns
- Unclean shutdowns can corrupt filesystems, databases, and even RAID arrays
- Power fluctuations can cause data integrity issues
- For ICS environments, power quality is directly linked to operational safety

### 8.3 Power Side-Channel Attacks

**Simple Power Analysis (SPA) and Differential Power Analysis (DPA):**

When a device performs cryptographic operations, its power consumption varies depending on the data being processed and the operations being performed. By measuring power consumption with high-precision equipment, an attacker can:

- Determine the secret key being used in AES encryption
- Extract RSA private keys from smartcards
- Recover PINs from secure hardware

This is why cryptographic implementations in hardware are required to be **constant-time** — the operations must take the same time and consume the same power regardless of key values, to prevent side-channel leakage.

**Relevance to Electrical Engineers in Cybersecurity:** This is precisely where your electrical engineering background gives you an advantage. Understanding current measurement, oscilloscope usage, signal processing, and circuit design are all prerequisites for power side-channel research — skills that most software-focused security professionals completely lack.

---

## 9. Physical Security

### 9.1 Why Physical Security Is the Foundation of All Security

> **There is a fundamental axiom in security: physical access equals game over.**

If an attacker has unconstrained physical access to a device, virtually every software and cryptographic protection can eventually be defeated. This is not theoretical — it is the reason secure facilities exist, why data centers have biometric access, and why classified systems are stored in locked cages.

All the software security in the world is meaningless if an attacker can:
- Walk up to an unlocked terminal
- Remove a hard drive and read it in their own system
- Install a hardware keylogger
- Insert a malicious USB device
- Take a photograph of your screen over your shoulder

### 9.2 Physical Attack Vectors

#### 9.2.1 Shoulder Surfing

The simplest attack: **visually observing what someone types or displays** — passwords, PINs, sensitive data, network credentials.

**Countermeasures:** Privacy screens (polarized film that narrows the viewing angle), situational awareness in public spaces, position yourself with your back to walls, use virtual keyboards for PIN entry where possible.

#### 9.2.2 Hardware Keyloggers

Physical keystroke logging devices that install between the keyboard and computer, or replace the keyboard cable entirely. They record every keystroke to internal storage, later retrieved physically or transmitted wirelessly.

**Types:**
- **PS/2/USB keylogger:** Inline device, often indistinguishable from a USB extension adapter
- **Wireless keylogger:** Transmits keystrokes via radio, can be read from a distance
- **Firmware keylogger:** Implanted in keyboard firmware — impossible to detect without firmware analysis
- **BIOS keylogger:** Rare but documented; records keystrokes at firmware level before OS loads

**Detection:** Physically inspect computers before use, especially in high-security environments. Run your fingers along all cable connections. Consider transparent keyboard enclosures in secure facilities. For high-value targets, use on-screen keyboards or hardware security tokens for authentication.

#### 9.2.3 Evil Maid Attack

Named after the hotel cleaning staff who have access to a guest's room:

1. Attacker gains brief, unobserved access to the target's device
2. Boots from external media, modifies the bootloader (installs a bootkit)
3. Modified bootloader captures the disk encryption password when the owner enters it
4. Attacker returns later to retrieve the captured password and decrypt the drive

**Countermeasures:** UEFI password, Secure Boot, Measured Boot with TPM, Anti-Evil-Maid tools (which hash the boot environment and display a secret to the user before asking for credentials — if the secret doesn't appear, the boot environment has changed).

#### 9.2.4 USB-Based Attacks

**Rubber Ducky / Malicious USB HID:**
A USB device that identifies itself as a keyboard to the OS, then executes a pre-programmed keystroke sequence — downloading and executing malware in seconds. The OS sees a trusted input device, so no suspicious file execution is triggered.

**BadUSB:**
Malware embedded in USB device firmware that reprograms the device to act as a different device type (e.g., a storage drive reprograms itself as a network adapter to redirect traffic). The firmware is not scanned by antivirus.

**USB Killer:**
Delivers a high-voltage surge (~200V) through the USB data lines, permanently destroying the motherboard. Used for sabotage.

**O.MG Cable:**
An Apple Lightning cable lookalike with an embedded Wi-Fi-accessible ARM processor. When connected, it executes payloads wirelessly while appearing to be a normal charging cable.

**Countermeasures:** USB port control software (allow only registered devices by hardware ID), USB data blockers for charging, port blockers/filers in high-security environments, endpoint protection that monitors HID device enumeration.

#### 9.2.5 Tailgating and Piggybacking

**Tailgating:** An unauthorized person follows an authorized person through an access-controlled door without proper authentication — by walking close behind them before the door closes.

**Piggybacking:** With the authorized person's knowledge (who holds the door open) — often through social engineering ("My hands are full, could you hold that?").

**In ICS/OT environments, this is particularly dangerous:** A tailgater into a substation, water treatment plant, or power control room has physical access to critical infrastructure. The consequences can extend far beyond data breach — operational disruption, equipment damage, and public safety risks.

**Countermeasures:** Mantrap/airlock entry (two doors requiring individual authentication), turnstile access controls that cannot be tailgated, security culture training, dual-person integrity requirements for critical areas.

#### 9.2.6 TEMPEST — Electromagnetic Emanation Attacks

**TEMPEST** (a codename, not an acronym — later backronymed to Transient ElectroMagnetic Pulse Emanation Standard) refers to surveillance techniques based on monitoring electromagnetic or acoustic emanations from electronic equipment.

**Examples:**
- **Van Eck Phreaking:** Reconstructing a monitor's displayed image from its electromagnetic emissions, captured with specialized equipment from a distance
- **Keyboard emanation:** Capturing keystrokes by analyzing the electromagnetic emissions of keyboard electronics
- **Power line analysis:** Reading device activity from power consumption patterns on the power line
- **Acoustic emanation:** Matrix printers' sound patterns reveal what is being printed; mechanical hard drive sounds can reveal access patterns; even CPU fans have been used to exfiltrate data as a covert channel

**TEMPEST Shielding:** Sensitive government facilities handling classified information use TEMPEST-shielded rooms (Faraday cages), TEMPEST-certified equipment (special shielding of electronics and cables), and proper cable management to prevent emanation leakage.

> **For your OT/Electrical background:** TEMPEST is directly related to EMC (Electromagnetic Compatibility) engineering — a field you likely studied. The difference is that EMC focuses on preventing interference; TEMPEST exploitation *uses* those same emissions for intelligence gathering. This is another domain where electrical engineering knowledge is directly applicable to cybersecurity.

### 9.3 Physical Security Controls

**Physical security is organized in concentric layers — exactly paralleling the "defense in depth" concept in network security:**

```
Outermost Layer: Perimeter Security
├── Fencing, walls, barriers
├── Lighting
├── CCTV / IP cameras
├── Security guards / patrols
└── Intrusion detection (motion, acoustic, vibration sensors)

Second Layer: Building Access
├── Locked doors
├── Key card / RFID access control
├── Biometric readers (fingerprint, retina, palm vein)
├── Visitor management systems
└── Reception/lobby control

Third Layer: Area Security (Zones within building)
├── Server room access control
├── Classified area separation
├── Mantrap entry systems
├── Camera coverage of sensitive areas
└── Clean desk / clear screen policies

Innermost Layer: Device Security
├── Cable locks for laptops
├── Server rack locks
├── Tamper-evident seals on equipment
├── USB port blockers
└── Hard drive encryption
```

**For OT/ICS environments, add:**
- Physical protection of PLCs and RTUs
- Control room access control
- Physical protection of communication cables and terminal blocks
- Serial port locks on PLC programming ports
- Physical inspection processes for maintenance personnel

### 9.4 Tamper Evidence and Detection

**Tamper-evident seals:** Stickers placed over screws, chassis seams, and connectors that visibly degrade or display "VOID" when removed. Used to detect unauthorized opening of equipment. Not tamper-proof (can be defeated with heat, solvents, or careful removal) but provide a deterrent and audit trail.

**Tamper detection circuits:** Active circuits that detect opening of an enclosure and automatically erase sensitive keys. Used in HSMs, payment terminals, and military equipment.

**Chassis intrusion detection:** Many motherboards include a chassis intrusion switch that logs to the Windows Event Log when the case is opened. Forensically, this can reveal unauthorized physical access.

---

## 10. Hardware Security: The Full Picture

### 10.1 The Hardware Attack Surface Map

```
┌─────────────────────────────────────────────────────────────────┐
│                   HARDWARE ATTACK SURFACE                       │
│                                                                 │
│  BEFORE BOOT:                                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Physical Access → Cold Boot → Evil Maid → PSU Glitch    │   │
│  │ UEFI Implant → Secure Boot Bypass → Boot Malware        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  AT BOOT:                                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ MBR/GPT Bootkit → GRUB Vulnerability → Signed Malware   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  DURING OPERATION:                                              │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Spectre/Meltdown → Rowhammer → DMA Attack               │   │
│  │ Power Analysis → Cache Timing → TEMPEST                  │   │
│  │ Hardware Keylogger → Malicious USB → PCILeech            │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  AFTER OPERATION:                                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Disk Forensics → Cold Boot (brief window)               │   │
│  │ Data Remanence → Improper Destruction → Repurposing     │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 10.2 The Hardware Trust Hierarchy

Security professionals often speak of a **Root of Trust** — the hardware or software component that is trusted implicitly, from which all other trust is derived. Understanding trust chains is fundamental to security architecture.

```
Hardware Root of Trust (e.g., TPM, HSM, Secure Enclave)
    │
    └── UEFI Firmware (verified by hardware RoT)
            │
            └── Bootloader (verified by Secure Boot / UEFI)
                    │
                    └── OS Kernel (verified by bootloader / code signing)
                            │
                            └── System Services (verified by OS)
                                    │
                                    └── User Applications (verified by OS)
```

**If any link in this chain is broken, everything above it is untrustworthy.** This is why hardware-level attacks (UEFI implants, TPM attacks) are so powerful — they break the chain at its base, making every layer above untrustworthy while appearing completely normal to OS-level security tools.

---

## 11. Hands-On Lab Exercises

The following exercises are designed to be completed safely and legally in your own environment or dedicated lab machines. **Never perform these on systems you do not own or have explicit written permission to test.**

### Exercise 1: Hardware Identification (30 minutes)

**Objective:** Build familiarity with actual hardware components.

**Windows:**
```powershell
# CPU information
Get-WmiObject Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed

# RAM information
Get-WmiObject Win32_PhysicalMemory | Select-Object Manufacturer, Capacity, Speed, MemoryType

# Motherboard information
Get-WmiObject Win32_BaseBoard | Select-Object Manufacturer, Product, SerialNumber

# TPM status
Get-TPM

# BIOS/UEFI information
Get-WmiObject Win32_BIOS | Select-Object Manufacturer, Name, Version, ReleaseDate

# Check if Secure Boot is enabled
Confirm-SecureBootUEFI
```

**Linux:**
```bash
# CPU information
lscpu
cat /proc/cpuinfo | grep "model name" | head -1

# RAM information
sudo dmidecode -t memory | grep -E "Size:|Speed:|Manufacturer:|Type:"
free -h

# Motherboard information
sudo dmidecode -t baseboard

# BIOS/UEFI information
sudo dmidecode -t bios

# Check for UEFI (as opposed to legacy BIOS)
[ -d /sys/firmware/efi ] && echo "UEFI" || echo "Legacy BIOS"

# Check Secure Boot status
mokutil --sb-state

# List all PCI devices
lspci -v

# Storage devices
lsblk -d -o NAME,SIZE,ROTA,TYPE  # ROTA=1 means spinning disk (HDD)
nvme list  # NVMe drives (requires nvme-cli)
```

### Exercise 2: Memory Forensics Introduction (1–2 hours)

**Objective:** Understand that RAM contains valuable forensic artifacts.

**Setup:** Install Volatility 3 on a test Linux machine.

```bash
# Install Volatility 3
pip3 install volatility3

# Acquire memory on Linux (requires LiME kernel module)
# First, install kernel headers
sudo apt-get install linux-headers-$(uname -r)

# Clone and build LiME
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src
make

# Load module to dump memory to file
sudo insmod lime-$(uname -r).ko "path=/tmp/memory.lime format=lime"

# Analyze with Volatility (use appropriate profile for your kernel)
python3 vol.py -f /tmp/memory.lime linux.pslist  # List processes
python3 vol.py -f /tmp/memory.lime linux.netstat  # Network connections
python3 vol.py -f /tmp/memory.lime linux.bash     # Bash history from memory
```

**What to look for:** Running processes, open network connections, commands executed in bash — all extracted from RAM without touching any log files.

### Exercise 3: Storage Analysis (1 hour)

**Objective:** Understand that "deleted" data may still be recoverable.

```bash
# Create a test file, "delete" it, and attempt recovery
dd if=/dev/zero of=test_disk.img bs=1M count=100  # Create 100MB test image
mkfs.ext4 test_disk.img
mkdir /tmp/testmount
sudo mount test_disk.img /tmp/testmount

# Write some test files
echo "This is sensitive data - password: SuperSecret123" | sudo tee /tmp/testmount/secret.txt
sudo umount /tmp/testmount

# Mount and delete the file
sudo mount test_disk.img /tmp/testmount
sudo rm /tmp/testmount/secret.txt
sudo umount /tmp/testmount

# Try to recover the deleted file with Autopsy or TestDisk/PhotoRec
sudo apt-get install testdisk
photorec test_disk.img  # GUI tool for file carving

# Or use strings to simply find the text in the raw image
strings test_disk.img | grep -A 2 -B 2 "sensitive"
```

**Expected outcome:** You will recover the "deleted" text because it was not overwritten. This demonstrates why data sanitization is critical.

### Exercise 4: UEFI Exploration (30 minutes)

**Objective:** Understand your system's UEFI configuration.

```bash
# Linux: Examine EFI System Partition
ls /sys/firmware/efi/efivars/  # EFI variables

# Read Secure Boot variables
cat /sys/firmware/efi/efivars/SecureBoot-*  # Status
cat /sys/firmware/efi/efivars/SetupMode-*   # Setup mode

# List UEFI boot entries
efibootmgr -v

# Check UEFI firmware information
sudo dmidecode -t 0
```

Explore your actual UEFI/BIOS settings (restart and press F2/Delete/Escape depending on motherboard):
- Locate Secure Boot settings — is it enabled?
- Find the TPM configuration — is it enabled?
- Locate boot order settings
- Find the chassis intrusion detection setting
- Look for Intel ME / AMT settings
- Find the option to require a UEFI password

---

## 12. Key Takeaways and Security Mindset

### 12.1 The 10 Most Important Hardware Security Concepts

These are the concepts that will appear again and again throughout your entire cybersecurity career. Internalize them now:

1. **Physical access breaks all software security.** Physical security is not optional, not secondary, not "someone else's problem." It is the foundation.

2. **The CPU's instruction pointer (RIP) is the crown jewel of exploitation.** Every code execution exploit, in its most fundamental form, is about controlling where the CPU fetches its next instruction.

3. **RAM is where the truth lives.** Malware may hide on disk, but it must execute in RAM. Memory forensics sees through fileless malware.

4. **Hardware features create hardware vulnerabilities.** Spectre exploits speculative execution (a performance feature). Rowhammer exploits DRAM physics. Your adversary thinks about hardware, not just software.

5. **UEFI firmware attacks are the most persistent.** Surviving OS reinstalls and drive replacements, UEFI implants represent the apex of persistence. Every incident response investigation should include UEFI integrity verification.

6. **"Deleted" does not mean "gone."** On HDDs especially, data persists until overwritten. Forensic tools exploit this. Proper data destruction requires physical destruction or cryptographic erasure.

7. **SED encryption may be weaker than you think.** Software-layer encryption (BitLocker, LUKS) is generally more trustworthy than self-encrypting drive hardware encryption.

8. **DMA is a trust boundary.** Any device with DMA access (PCIe, Thunderbolt) can read your RAM. IOMMU is the defense. Disable Thunderbolt on sensitive systems when not in use.

9. **GPU is a weapon in password cracking.** Understanding GPU-based cracking informs password policy requirements. Anything under 12 characters of mixed complexity is at risk.

10. **Your electrical engineering background is an unfair advantage.** Power analysis attacks, TEMPEST, electromagnetic emissions, hardware fault injection — these are domains where deep electronics knowledge translates directly into unique security capabilities.

### 12.2 The Mindset of a Hardware-Aware Security Professional

Most security professionals think in software abstractions. They think about code, protocols, and configurations. You need to think one level deeper:

- When you see a VPN gateway protecting a network, also ask: *Who has physical access to that device? Is the management port exposed? Is there a console cable attached?*
- When you implement full-disk encryption, also ask: *Is the key stored in TPM? Is the system set to require a pre-boot PIN? Is Sleep mode disabled to prevent cold boot?*
- When you assess an OT/ICS environment, also ask: *What are the serial ports on that PLC? Is there a diagnostic cable attached? Is the PLC's CPU socket accessible? What does the physical security of this cabinet look like?*
- When you investigate an incident, also ask: *Before you shut this system down — do you have a memory image? Are you destroying volatile evidence?*

This layer of thinking — translating physical reality into security implications — is what separates a truly capable security professional from a tool operator.

---

## References and Further Reading

### Foundational Academic Papers
- Kocher, P., et al. (2019). "Spectre Attacks: Exploiting Speculative Execution." *IEEE Security & Privacy*. https://spectreattack.com/spectre.pdf
- Lipp, M., et al. (2018). "Meltdown: Reading Kernel Memory from User Space." *USENIX Security 2018*. https://meltdownattack.com/meltdown.pdf
- Kim, Y., et al. (2014). "Flipping Bits in Memory Without Accessing Them: An Experimental Study of DRAM Disturbance Errors." *ISCA 2014*. (Original Rowhammer paper)
- Halderman, J. A., et al. (2009). "Lest We Remember: Cold Boot Attacks on Encryption Keys." *Communications of the ACM*.

### Security Research and Documentation
- UEFI Specification: https://uefi.org/specifications
- Intel Platform Security documentation: https://www.intel.com/content/www/us/en/architecture-and-technology/intel-platform-security.html
- NIST SP 800-147: BIOS Protection Guidelines: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-147.pdf
- NIST SP 800-155: BIOS Integrity Measurement Guidelines
- TCG TPM 2.0 Library Specification: https://trustedcomputinggroup.org/resource/tpm-library-specification/

### Malware Analysis Reports Referenced
- ESET LoJax Report: https://www.welivesecurity.com/wp-content/uploads/2018/09/ESET-LoJax.pdf
- ESET BlackLotus Report: https://www.welivesecurity.com/en/eset-research/uefi-threats-moving-esp-introducing-especter-bootkit/
- Kaspersky Equation Group: https://securelist.com/equation-the-death-star-of-malware-galaxy/68750/

### Tools
- Volatility 3 Framework: https://github.com/volatilityfoundation/volatility3
- PCILeech: https://github.com/ufrisk/pcileech
- me_cleaner (Intel ME): https://github.com/corna/me_cleaner
- CHIPSEC (UEFI security assessment): https://github.com/chipsec/chipsec

---

## Module Summary

| Topic | Cybersecurity Relevance | Key Attack | Key Defense |
|-------|------------------------|-----------|------------|
| CPU | Spectre/Meltdown, RIP control in exploits | Speculative execution side-channel | Microcode updates, software mitigations |
| RAM | Fileless malware, memory forensics | Cold boot, Rowhammer, process injection | Pre-boot PIN, ECC RAM, IOMMU |
| ROM | Firmware persistence | HDD firmware implant (Equation Group) | Secure firmware verification, signing |
| GPU | Password cracking acceleration | GPU memory scraping | Strong passwords (12+ chars, Argon2 hashing) |
| Motherboard | ME/AMT backdoor, DMA attacks | Intel AMT auth bypass, PCILeech | IOMMU, disable unnecessary ME features |
| Storage | Data recovery, forensics | Disk imaging, file carving | Crypto erase (NVMe Sanitize), physical destruction |
| BIOS/UEFI | Most persistent malware class | BlackLotus Secure Boot bypass | Secure Boot, firmware updates, UEFI password |
| PSU | Hardware fault injection | Power glitching, side-channel analysis | UPS for availability, constant-time crypto |
| Physical | Attack foundation for everything | Evil Maid, hardware keylogger, tailgating | Layered physical controls, tamper evidence |

---

*This document is part of the **Zero to Expert Cybersecurity Roadmap** — a comprehensive, systematic curriculum designed for professionals at the intersection of electrical engineering and cybersecurity.*

*Stage 0.1 Complete → Proceed to Stage 0.2: Operating System Fundamentals*

---
**Document Version:** 1.0  
**Last Updated:** 2025  
**License:** MIT — Free to use, share, and modify with attribution