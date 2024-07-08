---
description: >-
  This machine focused on enumerating an unknown port and identifying the
  service running on it.
---

# Algernon

## Summary

* This machine was running a vulnerable version of SmarterMail
* A public exploit was available that gave nt authority\system shell

## Let's unpack

### Enumeration

```bash
sudo nmap -sC -sN -A -oN nmapFull -p- -A 192.168.166.65

Nmap scan report for 192.168.166.65
Host is up (0.071s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-29-20  10:31PM       <DIR>          ImapRetrieval
| 06-24-24  11:06AM       <DIR>          Logs
| 04-29-20  10:31PM       <DIR>          PopRetrieval
|_04-29-20  10:32PM       <DIR>          Spool
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
9998/tcp  open  http          Microsoft IIS httpd 10.0
```

Port 9998 seemed interesting, so further enumeration revealed that this port was running vulnerbale version of SmarterMail

```bash
curl -L http://192.168.166.65:9998

<!DOCTYPE html>
...
var cssVersion = "100.0.6919.30414.8d65fc3f1d47d00";
var stProductVersion = "100.0.6919";
var stProductBuild = "6919 (Dec 11, 2018)";
...
```

### Foothold (without Metasploit)

To get a shell, we can use the following exploit.

{% embed url="https://www.exploit-db.com/exploits/49216" %}

On executing the exploit, open up nc listen to catch the reverse shell.

### Using Metasploit

```bash
# use exploit
exploit/windows/http/smartermail_rce         2019-04-17       excellent  Yes    SmarterTools SmarterMail less than build 6985 - .NET Deserialization Remote Code Execution

# get a root shell on executing exploit
```

